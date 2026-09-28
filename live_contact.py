"""Run with .venv/bin/python live_contact.py --help.

This is a local research prototype, not a public or audited signing service.
Production deployment, key governance, TLS termination, and rate limiting need
separate review. No LLM APIs are called and no model reliability is measured here.
"""

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from protocol import MAX_MESSAGE, Verifier, canonical, fingerprint, parse_json, sign_response


def make_server(private_key, issuer, port):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, format, *args):
            pass  # Do not retain callers' challenges or network metadata by default.

        def do_POST(self):
            if self.path != "/v1/challenge":
                self.send_error(404)
                return
            if self.headers.get_content_type() != "application/json":
                self.send_error(415)
                return
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding") is not None:
                self.send_error(400)
                return
            try:
                length = int(lengths[0])
                if not 0 < length <= MAX_MESSAGE:
                    self.send_error(413)
                    return
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("incomplete request")
                response = sign_response(private_key, issuer, parse_json(raw))
            except (ValueError, TimeoutError):
                self.send_error(400)
                return
            body = canonical(response)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("signing endpoint redirects are not accepted")


def probe(url, public_key, issuer, timeout=10):
    endpoint = urlsplit(url)
    if endpoint.username or endpoint.password or endpoint.fragment or endpoint.query:
        raise ValueError("endpoint must not contain credentials, a query, or a fragment")
    if endpoint.scheme != "https" and not (
        endpoint.scheme == "http" and endpoint.hostname in {"127.0.0.1", "::1"}
    ):
        raise ValueError("HTTPS is required except for numeric loopback addresses")
    if endpoint.path != "/v1/challenge":
        raise ValueError("endpoint path must be /v1/challenge")
    verifier = Verifier(public_key, issuer, timeout=timeout)
    request = Request(url, data=canonical(verifier.start()), method="POST",
                      headers={"Content-Type": "application/json", "Accept": "application/json"})
    # Explicit destination; neither environment proxies nor redirects choose a signer.
    opener = build_opener(ProxyHandler({}), NoRedirects())
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/json":
            raise ValueError("unexpected endpoint response")
        envelope = parse_json(response.read(MAX_MESSAGE + 1))
    result = verifier.verify(envelope)
    result["transport_endpoint"] = url
    result["transport_scope"] = (
        "loopback_test" if endpoint.hostname in {"127.0.0.1", "::1"} else "configured_https_endpoint"
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="create a disposable local test key and public pin")
    keygen.add_argument("--directory", default="private")
    server = commands.add_parser("serve", help="serve challenges on loopback only")
    server.add_argument("--private-key", required=True)
    server.add_argument("--issuer", default="local-research-signer")
    server.add_argument("--port", type=int, default=8787)
    client = commands.add_parser("probe", help="issue and verify one fresh challenge")
    client.add_argument("--url", default="http://127.0.0.1:8787/v1/challenge")
    client.add_argument("--public-key", required=True)
    client.add_argument("--issuer", default="local-research-signer")
    client.add_argument("--timeout", type=float, default=10,
                        help="maximum accepted challenge age and per-I/O timeout; "
                             "not a strict total wall-time limit for a slow server")
    commands.add_parser("demo", help="in-memory local demonstration, with ephemeral test keys")
    args = parser.parse_args()

    if args.command == "keygen":
        directory = Path(args.directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        private_path = directory / "signer.key"
        public_path = directory / "signer-public.pem"
        if private_path.exists() or public_path.exists():
            raise ValueError("key output already exists; choose a new directory")
        key = Ed25519PrivateKey.generate()
        private_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
        with os.fdopen(os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(private_bytes)
        with public_path.open("xb") as stream:
            stream.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
        print(json.dumps({"private_key_path": str(private_path.resolve()),
                          "public_key_path": str(public_path.resolve()),
                          "key_fingerprint": fingerprint(key.public_key()),
                          "purpose": "local test only"}, indent=2))
    elif args.command == "serve":
        key = serialization.load_pem_private_key(Path(args.private_key).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("an Ed25519 private key is required")
        with make_server(key, args.issuer, args.port) as service:
            print(json.dumps({"endpoint": f"http://127.0.0.1:{service.server_port}/v1/challenge",
                              "issuer": args.issuer, "key_fingerprint": fingerprint(key.public_key()),
                              "scope": "loopback research prototype"}), flush=True)
            try:
                service.serve_forever()
            except KeyboardInterrupt:
                pass
    elif args.command == "probe":
        key = serialization.load_pem_public_key(Path(args.public_key).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("an Ed25519 public key is required")
        print(json.dumps(probe(args.url, key, args.issuer, args.timeout), indent=2))
    else:
        key = Ed25519PrivateKey.generate()
        verifier = Verifier(key.public_key(), "local-research-signer")
        envelope = sign_response(key, "local-research-signer", verifier.start())
        result = {"scope": "in-memory local test; no external service contacted",
                  "fresh_response": verifier.verify(envelope)}
        try:
            verifier.verify(envelope)
        except ValueError as error:
            result["replay"] = {"verification": "rejected", "reason": str(error)}
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, HTTPError, URLError) as error:
        print(json.dumps({"verification": "unverified", "error": str(error),
                          "target_routing": "not_attested", "authorization": "not_attested"}))
        raise SystemExit(1)
