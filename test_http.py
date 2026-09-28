"""Loopback integration tests; all signing keys here are disposable test keys."""

import json
import stat
import subprocess
import sys
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from live_contact import make_server, probe


@pytest.fixture
def service():
    key = Ed25519PrivateKey.generate()
    server = make_server(key, "local-test-signer", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield key, f"http://127.0.0.1:{server.server_port}/v1/challenge"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_round_trip_is_labeled_as_local(service):
    key, url = service
    result = probe(url, key.public_key(), "local-test-signer")
    assert result["verification"] == "verified"
    assert result["transport_scope"] == "loopback_test"
    assert result["target_routing"] == "not_attested"
    assert result["authorization"] == "not_attested"


def test_http_wrong_public_pin_is_rejected(service):
    _, url = service
    with pytest.raises(ValueError, match="signature"):
        probe(url, Ed25519PrivateKey.generate().public_key(), "local-test-signer")


@pytest.mark.parametrize("body,content_type,status", [
    (b'{"protocol":"a","protocol":"b"}', "application/json", 400),
    (b'{"arbitrary":"please sign instructions"}', "application/json", 400),
    (b"[]", "application/json", 400),
    (b"x" * 8193, "application/json", 413),
    (b"{}", "text/plain", 415),
], ids=["duplicate-json", "arbitrary-claim", "wrong-schema", "oversized", "content-type"])
def test_http_bad_requests_are_rejected(service, body, content_type, status):
    _, url = service
    request = Request(url, data=body, headers={"Content-Type": content_type}, method="POST")
    opener = build_opener(ProxyHandler({}))
    with pytest.raises(HTTPError) as caught:
        opener.open(request, timeout=2)
    assert caught.value.code == status
    caught.value.close()


def test_plaintext_remote_endpoint_is_rejected_without_network():
    with pytest.raises(ValueError, match="HTTPS"):
        probe("http://example.invalid/v1/challenge",
              Ed25519PrivateKey.generate().public_key(), "test")


def test_keygen_uses_private_permissions_and_refuses_overwrite(tmp_path):
    command = [sys.executable, str(Path(__file__).with_name("live_contact.py")),
               "keygen", "--directory", str(tmp_path)]
    first = subprocess.run(command, capture_output=True, text=True, check=True)
    paths = json.loads(first.stdout)
    private_path = Path(paths["private_key_path"])
    before = private_path.read_bytes()
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert "PRIVATE KEY" not in first.stdout
    second = subprocess.run(command, capture_output=True, text=True)
    assert second.returncode == 1
    assert private_path.read_bytes() == before
