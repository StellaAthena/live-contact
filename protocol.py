"""Local research prototype: authenticate fresh contact with a configured signer.

Trust assumptions: the verifier, its key pin, randomness, clocks, and pending
challenge state are outside the simulated/untrusted environment. Successful
verification does not establish target routing, containment, or authorization.
"""

import base64
import hashlib
import json
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


VERSION = "eai-live-contact-v1"
CLAIM = "signer_received_this_challenge"
MAX_TTL = 120
MAX_MESSAGE = 8192
PAYLOAD_FIELDS = {"protocol", "issuer", "nonce", "claim", "issued_at", "expires_at"}


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("nonstandard JSON constant")


def parse_json(raw):
    if not isinstance(raw, (bytes, str)):
        raise ValueError("JSON must be bytes or text")
    try:
        raw = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(raw) > MAX_MESSAGE:
            raise ValueError("JSON message too large")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid JSON encoding or nesting") from error


def encode64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode64(value):
    if not isinstance(value, str) or len(value) > MAX_MESSAGE:
        raise ValueError("invalid base64url value")
    try:
        decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, UnicodeError) as error:
        raise ValueError("invalid base64url encoding") from error
    if encode64(decoded) != value:
        raise ValueError("noncanonical base64url encoding")
    return decoded


def fingerprint(public_key):
    raw = public_key.public_bytes(serialization.Encoding.Raw,
                                  serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _check_issuer(issuer):
    if not isinstance(issuer, str) or not re.fullmatch(r"[\x21-\x7e]{1,200}", issuer):
        raise ValueError("issuer must be 1–200 printable ASCII characters without spaces")


def _check_challenge(challenge):
    if not isinstance(challenge, dict) or set(challenge) != {"protocol", "nonce"}:
        raise ValueError("invalid challenge schema")
    if challenge["protocol"] != VERSION:
        raise ValueError("unsupported protocol")
    nonce = challenge["nonce"]
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise ValueError("nonce must contain 32 random bytes as lowercase hex")


def sign_response(private_key, issuer, challenge, ttl=30, now=None):
    _check_issuer(issuer)
    _check_challenge(challenge)
    if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
        raise ValueError("invalid lifetime")
    issued_at = int(time.time()) if now is None else now
    if type(issued_at) is not int or issued_at < 0:
        raise ValueError("invalid issue time")
    payload = canonical({
        "protocol": VERSION,
        "issuer": issuer,
        "nonce": challenge["nonce"],
        "claim": CLAIM,
        "issued_at": issued_at,
        "expires_at": issued_at + ttl,
    })
    signature = private_key.sign(VERSION.encode("ascii") + b"\x00" + payload)
    return {"payload": encode64(payload), "signature": encode64(signature)}


class Verifier:
    """One local verifier's outstanding challenges; use within one thread.

    Pending state is deliberately not reconstructed from the received payload.
    Restarting this object invalidates all its earlier challenges. The timeout
    uses monotonic time, separately from signed timestamps and wall-clock skew.
    """

    def __init__(self, public_key, issuer, timeout=10, wall_clock=time.time,
                 monotonic=time.monotonic, clock_skew=5):
        _check_issuer(issuer)
        if not 0 < timeout <= MAX_TTL or not 0 <= clock_skew <= MAX_TTL:
            raise ValueError("invalid timeout or clock skew")
        self.public_key = public_key
        self.issuer = issuer
        self.timeout = timeout
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self.clock_skew = clock_skew
        self.pending = {}

    def start(self):
        now = self.monotonic()
        self.pending = {nonce: started for nonce, started in self.pending.items()
                        if 0 <= now - started < self.timeout}
        nonce = secrets.token_hex(32)
        self.pending[nonce] = now
        return {"protocol": VERSION, "nonce": nonce}

    def verify(self, envelope):
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError("invalid response schema")
        payload_bytes = decode64(envelope["payload"])
        signature = decode64(envelope["signature"])
        if len(signature) != 64:
            raise ValueError("invalid signature length")
        try:
            self.public_key.verify(signature, VERSION.encode("ascii") + b"\x00" + payload_bytes)
        except InvalidSignature as error:
            raise ValueError("signature verification failed") from error
        payload = parse_json(payload_bytes)
        if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
            raise ValueError("invalid signed payload schema")
        if canonical(payload) != payload_bytes:
            raise ValueError("noncanonical signed JSON")
        _check_challenge({"protocol": payload["protocol"], "nonce": payload["nonce"]})
        if payload["issuer"] != self.issuer or payload["claim"] != CLAIM:
            raise ValueError("unexpected issuer or claim")
        issued = payload["issued_at"]
        expires = payload["expires_at"]
        if type(issued) is not int or type(expires) is not int:
            raise ValueError("timestamps must be integers")
        if issued < 0 or not 1 <= expires - issued <= MAX_TTL:
            raise ValueError("invalid signed lifetime")
        now = self.wall_clock()
        if issued > now + self.clock_skew or expires <= now:
            raise ValueError("response expired or issued in the future")
        nonce = payload["nonce"]
        if nonce not in self.pending:
            raise ValueError("unknown or already consumed challenge")
        elapsed = self.monotonic() - self.pending[nonce]
        if not 0 <= elapsed < self.timeout:
            del self.pending[nonce]
            raise ValueError("challenge timed out")
        del self.pending[nonce]
        return {
            "verification": "verified",
            "protocol": VERSION,
            "issuer": self.issuer,
            "key_fingerprint": fingerprint(self.public_key),
            "claim": CLAIM,
            "nonce": nonce,
            "issued_at": issued,
            "expires_at": expires,
            "round_trip_seconds": elapsed,
            "signer_contact": "fresh",
            "target_routing": "not_attested",
            "authorization": "not_attested",
            "message": "The configured signer answered this runtime's fresh challenge. "
                       "This does not establish other targets' reality, routing, or authorization.",
        }
