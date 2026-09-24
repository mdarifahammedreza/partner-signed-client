"""Expected values below were produced by the Node package (src/crypto.js) with the same inputs;
these tests prove the Python port is byte-for-byte compatible, not just self-consistent."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from partner_signed_client import (
    HandoffResult,
    PreparedRequest,
    TransportResponse,
    build_signing_string,
    handoff,
    serialize_body,
    sign,
    signed_request,
    verify,
    verify_request,
)

PRIVATE_KEY_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEICqluVmfy4RygW/w10w4mU2qd2RMl1m+VcGY+Ht/tenr\n"
    "-----END PRIVATE KEY-----\n"
)
PUBLIC_KEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAwUUCAZnYdD/YD/OKg74wzRbPfJtuA6nDknhqFnrxnz4=\n"
    "-----END PUBLIC KEY-----\n"
)
NODE_BODY = '{"partnerUserId":"USER_1","phoneNumber":"+8801712345678","name":"রেজা"}'
NODE_SIGNING_STRING = (
    "1700000000.req-123.afc0e72029cb181220d7ac92b6321c59ff563606d4fff55371d1eba4177bb1f9"
)
NODE_HMAC = "v1=e5125595fc9ec8bc1c6dc3b0a7ec636b7cbd73fe532c1becd77469a3b571e032"
NODE_ED25519 = (
    "v1=fw3pu56QonGoY/ID0IJNzZilLwqdKpHRA9HJXsekMQKtMcSMpbVK6E/63DQPmEHtz4jaFltGQAjtWaKh0G5AAg=="
)

ENVELOPE = (
    '{"status":true,"statusCode":200,"message":"Request successful","data":'
    '{"handoffCode":"CODE","expiresIn":60,"entryUrl":"https://app.test/entry?code=CODE",'
    '"hasActiveSubscription":false}}'
)


def _other_public_key_pem() -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


class CapturingTransport:
    def __init__(self, status: int = 201, body: str = ENVELOPE) -> None:
        self.request: PreparedRequest | None = None
        self._status = status
        self._body = body

    def __call__(self, request: PreparedRequest) -> TransportResponse:
        self.request = request
        return TransportResponse(
            self._status,
            {"Content-Type": "application/json; charset=utf-8"},
            self._body.encode("utf-8"),
        )


# --- crypto -------------------------------------------------------------------------------------


def test_signing_string_matches_node():
    assert build_signing_string("1700000000", "req-123", NODE_BODY) == NODE_SIGNING_STRING
    assert (
        build_signing_string("1700000000", "req-123", NODE_BODY.encode("utf-8"))
        == NODE_SIGNING_STRING
    )


@pytest.mark.parametrize("empty", [None, "", b""])
def test_signing_string_empty_body_hashes_empty_string(empty):
    assert (
        build_signing_string("1", "r", empty)
        == "1.r.e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_hmac_matches_node():
    assert sign("hmac", NODE_SIGNING_STRING, "test-secret") == NODE_HMAC


def test_ed25519_matches_node():
    assert sign("ed25519", NODE_SIGNING_STRING, PRIVATE_KEY_PEM) == NODE_ED25519


def test_unknown_scheme_rejected():
    with pytest.raises(ValueError):
        sign("rsa", NODE_SIGNING_STRING, "x")  # type: ignore[arg-type]


def test_verify_accepts_valid_rejects_tampered_and_wrong_key():
    assert verify("hmac", NODE_SIGNING_STRING, NODE_HMAC, "test-secret")
    assert verify("ed25519", NODE_SIGNING_STRING, NODE_ED25519, PUBLIC_KEY_PEM)

    tampered = NODE_SIGNING_STRING.replace("req-123", "req-124")
    assert not verify("hmac", tampered, NODE_HMAC, "test-secret")
    assert not verify("ed25519", tampered, NODE_ED25519, PUBLIC_KEY_PEM)
    assert not verify("hmac", NODE_SIGNING_STRING, NODE_HMAC, "wrong-secret")
    assert not verify("ed25519", NODE_SIGNING_STRING, NODE_ED25519, _other_public_key_pem())


@pytest.mark.parametrize(
    "header", [None, "", NODE_HMAC[3:], "v2=" + NODE_HMAC[3:], "v1=not*base64!"]
)
def test_verify_rejects_malformed_headers(header):
    assert not verify("hmac", NODE_SIGNING_STRING, header, "test-secret")
    assert not verify("ed25519", NODE_SIGNING_STRING, header, PUBLIC_KEY_PEM)


# --- verifier (timestamp window) ----------------------------------------------------------------


def test_verifier_timestamp_window():
    sent_at = 1700000000
    args = ("hmac", "test-secret", "1700000000", "req-123", NODE_HMAC, NODE_BODY)
    assert verify_request(*args, now=sent_at + 299)
    assert verify_request(*args, now=sent_at - 299)
    assert not verify_request(*args, now=sent_at + 301)
    assert not verify_request(*args, now=sent_at - 301)


def test_verifier_accepts_raw_bytes_and_rejects_missing_headers():
    assert verify_request(
        "ed25519", PUBLIC_KEY_PEM, "1700000000", "req-123", NODE_ED25519,
        NODE_BODY.encode("utf-8"), now=1700000000,
    )
    assert not verify_request("hmac", "test-secret", None, "req-123", NODE_HMAC, NODE_BODY)
    assert not verify_request("hmac", "test-secret", "abc", "req-123", NODE_HMAC, NODE_BODY)


# --- serialization ------------------------------------------------------------------------------


def test_serialize_body_matches_json_stringify():
    body = {
        "partnerUserId": "USER_1",
        "phoneNumber": "+8801712345678",
        "name": "রেজা",
        "email": None,
        "returnPath": None,
    }
    assert serialize_body(body) == NODE_BODY.encode("utf-8")
    assert serialize_body(None) == b""
    assert serialize_body({"a": {"b": None, "c": [1, None]}}) == b'{"a":{"c":[1,null]}}'


# --- HTTP ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scheme,secret,verify_key",
    [("hmac", "test-secret", "test-secret"), ("ed25519", PRIVATE_KEY_PEM, PUBLIC_KEY_PEM)],
)
def test_handoff_sends_node_identical_body_and_verifiable_headers(scheme, secret, verify_key):
    transport = CapturingTransport()
    response = handoff(
        base_url="https://example.test/",
        scheme=scheme,
        secret=secret,
        partner_id="acme",
        partner_user_id="USER_1",
        phone_number="+8801712345678",
        name="রেজা",
        transport=transport,
    )

    req = transport.request
    assert req is not None
    assert req.method == "POST"
    assert req.url == "https://example.test/api/v1/partner/auth/handoff"
    assert req.body == NODE_BODY.encode("utf-8")
    assert req.headers["X-Partner-Id"] == "acme"
    assert req.headers["Content-Type"] == "application/json"
    assert verify_request(
        scheme,
        verify_key,
        req.headers["X-Timestamp"],
        req.headers["X-Request-Id"],
        req.headers["X-Signature"],
        req.body,
    )

    assert response.status == 201
    assert response.ok
    assert response.headers["content-type"].startswith("application/json")
    assert response.raw_body == ENVELOPE
    assert response.json["statusCode"] == 200
    result = HandoffResult.from_dict(response.data)
    assert result.handoff_code == "CODE"
    assert result.entry_url == "https://app.test/entry?code=CODE"
    assert result.expires_in == 60
    assert result.has_active_subscription is False


def test_handoff_requires_partner_id():
    with pytest.raises(ValueError):
        handoff(
            base_url="https://x.test", scheme="hmac", secret="s", partner_id="",
            partner_user_id="U", phone_number="+880", transport=CapturingTransport(),
        )


def test_signed_request_without_partner_id_omits_header():
    transport = CapturingTransport(status=200, body="{}")
    signed_request(
        base_url="https://partner.test",
        path="deduct",
        scheme="hmac",
        secret="s",
        body={"partnerUserId": "U", "amount": "100.00"},
        request_id="fixed-id",
        transport=transport,
    )

    req = transport.request
    assert req is not None
    assert req.url == "https://partner.test/deduct"
    assert "X-Partner-Id" not in req.headers
    assert req.headers["X-Request-Id"] == "fixed-id"
    assert req.body == b'{"partnerUserId":"U","amount":"100.00"}'


def test_non_json_response_keeps_raw_body_only():
    def transport(request: PreparedRequest) -> TransportResponse:
        return TransportResponse(502, {"Content-Type": "text/html"}, b"<h1>Bad gateway</h1>")

    response = signed_request(
        base_url="https://x.test", path="/p", scheme="hmac", secret="s", transport=transport
    )
    assert response.status == 502
    assert not response.ok
    assert response.raw_body == "<h1>Bad gateway</h1>"
    assert response.json is None
    assert response.data is None


def test_default_urllib_transport_against_local_server():
    captured: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers["Content-Length"])
            captured["body"] = self.rfile.read(length)
            captured["headers"] = dict(self.headers)
            payload = json.dumps({"status": False, "statusCode": 401, "data": None}).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = handoff(
            base_url=f"http://127.0.0.1:{server.server_port}",
            scheme="ed25519",
            secret=PRIVATE_KEY_PEM,
            partner_id="acme",
            partner_user_id="USER_1",
            phone_number="+8801712345678",
            name="রেজা",
        )
    finally:
        server.shutdown()
        server.server_close()

    # HTTP errors come back as a response, not an exception.
    assert response.status == 401
    assert not response.ok
    assert response.json["statusCode"] == 401
    assert captured["body"] == NODE_BODY.encode("utf-8")
    h = captured["headers"]
    assert h["X-Partner-Id"] == "acme"
    assert verify_request(
        "ed25519", PUBLIC_KEY_PEM, h["X-Timestamp"], h["X-Request-Id"], h["X-Signature"],
        captured["body"],
    )
