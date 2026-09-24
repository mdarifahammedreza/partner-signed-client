"""Signing primitives: a byte-for-byte port of the Node package's ``src/crypto.js``.

That file in turn must match the backend's PartnerCryptoService. This is not an independent
protocol, it's a compatible client for the same one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from typing import Literal, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

__all__ = [
    "SIGNATURE_VERSION",
    "Scheme",
    "build_signing_string",
    "sign_hmac",
    "sign_ed25519",
    "sign",
    "verify",
]

#: Prefix on every signature header value (``v1=...``).
SIGNATURE_VERSION = "v1"

Scheme = Literal["hmac", "ed25519"]

_Body = Union[str, bytes, None]


def _to_bytes(value: _Body) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8")


def build_signing_string(timestamp: str, request_id: str, raw_body: _Body) -> str:
    """Return ``{timestamp}.{requestId}.{hex(sha256(rawBody))}``.

    Binds timestamp, request id and body together so tampering with any one invalidates the
    signature. ``raw_body`` must be the EXACT body sent on the wire (``str`` is UTF-8 encoded;
    ``None``/empty for no body).
    """
    body_hash = hashlib.sha256(_to_bytes(raw_body)).hexdigest()
    return f"{timestamp}.{request_id}.{body_hash}"


def sign_hmac(signing_string: str, secret: str) -> str:
    """``v1=`` + hex(HMAC-SHA256(signing_string, secret)). ``secret`` is the raw HMAC secret."""
    mac = hmac.new(secret.encode("utf-8"), signing_string.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{SIGNATURE_VERSION}={mac}"


def sign_ed25519(signing_string: str, private_key_pem: str) -> str:
    """``v1=`` + base64(Ed25519 signature). ``private_key_pem`` is a PKCS#8 PEM private key."""
    key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key in PKCS#8 PEM format")
    signature = key.sign(signing_string.encode("utf-8"))
    return f"{SIGNATURE_VERSION}={base64.b64encode(signature).decode('ascii')}"


def _check_scheme(scheme: str) -> None:
    if scheme not in ("hmac", "ed25519"):
        raise ValueError(f'Unsupported signing scheme "{scheme}" - expected "hmac" or "ed25519"')


def sign(scheme: Scheme, signing_string: str, secret: str) -> str:
    """Scheme-agnostic entry point. Returns the already-prefixed (``v1=...``) header value.

    ``secret`` is the HMAC secret, or the Ed25519 private key PEM.
    """
    _check_scheme(scheme)
    if scheme == "hmac":
        return sign_hmac(signing_string, secret)
    return sign_ed25519(signing_string, secret)


def verify(scheme: Scheme, signing_string: str, signature_header: str | None, key: str) -> bool:
    """Verify an ``X-Signature`` header value (the piece you need in your own ``/deduct``).

    ``key`` is the HMAC secret, or the sender's Ed25519 PUBLIC key PEM (SPKI,
    ``-----BEGIN PUBLIC KEY-----``). Does NOT check the timestamp window; see
    :func:`partner_signed_client.verify_request`.
    """
    _check_scheme(scheme)
    prefix = f"{SIGNATURE_VERSION}="
    if not signature_header or not signature_header.startswith(prefix):
        return False

    if scheme == "hmac":
        expected = sign_hmac(signing_string, key)
        return hmac.compare_digest(signature_header.encode("utf-8"), expected.encode("utf-8"))

    public_key = load_pem_public_key(key.encode("utf-8"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Expected an Ed25519 public key in SPKI PEM format")
    try:
        signature = base64.b64decode(signature_header[len(prefix):], validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        public_key.verify(signature, signing_string.encode("utf-8"))
    except InvalidSignature:
        return False
    return True
