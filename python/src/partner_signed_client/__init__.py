"""Python port of BanglaReels' Business Partner signed-request reference client (HMAC + Ed25519)."""

from .client import Transport, handoff, serialize_body, signed_request, urllib_transport
from .crypto import (
    SIGNATURE_VERSION,
    Scheme,
    build_signing_string,
    sign,
    sign_ed25519,
    sign_hmac,
    verify,
)
from .models import HandoffResult, PreparedRequest, SignedResponse, TransportResponse
from .verifier import DEFAULT_TOLERANCE_SECONDS, verify_request

__all__ = [
    "SIGNATURE_VERSION",
    "DEFAULT_TOLERANCE_SECONDS",
    "Scheme",
    "Transport",
    "build_signing_string",
    "sign_hmac",
    "sign_ed25519",
    "sign",
    "verify",
    "verify_request",
    "serialize_body",
    "signed_request",
    "handoff",
    "urllib_transport",
    "PreparedRequest",
    "TransportResponse",
    "SignedResponse",
    "HandoffResult",
]
