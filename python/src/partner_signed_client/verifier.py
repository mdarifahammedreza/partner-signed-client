"""Receiving-side check for a signed request.

Use it in your own ``/deduct`` endpoint to validate what BanglaReels sends you. Mirrors what the
backend's PartnerSignatureGuard does for the into-BanglaReels direction: timestamp window, then
signature over the exact raw body.
"""

from __future__ import annotations

import time

from .crypto import Scheme, _Body, build_signing_string, verify

__all__ = ["DEFAULT_TOLERANCE_SECONDS", "verify_request"]

#: Allowed clock skew between sender and receiver (+/-300s).
DEFAULT_TOLERANCE_SECONDS = 300


def verify_request(
    scheme: Scheme,
    key: str,
    timestamp: str | None,
    request_id: str | None,
    signature: str | None,
    raw_body: _Body,
    *,
    now: float | None = None,
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
) -> bool:
    """Return ``True`` when the headers carry a fresh, valid signature over ``raw_body``.

    :param key: HMAC secret, or the sender's Ed25519 PUBLIC key PEM.
    :param timestamp: the ``X-Timestamp`` header.
    :param request_id: the ``X-Request-Id`` header.
    :param signature: the ``X-Signature`` header.
    :param raw_body: the request body EXACTLY as received (``bytes`` or ``str``). Read it before
        any JSON parsing / model binding.
    :param now: Unix seconds to compare against (defaults to the current time).
    """
    if not timestamp or not request_id or not signature:
        return False
    try:
        unix_seconds = int(timestamp)
    except ValueError:
        return False

    current = time.time() if now is None else now
    if abs(int(current) - unix_seconds) > tolerance_seconds:
        return False

    signing_string = build_signing_string(timestamp, request_id, raw_body)
    return verify(scheme, signing_string, signature, key)
