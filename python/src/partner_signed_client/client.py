"""The universal signed-request client (= ``src/client.js`` + ``src/handoff.js``).

Works for both HMAC and Ed25519, calls the target URL, and returns the response. Compatible with
BOTH directions of BanglaReels' partner protocol:

* Calling INTO BanglaReels (any endpoint under PartnerSignatureGuard): pass ``partner_id`` so
  ``X-Partner-Id`` is sent.
* Simulating what BanglaReels sends OUT to a partner's own ``/deduct`` endpoint: leave
  ``partner_id`` as ``None``; that direction never sends it.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from .crypto import Scheme, build_signing_string, sign
from .models import PreparedRequest, SignedResponse, TransportResponse

__all__ = ["Transport", "urllib_transport", "serialize_body", "signed_request", "handoff"]

#: A callable that actually performs the HTTP exchange. Swap it out to use ``requests``/``httpx``,
#: or to capture requests in tests.
Transport = Callable[[PreparedRequest], TransportResponse]

_USER_AGENT = "danumai-partner-signed-client-python/0.1"


def _drop_none(value: Any) -> Any:
    # JSON.stringify drops `undefined` object fields; None plays that role here.
    if isinstance(value, Mapping):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple)):
        return [_drop_none(v) for v in value]
    return value


def serialize_body(body: Any) -> bytes:
    """Serialize ``body`` exactly like Node's ``JSON.stringify`` would, as UTF-8 bytes.

    Compact separators, no ``\\u`` escaping of ``+`` or non-ASCII, ``None`` fields omitted, key
    order preserved. ``None`` means no body (``b""``). A ``str``/``bytes`` body is taken as an
    already-serialized raw body and sent as-is.
    """
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(
        _drop_none(body), separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def urllib_transport(request: PreparedRequest) -> TransportResponse:
    """Default transport: stdlib ``urllib.request``. Non-2xx responses are returned, not raised."""
    req = urllib.request.Request(
        request.url,
        data=request.body if request.body else None,
        headers=dict(request.headers),
        method=request.method,
    )
    try:
        with urllib.request.urlopen(req, timeout=request.timeout) as resp:
            return TransportResponse(resp.status, _header_dict(resp.headers), resp.read())
    except urllib.error.HTTPError as error:
        with error:
            return TransportResponse(error.code, _header_dict(error.headers), error.read())


def _header_dict(message: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in message.items():
        key = name.lower()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return headers


def signed_request(
    *,
    base_url: str,
    path: str,
    scheme: Scheme,
    secret: str,
    method: str = "POST",
    body: Any = None,
    partner_id: str | None = None,
    request_id: str | None = None,
    extra_headers: Mapping[str, str] | None = None,
    timeout: float | None = 30.0,
    transport: Transport | None = None,
) -> SignedResponse:
    """Sign and send a request to any partner-signed endpoint.

    :param base_url: e.g. ``https://dev-api.banglareels.com`` or a partner's own API base.
    :param path: e.g. ``/api/v1/partner/auth/merge-confirm``.
    :param scheme: ``"hmac"`` or ``"ed25519"``.
    :param secret: HMAC secret, or Ed25519 private key PEM.
    :param body: sent as JSON (see :func:`serialize_body`); ``None`` for no body.
    :param partner_id: ``X-Partner-Id``; omit for the outbound (BanglaReels -> partner) direction.
    :param request_id: ``X-Request-Id``; reuse the same value on any retry of the same attempt.
        Auto-generated (UUID4) if omitted.
    :param transport: override the HTTP layer (defaults to :func:`urllib_transport`).
    """
    if not base_url:
        raise ValueError('signed_request: "base_url" is required')
    if not path:
        raise ValueError('signed_request: "path" is required')
    if not scheme:
        raise ValueError('signed_request: "scheme" is required ("hmac" | "ed25519")')
    if not secret:
        raise ValueError('signed_request: "secret" is required')

    request_id = request_id or str(uuid.uuid4())
    timestamp = str(int(time.time()))
    # Signed and sent as the EXACT same bytes; re-serializing after signing (e.g. a different key
    # order) would produce a body whose hash no longer matches the signature.
    raw_body = serialize_body(body)

    signing_string = build_signing_string(timestamp, request_id, raw_body)
    signature = sign(scheme, signing_string, secret)

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": _USER_AGENT,
        "X-Request-Id": request_id,
        "X-Timestamp": timestamp,
        "X-Signature": signature,
    }
    if partner_id:
        headers["X-Partner-Id"] = partner_id
    if extra_headers:
        # Case-insensitive override, like fetch's Headers.
        for name, value in extra_headers.items():
            for existing in [h for h in headers if h.lower() == name.lower()]:
                del headers[existing]
            headers[name] = value

    url = base_url.rstrip("/") + (path if path.startswith("/") else f"/{path}")
    prepared = PreparedRequest(
        method=method.upper(), url=url, headers=headers, body=raw_body, timeout=timeout
    )

    raw = (transport or urllib_transport)(prepared)
    headers_lower = {k.lower(): v for k, v in raw.headers.items()}
    text = raw.body.decode("utf-8", errors="replace")

    parsed: Any = None
    if "json" in headers_lower.get("content-type", "").lower():
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None

    return SignedResponse(
        status=raw.status,
        ok=200 <= raw.status <= 299,
        headers=headers_lower,
        raw_body=text,
        json=parsed,
    )


def handoff(
    *,
    base_url: str,
    scheme: Scheme,
    secret: str,
    partner_id: str,
    partner_user_id: str,
    phone_number: str,
    name: str | None = None,
    email: str | None = None,
    return_path: str | None = None,
    request_id: str | None = None,
    api_prefix: str = "/api/v1",
    timeout: float | None = 30.0,
    transport: Transport | None = None,
) -> SignedResponse:
    """The actual flow: sign + call ``POST {api_prefix}/partner/auth/handoff``.

    The API wraps the result in an envelope; read it with
    ``HandoffResult.from_dict(response.data)`` to get
    ``handoff_code, expires_in, entry_url, has_active_subscription, pending_merge``.
    """
    if not partner_id:
        raise ValueError('handoff: "partner_id" (X-Partner-Id) is required for this call')
    if not partner_user_id:
        raise ValueError('handoff: "partner_user_id" is required')
    if not phone_number:
        raise ValueError('handoff: "phone_number" is required')

    # Field order matches PartnerHandoffDto (and the Node client's object literal).
    body = {
        "partnerUserId": partner_user_id,
        "phoneNumber": phone_number,
        "name": name,
        "email": email,
        "returnPath": return_path,
    }
    return signed_request(
        base_url=base_url,
        path=f"{api_prefix}/partner/auth/handoff",
        method="POST",
        scheme=scheme,
        secret=secret,
        partner_id=partner_id,
        request_id=request_id,
        body=body,
        timeout=timeout,
        transport=transport,
    )
