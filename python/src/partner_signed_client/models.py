"""Request/response data types."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = ["PreparedRequest", "TransportResponse", "SignedResponse", "HandoffResult"]


@dataclass(frozen=True)
class PreparedRequest:
    """A fully signed request, handed to the transport. ``body`` is the exact signed bytes."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes
    timeout: float | None = None


@dataclass(frozen=True)
class TransportResponse:
    """What a transport returns: status, headers and the raw body bytes."""

    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class SignedResponse:
    """What every signed call returns."""

    status: int
    ok: bool
    #: Response headers, names lower-cased.
    headers: Mapping[str, str]
    #: The response body as text, always populated.
    raw_body: str
    #: Parsed JSON when the response declares a JSON content-type and parses; otherwise ``None``.
    json: Any = field(default=None)

    @property
    def data(self) -> Any:
        """The payload inside BanglaReels' response envelope ``{status, statusCode, message, data}``.

        Falls back to the parsed root when there's no ``data`` key; ``None`` without a JSON body.
        """
        if isinstance(self.json, dict) and "data" in self.json:
            return self.json["data"]
        return self.json


@dataclass(frozen=True)
class HandoffResult:
    """Successful ``POST partner/auth/handoff`` payload (HandoffResult)."""

    handoff_code: str
    expires_in: int
    entry_url: str
    has_active_subscription: bool
    pending_merge: Any = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HandoffResult:
        return cls(
            handoff_code=data["handoffCode"],
            expires_in=data["expiresIn"],
            entry_url=data["entryUrl"],
            has_active_subscription=data["hasActiveSubscription"],
            pending_merge=data.get("pendingMerge"),
        )
