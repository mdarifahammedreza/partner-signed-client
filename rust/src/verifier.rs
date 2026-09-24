//! Receiving-side check for a signed request — use it in your own `/deduct` endpoint to validate
//! what BanglaReels sends you. Mirrors what the backend's PartnerSignatureGuard does for the
//! into-BanglaReels direction: timestamp window, then signature over the exact raw body.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::HeaderMap;

use crate::crypto::{self, SigningScheme};
use crate::error::Result;

/// Allowed clock skew between sender and receiver (±300s).
pub const DEFAULT_TOLERANCE: Duration = Duration::from_secs(300);

/// The three signature headers of an incoming request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignedHeaders<'a> {
    /// `X-Timestamp` (Unix seconds).
    pub timestamp: Option<&'a str>,
    /// `X-Request-Id`.
    pub request_id: Option<&'a str>,
    /// `X-Signature` (`v1=...`).
    pub signature: Option<&'a str>,
}

impl<'a> SignedHeaders<'a> {
    pub fn new(timestamp: &'a str, request_id: &'a str, signature: &'a str) -> Self {
        Self {
            timestamp: Some(timestamp),
            request_id: Some(request_id),
            signature: Some(signature),
        }
    }

    /// Reads `X-Timestamp`, `X-Request-Id` and `X-Signature` from an `http` header map (the type
    /// used by reqwest, axum, hyper, ...). Missing or non-UTF-8 headers become `None`.
    pub fn from_header_map(headers: &'a HeaderMap) -> Self {
        let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
        Self {
            timestamp: get("x-timestamp"),
            request_id: get("x-request-id"),
            signature: get("x-signature"),
        }
    }
}

/// Verifies an incoming signed request against the current time with the default ±300s window.
///
/// - `key`: HMAC secret, or the sender's Ed25519 PUBLIC key PEM.
/// - `raw_body`: the request body EXACTLY as received — read it before deserializing.
///
/// Returns `Ok(false)` for missing headers, a stale/unparseable timestamp or a bad signature.
pub fn verify_request(
    scheme: SigningScheme,
    key: &str,
    headers: &SignedHeaders<'_>,
    raw_body: impl AsRef<[u8]>,
) -> Result<bool> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    verify_request_at(scheme, key, headers, raw_body, now, DEFAULT_TOLERANCE)
}

/// Like [`verify_request`], with an explicit "now" (Unix seconds) and tolerance — handy for tests.
pub fn verify_request_at(
    scheme: SigningScheme,
    key: &str,
    headers: &SignedHeaders<'_>,
    raw_body: impl AsRef<[u8]>,
    now_unix_secs: i64,
    tolerance: Duration,
) -> Result<bool> {
    let (Some(timestamp), Some(request_id), Some(signature)) =
        (headers.timestamp, headers.request_id, headers.signature)
    else {
        return Ok(false);
    };
    if timestamp.is_empty() || request_id.is_empty() || signature.is_empty() {
        return Ok(false);
    }

    let Ok(sent_at) = timestamp.parse::<i64>() else {
        return Ok(false);
    };
    if now_unix_secs.abs_diff(sent_at) > tolerance.as_secs() {
        return Ok(false);
    }

    let signing_string = crypto::build_signing_string(timestamp, request_id, raw_body);
    crypto::verify(scheme, &signing_string, signature, key)
}
