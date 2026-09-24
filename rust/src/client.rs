//! The universal signed-request client — works for both HMAC and Ed25519, calls the target URL,
//! and returns the response. Compatible with BOTH directions of BanglaReels' partner protocol:
//!
//! - Calling INTO BanglaReels (any endpoint under PartnerSignatureGuard): set `partner_id` so
//!   `X-Partner-Id` is sent.
//! - Simulating what BanglaReels sends OUT to a partner's own `/deduct` endpoint: leave
//!   `partner_id` as `None` — that direction never sends it.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use crate::crypto::{build_signing_string, sign};
use crate::error::{Error, Result};
use crate::models::{HandoffOptions, HandoffRequest, SignedRequestOptions, SignedResponse};

/// Default API prefix for BanglaReels endpoints.
pub const DEFAULT_API_PREFIX: &str = "/api/v1";

/// Async client for partner-signed endpoints. Cheap to clone (wraps a [`reqwest::Client`]).
#[derive(Debug, Clone, Default)]
pub struct PartnerClient {
    http: reqwest::Client,
}

impl PartnerClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses an existing [`reqwest::Client`] (custom timeouts, proxies, connection pool, ...).
    pub fn with_client(http: reqwest::Client) -> Self {
        Self { http }
    }

    /// Signs and sends a request to any partner-signed endpoint.
    pub async fn signed_request(&self, options: SignedRequestOptions) -> Result<SignedResponse> {
        require("base_url", &options.base_url)?;
        require("path", &options.path)?;
        require("secret", &options.secret)?;

        let request_id = options
            .request_id
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let timestamp = unix_now().to_string();
        // Signed and sent as the EXACT same bytes — re-serializing after signing (e.g. a different
        // key order) would produce a body whose hash no longer matches the signature.
        let raw_body = options.body.unwrap_or_default();

        let signing_string = build_signing_string(&timestamp, &request_id, &raw_body);
        let signature = sign(options.scheme, &signing_string, &options.secret)?;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        insert_header(&mut headers, "X-Request-Id", &request_id)?;
        insert_header(&mut headers, "X-Timestamp", &timestamp)?;
        insert_header(&mut headers, "X-Signature", &signature)?;
        if let Some(partner_id) = options.partner_id.as_deref().filter(|id| !id.is_empty()) {
            insert_header(&mut headers, "X-Partner-Id", partner_id)?;
        }
        for (name, value) in &options.extra_headers {
            insert_header(&mut headers, name, value)?;
        }

        let path = if options.path.starts_with('/') {
            options.path
        } else {
            format!("/{}", options.path)
        };
        let url = format!("{}{path}", options.base_url.trim_end_matches('/'));

        let mut request = self.http.request(options.method, url).headers(headers);
        if !raw_body.is_empty() {
            request = request.body(raw_body);
        }
        let response = request.send().await?;

        let status = response.status();
        let headers = collect_headers(response.headers());
        let is_json = headers
            .get("content-type")
            .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"));
        let raw_body = response.text().await?;
        let json = if is_json {
            serde_json::from_str::<Value>(&raw_body).ok()
        } else {
            None
        };

        Ok(SignedResponse {
            status: status.as_u16(),
            ok: status.is_success(),
            headers,
            raw_body,
            json,
        })
    }

    /// The actual flow: sign + call `POST {api_prefix}/partner/auth/handoff` and get back
    /// `{ handoffCode, expiresIn, entryUrl, hasActiveSubscription, pendingMerge? }` — read it with
    /// `response.data_as::<HandoffResult>()` (the API wraps it in an envelope).
    pub async fn handoff(&self, options: HandoffOptions) -> Result<SignedResponse> {
        require("partner_id", &options.partner_id)?;
        require("partner_user_id", &options.partner_user_id)?;
        require("phone_number", &options.phone_number)?;

        let body = HandoffRequest {
            partner_user_id: options.partner_user_id,
            phone_number: options.phone_number,
            name: options.name,
            email: options.email,
            return_path: options.return_path,
        };

        let mut request = SignedRequestOptions::new(
            options.base_url,
            format!("{}/partner/auth/handoff", options.api_prefix),
            options.scheme,
            options.secret,
        )
        .partner_id(options.partner_id)
        .json(&body)?;
        request.request_id = options.request_id;

        self.signed_request(request).await
    }
}

fn require(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(Error::MissingField(field))
    } else {
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<()> {
    let invalid = |reason: String| Error::InvalidHeader {
        name: name.to_owned(),
        reason,
    };
    let header_name =
        HeaderName::from_bytes(name.as_bytes()).map_err(|e| invalid(e.to_string()))?;
    let header_value = HeaderValue::from_str(value).map_err(|e| invalid(e.to_string()))?;
    headers.insert(header_name, header_value);
    Ok(())
}

fn collect_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    for (name, value) in headers {
        let value = String::from_utf8_lossy(value.as_bytes());
        out.entry(name.as_str().to_owned())
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(&value);
            })
            .or_insert_with(|| value.into_owned());
    }
    out
}
