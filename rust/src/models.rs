//! Request options, the handoff body/result, and the response type every signed call returns.

use std::collections::HashMap;

use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::DEFAULT_API_PREFIX;
use crate::crypto::SigningScheme;
use crate::error::{Error, Result};

/// Options for [`crate::PartnerClient::signed_request`]. Build with [`SignedRequestOptions::new`]
/// and the chained setters.
#[derive(Debug, Clone)]
pub struct SignedRequestOptions {
    /// e.g. `https://dev-api.banglareels.com` or a partner's own API base.
    pub base_url: String,
    /// e.g. `/api/v1/partner/auth/merge-confirm`.
    pub path: String,
    /// Defaults to POST.
    pub method: Method,
    /// The raw JSON body, exactly as it will be signed and sent; `None` for no body.
    /// Set it with [`SignedRequestOptions::json`] (or [`SignedRequestOptions::raw_body`]).
    pub body: Option<String>,
    pub scheme: SigningScheme,
    /// HMAC secret, or Ed25519 private key PEM.
    pub secret: String,
    /// `X-Partner-Id` — leave `None` for the outbound (BanglaReels → partner) direction.
    pub partner_id: Option<String>,
    /// `X-Request-Id` — reuse the same value on any retry of the same attempt; a UUID is generated
    /// when `None`.
    pub request_id: Option<String>,
    /// Additional headers, sent after (and overriding) the protocol headers.
    pub extra_headers: Vec<(String, String)>,
}

impl SignedRequestOptions {
    pub fn new(
        base_url: impl Into<String>,
        path: impl Into<String>,
        scheme: SigningScheme,
        secret: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            path: path.into(),
            method: Method::POST,
            body: None,
            scheme,
            secret: secret.into(),
            partner_id: None,
            request_id: None,
            extra_headers: Vec::new(),
        }
    }

    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Serializes `body` with `serde_json::to_string` — compact, no escaping of `+` or non-ASCII,
    /// fields in declaration order — i.e. the same bytes `JSON.stringify` produces. Mark optional
    /// fields `#[serde(skip_serializing_if = "Option::is_none")]` to mirror `undefined` being dropped.
    pub fn json<T: Serialize + ?Sized>(mut self, body: &T) -> Result<Self> {
        self.body = Some(serde_json::to_string(body)?);
        Ok(self)
    }

    /// Uses `body` verbatim as the (already-serialized) JSON body.
    pub fn raw_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn partner_id(mut self, partner_id: impl Into<String>) -> Self {
        self.partner_id = Some(partner_id.into());
        self
    }

    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
        self
    }
}

/// Options for [`crate::PartnerClient::handoff`]. Build with [`HandoffOptions::new`] and the
/// chained setters for the optional fields.
#[derive(Debug, Clone)]
pub struct HandoffOptions {
    /// e.g. `https://dev-api.banglareels.com`.
    pub base_url: String,
    /// Defaults to `/api/v1`.
    pub api_prefix: String,
    pub scheme: SigningScheme,
    /// HMAC secret, or Ed25519 private key PEM.
    pub secret: String,
    /// Your partner slug (`X-Partner-Id`).
    pub partner_id: String,
    /// Your own user id; must match what you'll later send on payment callbacks.
    pub partner_user_id: String,
    /// E.164 preferred.
    pub phone_number: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub return_path: Option<String>,
    pub request_id: Option<String>,
}

impl HandoffOptions {
    pub fn new(
        base_url: impl Into<String>,
        scheme: SigningScheme,
        secret: impl Into<String>,
        partner_id: impl Into<String>,
        partner_user_id: impl Into<String>,
        phone_number: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            api_prefix: DEFAULT_API_PREFIX.to_owned(),
            scheme,
            secret: secret.into(),
            partner_id: partner_id.into(),
            partner_user_id: partner_user_id.into(),
            phone_number: phone_number.into(),
            name: None,
            email: None,
            return_path: None,
            request_id: None,
        }
    }

    pub fn api_prefix(mut self, api_prefix: impl Into<String>) -> Self {
        self.api_prefix = api_prefix.into();
        self
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn return_path(mut self, return_path: impl Into<String>) -> Self {
        self.return_path = Some(return_path.into());
        self
    }

    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
}

/// Body of `POST partner/auth/handoff` — matches PartnerHandoffDto, same field order, `None`
/// fields left out (like `undefined` under `JSON.stringify`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoffRequest {
    pub partner_user_id: String,
    pub phone_number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_path: Option<String>,
}

/// Successful handoff response (HandoffResult), found inside the API envelope's `data`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoffResult {
    pub handoff_code: String,
    pub expires_in: i64,
    pub entry_url: String,
    pub has_active_subscription: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_merge: Option<Value>,
}

/// What every signed call returns.
#[derive(Debug, Clone)]
pub struct SignedResponse {
    pub status: u16,
    /// `true` for a 2xx status.
    pub ok: bool,
    /// Response headers, names lowercased, repeated values joined with `", "`.
    pub headers: HashMap<String, String>,
    /// The response body as text, always populated.
    pub raw_body: String,
    /// Parsed JSON when the response declares a JSON content-type and parses; otherwise `None`.
    pub json: Option<Value>,
}

impl SignedResponse {
    /// Deserializes the whole JSON body into `T`.
    pub fn body_as<T: DeserializeOwned>(&self) -> Result<T> {
        let json = self.json.as_ref().ok_or(Error::NoJsonBody)?;
        Ok(T::deserialize(json)?)
    }

    /// Deserializes the payload inside BanglaReels' response envelope
    /// (`{ status, statusCode, message, data, ... }`) — e.g. `data_as::<HandoffResult>()`.
    /// Falls back to the root value when there's no `data` property.
    pub fn data_as<T: DeserializeOwned>(&self) -> Result<T> {
        let json = self.json.as_ref().ok_or(Error::NoJsonBody)?;
        let payload = json.get("data").unwrap_or(json);
        Ok(T::deserialize(payload)?)
    }
}
