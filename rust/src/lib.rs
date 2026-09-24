//! Rust port of the Node package in the repo root: BanglaReels' Business Partner signed-request
//! protocol, with both supported schemes (**HMAC** and **Ed25519**), byte-for-byte compatible with
//! the Node `src/crypto.js`.
//!
//! - [`crypto`] — signing primitives (`build_signing_string`, `sign_hmac`, `sign_ed25519`, `sign`,
//!   `verify`), the equivalent of `src/crypto.js`.
//! - [`PartnerClient`] — `signed_request` and `handoff`, the equivalent of `src/client.js` and
//!   `src/handoff.js`.
//! - [`verifier`] — receiving-side check (timestamp window + signature) for your own `/deduct`
//!   endpoint.

pub mod client;
pub mod crypto;
mod error;
pub mod models;
pub mod verifier;

pub use client::{DEFAULT_API_PREFIX, PartnerClient};
pub use crypto::SigningScheme;
pub use error::{Error, Result};
pub use models::{
    HandoffOptions, HandoffRequest, HandoffResult, SignedRequestOptions, SignedResponse,
};
pub use verifier::SignedHeaders;
