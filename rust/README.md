# partner-signed-client (Rust)

Rust port of the Node package in the repo root: the same **HMAC** and **Ed25519** partner
signed-request protocol, byte-for-byte compatible. The tests check it against signatures produced
by the Node `src/crypto.js`.

Requires Rust 1.85+ (edition 2024). The client is async, built on [`reqwest`](https://crates.io/crates/reqwest)
with rustls, so there's no system OpenSSL dependency. Run it inside a Tokio runtime. Crypto comes
from the RustCrypto / dalek crates (`hmac`, `sha2`, `ed25519-dalek`).

```
rust/
├── Cargo.toml
├── src/
│   ├── crypto.rs     # build_signing_string, sign_hmac, sign_ed25519, sign, verify, SigningScheme  (= src/crypto.js)
│   ├── client.rs     # PartnerClient::signed_request, PartnerClient::handoff                         (= src/client.js + src/handoff.js)
│   ├── verifier.rs   # receiving-side check for your own /deduct endpoint (±300s window)
│   ├── models.rs     # options, HandoffRequest/HandoffResult, SignedResponse
│   └── error.rs
├── examples/handoff.rs   # = examples/test-handoff-{hmac,ed25519}.js
└── tests/compatibility.rs
```

## Run

```sh
cd rust
cargo test                                   # compatibility tests (offline, uses a local test server)

# Uses the same repo-root .env as the Node examples (copy .env.example → .env)
cargo run --example handoff -- hmac
cargo run --example handoff -- ed25519
```

## Install

It isn't on crates.io. Depend on it by path or git:

```toml
[dependencies]
partner-signed-client = { path = "../handshake/rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Handoff flow

```rust
use partner_signed_client::{HandoffOptions, HandoffResult, PartnerClient, SigningScheme};

let client = PartnerClient::new(); // or PartnerClient::with_client(your_reqwest_client)

let response = client
    .handoff(HandoffOptions::new(
        "https://dev-api.banglareels.com",
        SigningScheme::Hmac,          // or SigningScheme::Ed25519
        std::env::var("SIGNING_SECRET")?, // HMAC secret, or Ed25519 private key PEM
        "your-partner-slug",          // sent as X-Partner-Id
        "YOUR_USER_889123",           // your own user id
        "+8801712345678",             // E.164 preferred
    ))
    .await?;

if response.ok {
    // The API wraps results as { status, statusCode, message, data }. data_as unwraps `data`.
    let result: HandoffResult = response.data_as()?;
    // result.entry_url → redirect the subscriber's browser here
    // result.handoff_code → single-use, ~60s TTL
}
```

The optional fields have chained setters: `.name(..)`, `.email(..)`, `.return_path(..)`,
`.request_id(..)` and `.api_prefix(..)` (default `/api/v1`).

For Ed25519, pass `SigningScheme::Ed25519`. The secret is then the PKCS#8 private key PEM
(`-----BEGIN PRIVATE KEY-----`). You can generate one with Node, or with
`openssl genpkey -algorithm ed25519`.

`SignedResponse` has `status`, `ok`, `headers` (lowercased names), `raw_body` (always set) and
`json` (a `serde_json::Value` when the response is JSON). `body_as::<T>()` deserializes the whole
body, and `data_as::<T>()` deserializes the envelope's `data`.

## Any other signed endpoint

```rust
use partner_signed_client::{PartnerClient, SignedRequestOptions, SigningScheme};
use serde_json::json;

let options = SignedRequestOptions::new(
    "https://dev-api.banglareels.com",
    "/api/v1/partner/auth/merge-confirm",
    SigningScheme::Hmac,
    secret,
)
.partner_id("your-partner-slug") // leave it off to simulate BanglaReels → your /deduct
.json(&json!({ "partnerUserId": "YOUR_USER_889123" }))?;

let response = PartnerClient::new().signed_request(options).await?;
```

The method defaults to POST. Use `.method(reqwest::Method::PUT)` to change it and
`.header(name, value)` for extra headers.

`.json(..)` serializes with `serde_json::to_string`. The output is compact, doesn't escape `+` or
non-ASCII characters, and keeps field order (the crate enables serde_json's `preserve_order`, so
`json!` bodies keep their key order too). This matches `JSON.stringify`, so the Rust client sends
exactly the same bytes as the Node client. The bytes that get signed are the bytes that get sent.
For your own body structs, mark optional fields
`#[serde(skip_serializing_if = "Option::is_none")]`: `JSON.stringify` drops `undefined` fields
instead of writing `null`. `HandoffRequest` already does this.

## Verifying BanglaReels' calls to your `/deduct` (axum)

Sign and verify against the **raw body bytes**. Take the body as `Bytes` and deserialize it
yourself after verifying. A `Json<T>` extractor would re-serialize, and that copy won't hash the
same.

```rust
use axum::{body::Bytes, http::{HeaderMap, StatusCode}, routing::post, Router};
use partner_signed_client::{verifier, SignedHeaders, SigningScheme};

async fn deduct(headers: HeaderMap, body: Bytes) -> StatusCode {
    let valid = verifier::verify_request(
        SigningScheme::Hmac,
        &outbound_signing_secret(),             // HMAC secret, or Ed25519 PUBLIC key PEM
        &SignedHeaders::from_header_map(&headers),
        &body,                                  // also enforces the ±300s timestamp window
    );
    if !matches!(valid, Ok(true)) {
        return StatusCode::UNAUTHORIZED;
    }

    let Ok(deduct) = serde_json::from_slice::<DeductRequest>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    // dedupe on X-Request-Id / idempotencyKey, then charge...
    StatusCode::OK
}

let app = Router::new().route("/deduct", post(deduct));
```

`SignedHeaders::from_header_map` takes the `http` crate's `HeaderMap` (the one reqwest re-exports).
axum uses the same crate, so its `HeaderMap` works as long as both are on `http` 1.x.

`verify_request` returns `Ok(false)` for missing headers, a stale timestamp or a bad signature.
It returns `Err` only when the Ed25519 public key can't be parsed. HMAC comparison is
constant-time. Use `verifier::verify_request_at` to pass your own clock and tolerance, and
`crypto::verify` to check a signature without the timestamp window.

The protocol itself is described in the root [README](../README.md#how-the-signature-is-built).
