//! Signing primitives — a byte-for-byte port of the Node package's `src/crypto.js`, which in turn
//! must match the backend's PartnerCryptoService. Not an independent protocol, a compatible client
//! for the same one.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Prefix on every signature header value (`v1=...`).
pub const SIGNATURE_VERSION: &str = "v1";

const SIGNATURE_PREFIX: &str = "v1=";

type HmacSha256 = Hmac<Sha256>;

/// The two supported signing schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningScheme {
    /// `hex(hmac_sha256(signingString, secret))` — the secret is shared with BanglaReels.
    Hmac,
    /// `base64(ed25519_sign(signingString, privateKey))` — BanglaReels only holds your public key.
    Ed25519,
}

impl SigningScheme {
    /// The protocol name, as the Node client spells it (`"hmac"` / `"ed25519"`).
    pub fn as_str(self) -> &'static str {
        match self {
            SigningScheme::Hmac => "hmac",
            SigningScheme::Ed25519 => "ed25519",
        }
    }
}

impl fmt::Display for SigningScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SigningScheme {
    type Err = Error;

    /// Accepts `"hmac"` or `"ed25519"`, case-insensitively.
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "hmac" => Ok(SigningScheme::Hmac),
            "ed25519" => Ok(SigningScheme::Ed25519),
            _ => Err(Error::UnsupportedScheme(s.to_owned())),
        }
    }
}

/// Binds timestamp, request id and body together so tampering with any one invalidates the
/// signature: `{timestamp}.{requestId}.{hex(sha256(rawBody))}`.
///
/// `raw_body` must be the EXACT bytes sent on the wire (empty for no body).
pub fn build_signing_string(
    timestamp: &str,
    request_id: &str,
    raw_body: impl AsRef<[u8]>,
) -> String {
    let body_hash = hex::encode(Sha256::digest(raw_body.as_ref()));
    format!("{timestamp}.{request_id}.{body_hash}")
}

/// `v1=` + lowercase hex HMAC-SHA256. `secret` is the raw HMAC secret (not the encrypted-at-rest form).
pub fn sign_hmac(signing_string: &str, secret: &str) -> String {
    format!(
        "{SIGNATURE_PREFIX}{}",
        hex::encode(hmac_sha256(signing_string, secret))
    )
}

/// `v1=` + standard base64 Ed25519 signature. `private_key_pem` is a PKCS#8 PEM
/// (`-----BEGIN PRIVATE KEY-----`).
pub fn sign_ed25519(signing_string: &str, private_key_pem: &str) -> Result<String> {
    let key = SigningKey::from_pkcs8_pem(private_key_pem.trim())
        .map_err(|e| Error::InvalidPrivateKey(e.to_string()))?;
    let signature = key.sign(signing_string.as_bytes());
    Ok(format!(
        "{SIGNATURE_PREFIX}{}",
        BASE64.encode(signature.to_bytes())
    ))
}

/// Scheme-agnostic entry point — the "works for both HMAC and Ed25519" piece. Returns the
/// already-prefixed (`v1=...`) signature header value.
///
/// `secret` is the HMAC secret, or the Ed25519 private key PEM.
pub fn sign(scheme: SigningScheme, signing_string: &str, secret: &str) -> Result<String> {
    match scheme {
        SigningScheme::Hmac => Ok(sign_hmac(signing_string, secret)),
        SigningScheme::Ed25519 => sign_ed25519(signing_string, secret),
    }
}

/// Verifies an `X-Signature` header value — the piece you need inside your own `/deduct` endpoint.
/// Does NOT check the timestamp window; see [`crate::verifier`].
///
/// `key` is the HMAC secret, or the sender's Ed25519 PUBLIC key PEM (`-----BEGIN PUBLIC KEY-----`).
/// Returns `Ok(false)` for a malformed or non-matching signature, and `Err` only when the
/// Ed25519 public key itself can't be parsed. The HMAC comparison is constant-time.
pub fn verify(
    scheme: SigningScheme,
    signing_string: &str,
    signature_header: &str,
    key: &str,
) -> Result<bool> {
    let Some(encoded) = signature_header.strip_prefix(SIGNATURE_PREFIX) else {
        return Ok(false);
    };

    match scheme {
        SigningScheme::Hmac => {
            // The protocol emits lowercase hex; reject anything else before decoding.
            if encoded.bytes().any(|b| b.is_ascii_uppercase()) {
                return Ok(false);
            }
            let Ok(expected) = hex::decode(encoded) else {
                return Ok(false);
            };
            let mut mac = new_hmac(key);
            mac.update(signing_string.as_bytes());
            Ok(mac.verify_slice(&expected).is_ok())
        }
        SigningScheme::Ed25519 => {
            let public_key = VerifyingKey::from_public_key_pem(key.trim())
                .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;
            let Ok(bytes) = BASE64.decode(encoded) else {
                return Ok(false);
            };
            let Ok(signature) = Signature::from_slice(&bytes) else {
                return Ok(false);
            };
            Ok(public_key
                .verify(signing_string.as_bytes(), &signature)
                .is_ok())
        }
    }
}

fn new_hmac(secret: &str) -> HmacSha256 {
    HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length")
}

fn hmac_sha256(message: &str, secret: &str) -> Vec<u8> {
    let mut mac = new_hmac(secret);
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
