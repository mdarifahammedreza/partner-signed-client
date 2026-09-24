/// Everything that can go wrong while signing, sending or reading a partner-signed request.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported signing scheme \"{0}\" — expected \"hmac\" or \"ed25519\"")]
    UnsupportedScheme(String),

    #[error("expected an Ed25519 private key in PKCS#8 PEM format: {0}")]
    InvalidPrivateKey(String),

    #[error("expected an Ed25519 public key in SPKI PEM format: {0}")]
    InvalidPublicKey(String),

    #[error("\"{0}\" is required")]
    MissingField(&'static str),

    #[error("invalid header {name:?}: {reason}")]
    InvalidHeader { name: String, reason: String },

    #[error("the response has no JSON body")]
    NoJsonBody,

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
