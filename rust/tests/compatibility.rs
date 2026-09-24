//! Expected values below were produced by the Node package (src/crypto.js) with the same inputs —
//! these tests prove the Rust port is byte-for-byte compatible, not just self-consistent.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use partner_signed_client::crypto::{self, build_signing_string, sign, sign_ed25519, sign_hmac};
use partner_signed_client::verifier::{self, DEFAULT_TOLERANCE};
use partner_signed_client::{
    HandoffOptions, HandoffRequest, HandoffResult, PartnerClient, SignedHeaders,
    SignedRequestOptions, SigningScheme,
};
use serde_json::json;

const PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICqluVmfy4RygW/w10w4mU2qd2RMl1m+VcGY+Ht/tenr\n-----END PRIVATE KEY-----\n";
const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAwUUCAZnYdD/YD/OKg74wzRbPfJtuA6nDknhqFnrxnz4=\n-----END PUBLIC KEY-----\n";

const NODE_BODY: &str = r#"{"partnerUserId":"USER_1","phoneNumber":"+8801712345678","name":"রেজা"}"#;
const NODE_SIGNING_STRING: &str =
    "1700000000.req-123.afc0e72029cb181220d7ac92b6321c59ff563606d4fff55371d1eba4177bb1f9";
const NODE_HMAC: &str = "v1=e5125595fc9ec8bc1c6dc3b0a7ec636b7cbd73fe532c1becd77469a3b571e032";
const NODE_ED25519: &str =
    "v1=fw3pu56QonGoY/ID0IJNzZilLwqdKpHRA9HJXsekMQKtMcSMpbVK6E/63DQPmEHtz4jaFltGQAjtWaKh0G5AAg==";

const ENVELOPE: &str = r#"{"status":true,"statusCode":200,"message":"Request successful","data":{"handoffCode":"CODE","expiresIn":60,"entryUrl":"https://app.test/entry?code=CODE","hasActiveSubscription":false}}"#;

// ---------------------------------------------------------------------------------------------
// crypto
// ---------------------------------------------------------------------------------------------

#[test]
fn signing_string_matches_node() {
    assert_eq!(
        build_signing_string("1700000000", "req-123", NODE_BODY),
        NODE_SIGNING_STRING
    );
}

#[test]
fn signing_string_empty_body_hashes_empty_string() {
    assert_eq!(
        build_signing_string("1", "r", ""),
        "1.r.e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn hmac_matches_node() {
    assert_eq!(sign_hmac(NODE_SIGNING_STRING, "test-secret"), NODE_HMAC);
    assert_eq!(
        sign(SigningScheme::Hmac, NODE_SIGNING_STRING, "test-secret").unwrap(),
        NODE_HMAC
    );
}

#[test]
fn ed25519_matches_node() {
    assert_eq!(
        sign_ed25519(NODE_SIGNING_STRING, PRIVATE_KEY_PEM).unwrap(),
        NODE_ED25519
    );
    assert_eq!(
        sign(SigningScheme::Ed25519, NODE_SIGNING_STRING, PRIVATE_KEY_PEM).unwrap(),
        NODE_ED25519
    );
}

#[test]
fn verify_accepts_valid_rejects_tampered() {
    assert!(
        crypto::verify(
            SigningScheme::Hmac,
            NODE_SIGNING_STRING,
            NODE_HMAC,
            "test-secret"
        )
        .unwrap()
    );
    assert!(
        crypto::verify(
            SigningScheme::Ed25519,
            NODE_SIGNING_STRING,
            NODE_ED25519,
            PUBLIC_KEY_PEM
        )
        .unwrap()
    );

    let tampered = NODE_SIGNING_STRING.replace("req-123", "req-124");
    assert!(!crypto::verify(SigningScheme::Hmac, &tampered, NODE_HMAC, "test-secret").unwrap());
    assert!(
        !crypto::verify(
            SigningScheme::Ed25519,
            &tampered,
            NODE_ED25519,
            PUBLIC_KEY_PEM
        )
        .unwrap()
    );
}

#[test]
fn verify_rejects_wrong_key_and_malformed_signatures() {
    assert!(
        !crypto::verify(
            SigningScheme::Hmac,
            NODE_SIGNING_STRING,
            NODE_HMAC,
            "wrong-secret"
        )
        .unwrap()
    );

    // A different Ed25519 key pair's public key.
    let other_public = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAw0IxqZxQm/OFH38XArlO/wisHmAh5WHWGBZFrHUzY0Q=\n-----END PUBLIC KEY-----\n";
    assert!(
        !crypto::verify(
            SigningScheme::Ed25519,
            NODE_SIGNING_STRING,
            NODE_ED25519,
            other_public
        )
        .unwrap()
    );

    // Missing prefix, bad encoding, uppercase hex, truncated signature.
    assert!(
        !crypto::verify(
            SigningScheme::Hmac,
            NODE_SIGNING_STRING,
            &NODE_HMAC[3..],
            "test-secret"
        )
        .unwrap()
    );
    assert!(
        !crypto::verify(
            SigningScheme::Hmac,
            NODE_SIGNING_STRING,
            "v1=zz",
            "test-secret"
        )
        .unwrap()
    );
    assert!(
        !crypto::verify(
            SigningScheme::Hmac,
            NODE_SIGNING_STRING,
            &NODE_HMAC.to_uppercase().replace("V1=", "v1="),
            "test-secret"
        )
        .unwrap()
    );
    assert!(
        !crypto::verify(
            SigningScheme::Ed25519,
            NODE_SIGNING_STRING,
            "v1=!!!",
            PUBLIC_KEY_PEM
        )
        .unwrap()
    );
    assert!(
        !crypto::verify(
            SigningScheme::Ed25519,
            NODE_SIGNING_STRING,
            "v1=AAAA",
            PUBLIC_KEY_PEM
        )
        .unwrap()
    );

    // An unparseable public key is an error, not a silent `false`.
    assert!(
        crypto::verify(
            SigningScheme::Ed25519,
            NODE_SIGNING_STRING,
            NODE_ED25519,
            "not a pem"
        )
        .is_err()
    );
    assert!(sign_ed25519(NODE_SIGNING_STRING, "not a pem").is_err());
}

#[test]
fn scheme_parses_like_node() {
    assert_eq!(
        "hmac".parse::<SigningScheme>().unwrap(),
        SigningScheme::Hmac
    );
    assert_eq!(
        "Ed25519".parse::<SigningScheme>().unwrap(),
        SigningScheme::Ed25519
    );
    assert!("rsa".parse::<SigningScheme>().is_err());
    assert_eq!(SigningScheme::Ed25519.to_string(), "ed25519");
}

#[test]
fn handoff_body_serializes_like_json_stringify() {
    let body = HandoffRequest {
        partner_user_id: "USER_1".into(),
        phone_number: "+8801712345678".into(),
        name: Some("রেজা".into()),
        email: None,
        return_path: None,
    };
    assert_eq!(serde_json::to_string(&body).unwrap(), NODE_BODY);
}

// ---------------------------------------------------------------------------------------------
// verifier
// ---------------------------------------------------------------------------------------------

#[test]
fn verifier_enforces_timestamp_window() {
    let headers = SignedHeaders::new("1700000000", "req-123", NODE_HMAC);
    let verify_at = |now| {
        verifier::verify_request_at(
            SigningScheme::Hmac,
            "test-secret",
            &headers,
            NODE_BODY,
            now,
            DEFAULT_TOLERANCE,
        )
        .unwrap()
    };

    assert!(verify_at(1_700_000_000 + 299));
    assert!(verify_at(1_700_000_000 - 299));
    assert!(!verify_at(1_700_000_000 + 301));
    assert!(!verify_at(1_700_000_000 - 301));
}

#[test]
fn verifier_rejects_missing_headers_and_tampered_body() {
    let now = 1_700_000_000;
    let missing = SignedHeaders {
        signature: None,
        ..SignedHeaders::new("1700000000", "req-123", NODE_HMAC)
    };
    assert!(
        !verifier::verify_request_at(
            SigningScheme::Hmac,
            "test-secret",
            &missing,
            NODE_BODY,
            now,
            DEFAULT_TOLERANCE
        )
        .unwrap()
    );

    let headers = SignedHeaders::new("1700000000", "req-123", NODE_ED25519);
    assert!(
        verifier::verify_request_at(
            SigningScheme::Ed25519,
            PUBLIC_KEY_PEM,
            &headers,
            NODE_BODY,
            now,
            DEFAULT_TOLERANCE
        )
        .unwrap()
    );
    let tampered_body = NODE_BODY.replace("USER_1", "USER_2");
    assert!(
        !verifier::verify_request_at(
            SigningScheme::Ed25519,
            PUBLIC_KEY_PEM,
            &headers,
            tampered_body,
            now,
            DEFAULT_TOLERANCE
        )
        .unwrap()
    );
}

// ---------------------------------------------------------------------------------------------
// HTTP — against a tiny local server
// ---------------------------------------------------------------------------------------------

struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// Accepts one connection, records the request and answers `201` with the API envelope.
fn spawn_server() -> (String, mpsc::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();

        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
            }
        }

        let length = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();

        let mut stream = stream;
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ENVELOPE}",
            ENVELOPE.len()
        )
        .unwrap();
        stream.flush().unwrap();

        tx.send(CapturedRequest {
            method,
            path,
            headers,
            body: String::from_utf8(body).unwrap(),
        })
        .unwrap();
    });

    (base_url, rx)
}

async fn assert_handoff_roundtrip(scheme: SigningScheme, secret: &str, verify_key: &str) {
    let (base_url, rx) = spawn_server();

    let response = PartnerClient::new()
        .handoff(
            HandoffOptions::new(
                format!("{base_url}/"),
                scheme,
                secret,
                "acme",
                "USER_1",
                "+8801712345678",
            )
            .name("রেজা"),
        )
        .await
        .unwrap();

    let request = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/v1/partner/auth/handoff");
    assert_eq!(request.body, NODE_BODY);
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.header("x-partner-id"), Some("acme"));

    let headers = SignedHeaders {
        timestamp: request.header("x-timestamp"),
        request_id: request.header("x-request-id"),
        signature: request.header("x-signature"),
    };
    assert!(verifier::verify_request(scheme, verify_key, &headers, &request.body).unwrap());

    assert_eq!(response.status, 201);
    assert!(response.ok);
    assert_eq!(response.raw_body, ENVELOPE);
    assert_eq!(
        response.headers.get("content-type").unwrap(),
        "application/json; charset=utf-8"
    );

    let result: HandoffResult = response.data_as().unwrap();
    assert_eq!(result.handoff_code, "CODE");
    assert_eq!(result.expires_in, 60);
    assert_eq!(result.entry_url, "https://app.test/entry?code=CODE");
    assert!(!result.has_active_subscription);
    assert!(result.pending_merge.is_none());
}

#[tokio::test]
async fn handoff_hmac_sends_node_identical_body_and_verifiable_headers() {
    assert_handoff_roundtrip(SigningScheme::Hmac, "test-secret", "test-secret").await;
}

#[tokio::test]
async fn handoff_ed25519_sends_node_identical_body_and_verifiable_headers() {
    assert_handoff_roundtrip(SigningScheme::Ed25519, PRIVATE_KEY_PEM, PUBLIC_KEY_PEM).await;
}

#[tokio::test]
async fn signed_request_without_partner_id_omits_header() {
    let (base_url, rx) = spawn_server();

    let options = SignedRequestOptions::new(&base_url, "deduct", SigningScheme::Hmac, "s")
        .request_id("fixed-id")
        .json(&json!({ "partnerUserId": "U", "amount": "100.00" }))
        .unwrap();
    let response = PartnerClient::new().signed_request(options).await.unwrap();

    let request = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(request.path, "/deduct");
    assert_eq!(request.header("x-partner-id"), None);
    assert_eq!(request.header("x-request-id"), Some("fixed-id"));
    assert_eq!(request.body, r#"{"partnerUserId":"U","amount":"100.00"}"#);
    assert_eq!(response.status, 201);
}

#[tokio::test]
async fn handoff_requires_partner_fields() {
    let options = HandoffOptions::new(
        "http://127.0.0.1:9",
        SigningScheme::Hmac,
        "s",
        "",
        "U",
        "+880",
    );
    let error = PartnerClient::new().handoff(options).await.unwrap_err();
    assert!(error.to_string().contains("partner_id"));
}
