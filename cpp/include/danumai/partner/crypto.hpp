// Signing primitives — a byte-for-byte port of the Node package's src/crypto.js, which in turn must
// match the backend's PartnerCryptoService. Not an independent protocol, a compatible client for
// the same one.
#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

namespace danumai::partner {

/// Prefix on every signature header value ("v1=...").
inline constexpr std::string_view kSignatureVersion = "v1";

enum class SigningScheme { Hmac, Ed25519 };

/// Thrown when OpenSSL fails, or a key can't be read (bad PEM, wrong key type).
class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Parses "hmac" / "ed25519" (case-insensitive). Throws std::invalid_argument otherwise.
SigningScheme parse_scheme(std::string_view name);

/// "hmac" / "ed25519".
std::string_view to_string(SigningScheme scheme);

/// Binds timestamp, request id and body together so tampering with any one invalidates the
/// signature: "{timestamp}.{requestId}.{hex(sha256(rawBody))}".
///
/// @param raw_body the EXACT body bytes sent on the wire (empty for no body).
std::string build_signing_string(std::string_view timestamp, std::string_view request_id,
                                 std::string_view raw_body);

/// "v1=" + lowercase hex(HMAC-SHA256(signing_string, secret)).
/// @param secret raw HMAC secret (not the encrypted-at-rest form).
std::string sign_hmac(std::string_view signing_string, std::string_view secret);

/// "v1=" + base64(Ed25519 signature over signing_string).
/// @param private_key_pem Ed25519 private key, PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----").
std::string sign_ed25519(std::string_view signing_string, std::string_view private_key_pem);

/// Scheme-agnostic entry point — returns the already-prefixed ("v1=...") X-Signature value.
/// @param secret HMAC secret, or Ed25519 private key PEM.
std::string sign(SigningScheme scheme, std::string_view signing_string, std::string_view secret);

/// Verifies an X-Signature header value — the piece you need inside your own /deduct endpoint.
/// Does NOT check the timestamp window; see verify_signed_request() in verifier.hpp.
///
/// HMAC is compared in constant time. Returns false for a wrong/malformed signature; throws
/// CryptoError if the key itself can't be used.
///
/// @param key HMAC secret, or Ed25519 PUBLIC key PEM ("-----BEGIN PUBLIC KEY-----").
bool verify(SigningScheme scheme, std::string_view signing_string,
            std::string_view signature_header, std::string_view key);

/// Random UUID v4 (lowercase, 8-4-4-4-12) from OpenSSL's CSPRNG — the default X-Request-Id.
std::string generate_request_id();

}  // namespace danumai::partner
