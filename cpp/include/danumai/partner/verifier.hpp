// Receiving-side check for a signed request — use it in your own /deduct endpoint to validate what
// BanglaReels sends you. Mirrors what the backend's PartnerSignatureGuard does for the
// into-BanglaReels direction: timestamp window first, then the signature over the exact raw body.
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>

#include "danumai/partner/crypto.hpp"

namespace danumai::partner {

/// Allowed clock skew between sender and receiver (±300s).
inline constexpr std::chrono::seconds kDefaultTolerance{300};

/// @param key HMAC secret, or the sender's Ed25519 PUBLIC key PEM.
/// @param timestamp the X-Timestamp header (Unix seconds).
/// @param request_id the X-Request-Id header.
/// @param signature the X-Signature header.
/// @param raw_body the request body EXACTLY as received — never a re-serialized copy.
/// @param now_unix override "now" (Unix seconds), e.g. in tests; defaults to the system clock.
/// @return false when a header is missing, the timestamp is outside the window, or the signature
///         doesn't match. Throws CryptoError only for an unusable key.
bool verify_signed_request(SigningScheme scheme, std::string_view key, std::string_view timestamp,
                           std::string_view request_id, std::string_view signature,
                           std::string_view raw_body,
                           std::optional<std::int64_t> now_unix = std::nullopt,
                           std::chrono::seconds tolerance = kDefaultTolerance);

}  // namespace danumai::partner
