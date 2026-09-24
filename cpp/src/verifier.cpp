#include "danumai/partner/verifier.hpp"

#include <charconv>
#include <chrono>

namespace danumai::partner {

bool verify_signed_request(SigningScheme scheme, std::string_view key, std::string_view timestamp,
                           std::string_view request_id, std::string_view signature,
                           std::string_view raw_body, std::optional<std::int64_t> now_unix,
                           std::chrono::seconds tolerance) {
    if (timestamp.empty() || request_id.empty() || signature.empty()) return false;

    std::int64_t sent_at = 0;
    const char* end = timestamp.data() + timestamp.size();
    const auto [ptr, ec] = std::from_chars(timestamp.data(), end, sent_at);
    if (ec != std::errc() || ptr != end) return false;

    const std::int64_t now =
        now_unix ? *now_unix
                 : std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    // Unsigned difference: can't overflow even for absurd timestamps.
    const std::uint64_t skew = now >= sent_at
                                   ? static_cast<std::uint64_t>(now) - static_cast<std::uint64_t>(sent_at)
                                   : static_cast<std::uint64_t>(sent_at) - static_cast<std::uint64_t>(now);
    if (tolerance.count() < 0 || skew > static_cast<std::uint64_t>(tolerance.count())) return false;

    return verify(scheme, build_signing_string(timestamp, request_id, raw_body), signature, key);
}

}  // namespace danumai::partner
