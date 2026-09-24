// The universal signed-request client — works for both HMAC and Ed25519, calls the target URL and
// returns the response. Compatible with BOTH directions of BanglaReels' partner protocol:
//
//  - Calling INTO BanglaReels (any endpoint under PartnerSignatureGuard): set `partner_id` so
//    X-Partner-Id is sent.
//  - Simulating what BanglaReels sends OUT to a partner's own /deduct endpoint: leave `partner_id`
//    unset — that direction never sends it.
//
// Request building (build_signed_request / build_handoff_request) is separate from the HTTP
// transport, so it can be tested or reused with your own HTTP stack.
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>

#include "danumai/partner/models.hpp"

namespace danumai::partner {

/// Thrown when the HTTP call itself fails (DNS, TLS, timeout...) — not for non-2xx statuses.
class TransportError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Pluggable HTTP layer. CurlTransport is the default; tests use a fake.
class HttpTransport {
public:
    virtual ~HttpTransport() = default;
    virtual HttpResponse send(const PreparedRequest& request) = 0;
};

/// libcurl-based transport. Does not follow redirects. Thread-safe to share: each send() uses its
/// own easy handle.
class CurlTransport : public HttpTransport {
public:
    explicit CurlTransport(std::chrono::milliseconds timeout = std::chrono::seconds(30));
    HttpResponse send(const PreparedRequest& request) override;

private:
    std::chrono::milliseconds timeout_;
};

/// Builds and signs a request at `timestamp_unix` (Unix seconds) without sending it.
/// The body is serialized once; those exact bytes are hashed, signed and returned in `body`.
PreparedRequest build_signed_request(const SignedRequestOptions& options,
                                     std::int64_t timestamp_unix);

/// Same, using the current system time.
PreparedRequest build_signed_request(const SignedRequestOptions& options);

/// Validates handoff options and maps them to the generic request for
/// POST {base_url}{api_prefix}/partner/auth/handoff.
SignedRequestOptions build_handoff_request(const HandoffOptions& options);

class PartnerClient {
public:
    /// @param transport optional — a CurlTransport is created when null.
    explicit PartnerClient(std::shared_ptr<HttpTransport> transport = nullptr);

    /// Signs and sends a request to any partner-signed endpoint.
    SignedResponse signed_request(const SignedRequestOptions& options) const;

    /// The actual flow: sign + call POST {api_prefix}/partner/auth/handoff. Read the result with
    /// `response.data_as<HandoffResult>()` — the API wraps it in an envelope.
    SignedResponse handoff(const HandoffOptions& options) const;

private:
    std::shared_ptr<HttpTransport> transport_;
};

}  // namespace danumai::partner
