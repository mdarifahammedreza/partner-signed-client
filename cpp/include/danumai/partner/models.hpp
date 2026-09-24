// Options, request/response types for the signed-request client.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "danumai/partner/crypto.hpp"

namespace danumai::partner {

/// Insertion-ordered JSON. Plain nlohmann::json sorts object keys, which would change the bytes
/// (and so the body hash) compared with Node's JSON.stringify.
using Json = nlohmann::ordered_json;

using HeaderList = std::vector<std::pair<std::string, std::string>>;

/// Options for PartnerClient::signed_request().
struct SignedRequestOptions {
    /// e.g. "https://dev-api.banglareels.com" or a partner's own API base.
    std::string base_url;
    /// e.g. "/api/v1/partner/auth/merge-confirm" (a leading "/" is added if missing).
    std::string path;
    std::string method = "POST";
    /// Serialized compactly with dump() (key order preserved, non-ASCII left as raw UTF-8) —
    /// the same bytes JSON.stringify produces. std::nullopt for no body.
    std::optional<Json> body;
    SigningScheme scheme = SigningScheme::Hmac;
    /// HMAC secret, or Ed25519 private key PEM.
    std::string secret;
    /// X-Partner-Id — leave unset for the outbound (BanglaReels -> partner) direction.
    std::optional<std::string> partner_id;
    /// X-Request-Id — reuse the same value on any retry of the same attempt; a UUID v4 is
    /// generated when unset.
    std::optional<std::string> request_id;
    /// Added after the protocol headers; a header with the same name (case-insensitive) replaces it.
    HeaderList extra_headers;
};

/// Options for PartnerClient::handoff().
struct HandoffOptions {
    /// e.g. "https://dev-api.banglareels.com".
    std::string base_url;
    std::string api_prefix = "/api/v1";
    SigningScheme scheme = SigningScheme::Hmac;
    /// HMAC secret, or Ed25519 private key PEM.
    std::string secret;
    /// Your partner slug (X-Partner-Id).
    std::string partner_id;
    /// Your own user id; must match what you'll later send on payment callbacks.
    std::string partner_user_id;
    /// E.164 preferred.
    std::string phone_number;
    std::optional<std::string> name;
    std::optional<std::string> email;
    std::optional<std::string> return_path;
    std::optional<std::string> request_id;
};

/// Body of POST partner/auth/handoff — matches PartnerHandoffDto, same field order.
struct HandoffRequest {
    std::string partner_user_id;
    std::string phone_number;
    std::optional<std::string> name;
    std::optional<std::string> email;
    std::optional<std::string> return_path;

    /// {partnerUserId, phoneNumber, name?, email?, returnPath?} — unset fields are omitted,
    /// exactly like JSON.stringify drops `undefined`.
    Json to_json() const;
};

/// Successful handoff payload (HandoffResult), found inside the API envelope's `data`.
struct HandoffResult {
    std::string handoff_code;
    std::int64_t expires_in = 0;
    std::string entry_url;
    bool has_active_subscription = false;
    std::optional<Json> pending_merge;
};

/// nlohmann ADL hook, so `json.get<HandoffResult>()` / `response.data_as<HandoffResult>()` work.
void from_json(const Json& j, HandoffResult& result);

/// A fully built, signed request — everything the transport needs to put on the wire.
struct PreparedRequest {
    std::string method;
    std::string url;
    HeaderList headers;
    /// Exactly the bytes that were hashed and signed.
    std::string body;

    /// First header with this name (case-insensitive), if any.
    std::optional<std::string> header(std::string_view name) const;
};

/// What the transport hands back.
struct HttpResponse {
    long status = 0;
    /// Lower-cased names; repeated headers joined with ", ".
    std::map<std::string, std::string> headers;
    std::string body;
};

/// What every signed call returns.
struct SignedResponse {
    long status = 0;
    bool ok = false;
    /// Lower-cased names; repeated headers joined with ", ".
    std::map<std::string, std::string> headers;
    /// The response body as text, always populated.
    std::string raw_body;
    /// Parsed JSON when the response declares a JSON content-type and parses; otherwise unset.
    std::optional<Json> json;

    /// The payload inside BanglaReels' response envelope ({status, statusCode, message, data}),
    /// falling back to the root when there's no `data` member. nullptr when there's no JSON body.
    const Json* data() const;

    /// data() converted to T (e.g. HandoffResult); std::nullopt when there's no JSON body.
    /// Throws nlohmann::json::exception if the payload doesn't have T's shape.
    template <typename T>
    std::optional<T> data_as() const {
        const Json* payload = data();
        if (payload == nullptr) return std::nullopt;
        return payload->get<T>();
    }
};

}  // namespace danumai::partner
