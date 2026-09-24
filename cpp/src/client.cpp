#include "danumai/partner/client.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <string>
#include <utility>

namespace danumai::partner {
namespace {

bool iequals(std::string_view a, std::string_view b) {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) ==
                      std::tolower(static_cast<unsigned char>(y));
           });
}

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

void require(bool condition, const char* message) {
    if (!condition) throw std::invalid_argument(message);
}

/// Sets `name`, replacing an existing header of the same name (case-insensitive).
void set_header(HeaderList& headers, std::string name, std::string value) {
    auto it = std::find_if(headers.begin(), headers.end(),
                           [&](const auto& h) { return iequals(h.first, name); });
    if (it != headers.end()) {
        it->first = std::move(name);
        it->second = std::move(value);
    } else {
        headers.emplace_back(std::move(name), std::move(value));
    }
}

std::string join_url(std::string_view base_url, std::string_view path) {
    // Same as Node: strip trailing "/" from the base, ensure one leading "/" on the path.
    while (!base_url.empty() && base_url.back() == '/') base_url.remove_suffix(1);
    std::string url(base_url);
    if (path.empty() || path.front() != '/') url += '/';
    url += path;
    return url;
}

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

// ---- models --------------------------------------------------------------------------------

Json HandoffRequest::to_json() const {
    // Json is insertion-ordered: this is the field order JSON.stringify emits in the Node client.
    Json j = Json::object();
    j["partnerUserId"] = partner_user_id;
    j["phoneNumber"] = phone_number;
    if (name) j["name"] = *name;
    if (email) j["email"] = *email;
    if (return_path) j["returnPath"] = *return_path;
    return j;
}

void from_json(const Json& j, HandoffResult& result) {
    j.at("handoffCode").get_to(result.handoff_code);
    j.at("expiresIn").get_to(result.expires_in);
    j.at("entryUrl").get_to(result.entry_url);
    j.at("hasActiveSubscription").get_to(result.has_active_subscription);
    if (auto it = j.find("pendingMerge"); it != j.end() && !it->is_null()) {
        result.pending_merge = *it;
    } else {
        result.pending_merge.reset();
    }
}

std::optional<std::string> PreparedRequest::header(std::string_view name) const {
    for (const auto& [key, value] : headers) {
        if (iequals(key, name)) return value;
    }
    return std::nullopt;
}

const Json* SignedResponse::data() const {
    if (!json) return nullptr;
    if (json->is_object()) {
        if (auto it = json->find("data"); it != json->end()) return &*it;
    }
    return &*json;
}

// ---- request building ----------------------------------------------------------------------

PreparedRequest build_signed_request(const SignedRequestOptions& options,
                                     std::int64_t timestamp_unix) {
    require(!options.base_url.empty(), "signed_request: \"base_url\" is required");
    require(!options.path.empty(), "signed_request: \"path\" is required");
    require(!options.secret.empty(), "signed_request: \"secret\" is required");

    PreparedRequest request;
    request.method = options.method.empty() ? "POST" : options.method;
    request.url = join_url(options.base_url, options.path);

    const std::string request_id = options.request_id ? *options.request_id : generate_request_id();
    const std::string timestamp = std::to_string(timestamp_unix);
    // Serialized ONCE and sent as these exact bytes — re-serializing after signing (e.g. with a
    // different key order) would produce a body whose hash no longer matches the signature.
    // dump() defaults: compact, ensure_ascii=false (raw UTF-8), same as JSON.stringify.
    request.body = options.body ? options.body->dump() : std::string();

    const std::string signing_string = build_signing_string(timestamp, request_id, request.body);

    request.headers = {
        {"Content-Type", "application/json"},
        {"X-Request-Id", request_id},
        {"X-Timestamp", timestamp},
        {"X-Signature", sign(options.scheme, signing_string, options.secret)},
    };
    if (options.partner_id && !options.partner_id->empty()) {
        request.headers.emplace_back("X-Partner-Id", *options.partner_id);
    }
    for (const auto& [name, value] : options.extra_headers) set_header(request.headers, name, value);

    return request;
}

PreparedRequest build_signed_request(const SignedRequestOptions& options) {
    return build_signed_request(options, now_unix());
}

SignedRequestOptions build_handoff_request(const HandoffOptions& options) {
    require(!options.partner_id.empty(), "handoff: \"partner_id\" (X-Partner-Id) is required for this call");
    require(!options.partner_user_id.empty(), "handoff: \"partner_user_id\" is required");
    require(!options.phone_number.empty(), "handoff: \"phone_number\" is required");

    SignedRequestOptions request;
    request.base_url = options.base_url;
    request.path = options.api_prefix + "/partner/auth/handoff";
    request.method = "POST";
    request.scheme = options.scheme;
    request.secret = options.secret;
    request.partner_id = options.partner_id;
    request.request_id = options.request_id;
    request.body = HandoffRequest{options.partner_user_id, options.phone_number, options.name,
                                  options.email, options.return_path}
                       .to_json();
    return request;
}

// ---- client --------------------------------------------------------------------------------

PartnerClient::PartnerClient(std::shared_ptr<HttpTransport> transport)
    : transport_(transport ? std::move(transport) : std::make_shared<CurlTransport>()) {}

SignedResponse PartnerClient::signed_request(const SignedRequestOptions& options) const {
    const PreparedRequest request = build_signed_request(options);
    HttpResponse http = transport_->send(request);

    SignedResponse response;
    response.status = http.status;
    response.ok = http.status >= 200 && http.status <= 299;
    response.headers = std::move(http.headers);
    response.raw_body = std::move(http.body);

    auto content_type = response.headers.find("content-type");
    if (content_type != response.headers.end() &&
        to_lower(content_type->second).find("json") != std::string::npos) {
        Json parsed = Json::parse(response.raw_body, nullptr, /*allow_exceptions=*/false);
        if (!parsed.is_discarded()) response.json = std::move(parsed);
    }
    return response;
}

SignedResponse PartnerClient::handoff(const HandoffOptions& options) const {
    return signed_request(build_handoff_request(options));
}

}  // namespace danumai::partner
