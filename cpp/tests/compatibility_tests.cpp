// Expected values below were produced by the Node package (src/crypto.js) with the same inputs —
// these tests prove the C++ port is byte-for-byte compatible, not just self-consistent.
//
// Self-contained runner: no test framework dependency. Exit code is non-zero if anything fails.

#include <cstdlib>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <regex>
#include <string>
#include <vector>

#include "danumai/partner_signed_client.hpp"

using namespace danumai::partner;

// ---- tiny test harness ---------------------------------------------------------------------

namespace {

struct TestCase {
    const char* name;
    std::function<void()> body;
};

std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> body) {
        registry().push_back({name, std::move(body)});
    }
};

int g_failures = 0;

void report_failure(const char* file, int line, const std::string& message) {
    ++g_failures;
    std::cerr << "    " << file << ":" << line << ": " << message << "\n";
}

}  // namespace

#define TEST_CASE(fn)                                    \
    static void fn();                                    \
    static const Registrar registrar_##fn(#fn, fn);      \
    static void fn()

#define CHECK(expr) \
    do { if (!(expr)) report_failure(__FILE__, __LINE__, "CHECK(" #expr ") failed"); } while (0)

#define CHECK_EQ(actual, expected)                                                      \
    do {                                                                                \
        const auto& a_ = (actual);                                                      \
        const auto& e_ = (expected);                                                    \
        if (!(a_ == e_)) {                                                              \
            report_failure(__FILE__, __LINE__,                                          \
                           std::string("CHECK_EQ(" #actual ", " #expected ")\n      actual:   ") + \
                               std::string(a_) + "\n      expected: " + std::string(e_)); \
        }                                                                               \
    } while (0)

#define CHECK_THROWS(expr)                                                        \
    do {                                                                          \
        bool threw_ = false;                                                      \
        try { (void)(expr); } catch (const std::exception&) { threw_ = true; }    \
        if (!threw_) report_failure(__FILE__, __LINE__, "expected exception: " #expr); \
    } while (0)

// ---- Node-produced vectors -----------------------------------------------------------------

namespace {

const std::string kPrivateKeyPem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEICqluVmfy4RygW/w10w4mU2qd2RMl1m+VcGY+Ht/tenr\n"
    "-----END PRIVATE KEY-----\n";

const std::string kPublicKeyPem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAwUUCAZnYdD/YD/OKg74wzRbPfJtuA6nDknhqFnrxnz4=\n"
    "-----END PUBLIC KEY-----\n";

// "রেজা" spelled as explicit UTF-8 bytes so the test doesn't depend on the source/execution
// character set (or on C++20's char8_t u8 literals).
const std::string kName = "\xe0\xa6\xb0\xe0\xa7\x87\xe0\xa6\x9c\xe0\xa6\xbe";

const std::string kNodeBody =
    "{\"partnerUserId\":\"USER_1\",\"phoneNumber\":\"+8801712345678\",\"name\":\"" + kName + "\"}";
const std::string kNodeSigningString =
    "1700000000.req-123.afc0e72029cb181220d7ac92b6321c59ff563606d4fff55371d1eba4177bb1f9";
const std::string kNodeHmac = "v1=e5125595fc9ec8bc1c6dc3b0a7ec636b7cbd73fe532c1becd77469a3b571e032";
const std::string kNodeEd25519 =
    "v1=fw3pu56QonGoY/ID0IJNzZilLwqdKpHRA9HJXsekMQKtMcSMpbVK6E/63DQPmEHtz4jaFltGQAjtWaKh0G5AAg==";

const std::string kEnvelope =
    "{\"status\":true,\"statusCode\":200,\"message\":\"Request successful\",\"data\":"
    "{\"handoffCode\":\"CODE\",\"expiresIn\":60,\"entryUrl\":\"https://app.test/entry?code=CODE\","
    "\"hasActiveSubscription\":false}}";

/// Captures the prepared request instead of sending it; replies with a canned 201 envelope.
class FakeTransport : public HttpTransport {
public:
    PreparedRequest last;
    int calls = 0;

    HttpResponse send(const PreparedRequest& request) override {
        last = request;
        ++calls;
        HttpResponse response;
        response.status = 201;
        response.headers["content-type"] = "application/json; charset=utf-8";
        response.body = kEnvelope;
        return response;
    }
};

std::string header_or_empty(const PreparedRequest& r, const char* name) {
    return r.header(name).value_or("");
}

}  // namespace

// ---- crypto --------------------------------------------------------------------------------

TEST_CASE(signing_string_matches_node) {
    CHECK_EQ(build_signing_string("1700000000", "req-123", kNodeBody), kNodeSigningString);
}

TEST_CASE(signing_string_empty_body_hashes_empty_string) {
    CHECK_EQ(build_signing_string("1", "r", ""),
             std::string("1.r.e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

TEST_CASE(hmac_matches_node) {
    CHECK_EQ(sign_hmac(kNodeSigningString, "test-secret"), kNodeHmac);
    CHECK_EQ(sign(SigningScheme::Hmac, kNodeSigningString, "test-secret"), kNodeHmac);
}

TEST_CASE(ed25519_matches_node) {
    CHECK_EQ(sign_ed25519(kNodeSigningString, kPrivateKeyPem), kNodeEd25519);
    CHECK_EQ(sign(SigningScheme::Ed25519, kNodeSigningString, kPrivateKeyPem), kNodeEd25519);
}

TEST_CASE(verify_accepts_valid_rejects_tampered) {
    CHECK(verify(SigningScheme::Hmac, kNodeSigningString, kNodeHmac, "test-secret"));
    CHECK(verify(SigningScheme::Ed25519, kNodeSigningString, kNodeEd25519, kPublicKeyPem));

    std::string tampered = kNodeSigningString;
    tampered.replace(tampered.find("req-123"), 7, "req-124");
    CHECK(!verify(SigningScheme::Hmac, tampered, kNodeHmac, "test-secret"));
    CHECK(!verify(SigningScheme::Ed25519, tampered, kNodeEd25519, kPublicKeyPem));
    CHECK(!verify(SigningScheme::Hmac, kNodeSigningString, kNodeHmac, "wrong-secret"));
}

TEST_CASE(verify_rejects_wrong_key_and_malformed_signatures) {
    // A different, freshly generated Ed25519 public key.
    const std::string other_public_key =
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEA9h2DMPmeHUTcis5KISqG5//X0yIu2VK+qgqmPeMiJxY=\n"
        "-----END PUBLIC KEY-----\n";
    CHECK(!verify(SigningScheme::Ed25519, kNodeSigningString, kNodeEd25519, other_public_key));

    CHECK(!verify(SigningScheme::Hmac, kNodeSigningString, "", "test-secret"));
    CHECK(!verify(SigningScheme::Hmac, kNodeSigningString, kNodeHmac.substr(3), "test-secret"));
    CHECK(!verify(SigningScheme::Hmac, kNodeSigningString, "v2=" + kNodeHmac.substr(3), "test-secret"));
    CHECK(!verify(SigningScheme::Ed25519, kNodeSigningString, "v1=not*base64!", kPublicKeyPem));
    CHECK(!verify(SigningScheme::Ed25519, kNodeSigningString, "v1=AAAA", kPublicKeyPem));
}

TEST_CASE(bad_keys_throw) {
    CHECK_THROWS(sign_ed25519(kNodeSigningString, "not a pem"));
    CHECK_THROWS(sign_ed25519(kNodeSigningString, kPublicKeyPem));  // public key where private expected
    CHECK_THROWS(verify(SigningScheme::Ed25519, kNodeSigningString, kNodeEd25519, "not a pem"));
}

TEST_CASE(parse_scheme_accepts_known_names) {
    CHECK(parse_scheme("hmac") == SigningScheme::Hmac);
    CHECK(parse_scheme("Ed25519") == SigningScheme::Ed25519);
    CHECK_THROWS(parse_scheme("rsa"));
    CHECK_EQ(to_string(SigningScheme::Ed25519), std::string_view("ed25519"));
}

TEST_CASE(request_id_is_uuid_v4) {
    const std::regex uuid_v4("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    const std::string a = generate_request_id();
    const std::string b = generate_request_id();
    CHECK(std::regex_match(a, uuid_v4));
    CHECK(std::regex_match(b, uuid_v4));
    CHECK(a != b);
}

// ---- verifier ------------------------------------------------------------------------------

TEST_CASE(verifier_enforces_timestamp_window) {
    const std::int64_t sent_at = 1700000000;
    CHECK(verify_signed_request(SigningScheme::Hmac, "test-secret", "1700000000", "req-123", kNodeHmac,
                                kNodeBody, sent_at + 299));
    CHECK(verify_signed_request(SigningScheme::Hmac, "test-secret", "1700000000", "req-123", kNodeHmac,
                                kNodeBody, sent_at - 299));
    CHECK(!verify_signed_request(SigningScheme::Hmac, "test-secret", "1700000000", "req-123", kNodeHmac,
                                 kNodeBody, sent_at + 301));
    CHECK(!verify_signed_request(SigningScheme::Hmac, "test-secret", "1700000000", "req-123", kNodeHmac,
                                 kNodeBody, sent_at - 301));
    CHECK(verify_signed_request(SigningScheme::Ed25519, kPublicKeyPem, "1700000000", "req-123",
                                kNodeEd25519, kNodeBody, sent_at + 299));
}

TEST_CASE(verifier_rejects_missing_or_malformed_headers) {
    const std::int64_t now = 1700000000;
    CHECK(!verify_signed_request(SigningScheme::Hmac, "test-secret", "", "req-123", kNodeHmac, kNodeBody, now));
    CHECK(!verify_signed_request(SigningScheme::Hmac, "test-secret", "1700000000x", "req-123", kNodeHmac, kNodeBody, now));
    CHECK(!verify_signed_request(SigningScheme::Hmac, "test-secret", "1700000000", "", kNodeHmac, kNodeBody, now));
    CHECK(!verify_signed_request(SigningScheme::Hmac, "test-secret", "1700000000", "req-123", "", kNodeBody, now));
    // Re-serialized body (different key order) must not verify.
    const std::string reordered =
        "{\"phoneNumber\":\"+8801712345678\",\"partnerUserId\":\"USER_1\",\"name\":\"" + kName + "\"}";
    CHECK(!verify_signed_request(SigningScheme::Hmac, "test-secret", "1700000000", "req-123", kNodeHmac, reordered, now));
}

// ---- request building ----------------------------------------------------------------------

TEST_CASE(handoff_body_is_node_identical) {
    HandoffRequest body{"USER_1", "+8801712345678", kName, std::nullopt, std::nullopt};
    CHECK_EQ(body.to_json().dump(), kNodeBody);

    HandoffRequest full{"U", "+880", std::nullopt, std::string("a@b.c"), std::string("/x")};
    CHECK_EQ(full.to_json().dump(),
             std::string("{\"partnerUserId\":\"U\",\"phoneNumber\":\"+880\",\"email\":\"a@b.c\",\"returnPath\":\"/x\"}"));
}

TEST_CASE(prepared_request_is_signed_like_node) {
    HandoffOptions options;
    options.base_url = "https://example.test/";
    options.scheme = SigningScheme::Hmac;
    options.secret = "test-secret";
    options.partner_id = "acme";
    options.partner_user_id = "USER_1";
    options.phone_number = "+8801712345678";
    options.name = kName;
    options.request_id = "req-123";

    const PreparedRequest r = build_signed_request(build_handoff_request(options), 1700000000);
    CHECK_EQ(r.method, std::string("POST"));
    CHECK_EQ(r.url, std::string("https://example.test/api/v1/partner/auth/handoff"));
    CHECK_EQ(r.body, kNodeBody);
    CHECK_EQ(header_or_empty(r, "X-Timestamp"), std::string("1700000000"));
    CHECK_EQ(header_or_empty(r, "X-Request-Id"), std::string("req-123"));
    CHECK_EQ(header_or_empty(r, "X-Signature"), kNodeHmac);
    CHECK_EQ(header_or_empty(r, "X-Partner-Id"), std::string("acme"));
    CHECK_EQ(header_or_empty(r, "Content-Type"), std::string("application/json"));

    options.scheme = SigningScheme::Ed25519;
    options.secret = kPrivateKeyPem;
    const PreparedRequest e = build_signed_request(build_handoff_request(options), 1700000000);
    CHECK_EQ(header_or_empty(e, "X-Signature"), kNodeEd25519);
}

TEST_CASE(handoff_validates_required_fields) {
    HandoffOptions options;
    options.base_url = "https://example.test";
    options.secret = "s";
    options.partner_user_id = "U";
    options.phone_number = "+880";
    CHECK_THROWS(build_handoff_request(options));  // no partner_id
    options.partner_id = "acme";
    options.phone_number.clear();
    CHECK_THROWS(build_handoff_request(options));

    SignedRequestOptions raw;
    raw.base_url = "https://example.test";
    raw.path = "/x";
    CHECK_THROWS(build_signed_request(raw, 1));  // no secret
}

TEST_CASE(signed_request_without_partner_id_omits_header) {
    SignedRequestOptions options;
    options.base_url = "https://partner.test";
    options.path = "deduct";
    options.scheme = SigningScheme::Hmac;
    options.secret = "s";
    options.body = Json{{"partnerUserId", "U"}, {"amount", "100.00"}};

    const PreparedRequest r = build_signed_request(options, 1700000000);
    CHECK_EQ(r.url, std::string("https://partner.test/deduct"));
    CHECK(!r.header("X-Partner-Id").has_value());
    CHECK_EQ(r.body, std::string("{\"partnerUserId\":\"U\",\"amount\":\"100.00\"}"));
    CHECK(verify_signed_request(SigningScheme::Hmac, "s", header_or_empty(r, "X-Timestamp"),
                                header_or_empty(r, "X-Request-Id"), header_or_empty(r, "X-Signature"),
                                r.body, 1700000000));

    options.partner_id = "";  // empty counts as "not given", like Node's truthiness check
    CHECK(!build_signed_request(options, 1).header("X-Partner-Id").has_value());
}

TEST_CASE(no_body_signs_empty_string_and_extra_headers_override) {
    SignedRequestOptions options;
    options.base_url = "https://partner.test";
    options.path = "/ping";
    options.method = "GET";
    options.secret = "s";
    options.request_id = "r";
    options.extra_headers = {{"content-type", "text/plain"}, {"X-Trace", "1"}};

    const PreparedRequest r = build_signed_request(options, 1);
    CHECK_EQ(r.body, std::string());
    CHECK_EQ(header_or_empty(r, "X-Signature"), sign_hmac(build_signing_string("1", "r", ""), "s"));
    CHECK_EQ(header_or_empty(r, "Content-Type"), std::string("text/plain"));
    CHECK_EQ(header_or_empty(r, "X-Trace"), std::string("1"));
}

// ---- client + envelope ---------------------------------------------------------------------

TEST_CASE(handoff_end_to_end_with_fake_transport) {
    const struct { SigningScheme scheme; std::string secret, verify_key; } cases[] = {
        {SigningScheme::Hmac, "test-secret", "test-secret"},
        {SigningScheme::Ed25519, kPrivateKeyPem, kPublicKeyPem},
    };
    for (const auto& c : cases) {
        auto transport = std::make_shared<FakeTransport>();
        PartnerClient client(transport);

        HandoffOptions options;
        options.base_url = "https://example.test/";
        options.scheme = c.scheme;
        options.secret = c.secret;
        options.partner_id = "acme";
        options.partner_user_id = "USER_1";
        options.phone_number = "+8801712345678";
        options.name = kName;

        const SignedResponse response = client.handoff(options);
        const PreparedRequest& sent = transport->last;

        CHECK(transport->calls == 1);
        CHECK_EQ(sent.url, std::string("https://example.test/api/v1/partner/auth/handoff"));
        CHECK_EQ(sent.body, kNodeBody);
        CHECK_EQ(header_or_empty(sent, "X-Partner-Id"), std::string("acme"));
        CHECK(verify_signed_request(c.scheme, c.verify_key, header_or_empty(sent, "X-Timestamp"),
                                    header_or_empty(sent, "X-Request-Id"),
                                    header_or_empty(sent, "X-Signature"), sent.body));

        CHECK(response.status == 201);
        CHECK(response.ok);
        CHECK(response.json.has_value());
        const auto result = response.data_as<HandoffResult>();
        CHECK(result.has_value());
        if (result) {
            CHECK_EQ(result->handoff_code, std::string("CODE"));
            CHECK_EQ(result->entry_url, std::string("https://app.test/entry?code=CODE"));
            CHECK(result->expires_in == 60);
            CHECK(!result->has_active_subscription);
            CHECK(!result->pending_merge.has_value());
        }
    }
}

TEST_CASE(data_falls_back_to_root_without_envelope) {
    SignedResponse response;
    response.json = Json::parse(
        "{\"handoffCode\":\"C\",\"expiresIn\":5,\"entryUrl\":\"u\",\"hasActiveSubscription\":true,"
        "\"pendingMerge\":{\"x\":1}}");
    const auto result = response.data_as<HandoffResult>();
    CHECK(result.has_value());
    if (result) {
        CHECK_EQ(result->handoff_code, std::string("C"));
        CHECK(result->has_active_subscription);
        CHECK(result->pending_merge.has_value());
    }

    SignedResponse empty;
    CHECK(empty.data() == nullptr);
    CHECK(!empty.data_as<HandoffResult>().has_value());
}

// ---- runner --------------------------------------------------------------------------------

int main() {
    int failed_tests = 0;
    for (const auto& test : registry()) {
        const int before = g_failures;
        try {
            test.body();
        } catch (const std::exception& e) {
            report_failure(__FILE__, __LINE__, std::string("unexpected exception: ") + e.what());
        }
        const bool passed = g_failures == before;
        if (!passed) ++failed_tests;
        std::cout << (passed ? "[PASS] " : "[FAIL] ") << test.name << "\n";
    }
    std::cout << "\n" << (registry().size() - static_cast<std::size_t>(failed_tests)) << "/"
              << registry().size() << " tests passed\n";
    return failed_tests == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
