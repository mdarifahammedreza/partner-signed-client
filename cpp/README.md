# partner_signed_client (C++)

C++17 port of the Node package in the repo root: the same **HMAC** and **Ed25519** partner
signed-request protocol, byte-for-byte compatible. The tests check it against signatures produced
by the Node `src/crypto.js`.

Dependencies:

- **OpenSSL 3** (`libcrypto` only) — SHA-256, HMAC, Ed25519, CSPRNG.
- **libcurl** — the default HTTP transport.
- **[nlohmann/json](https://github.com/nlohmann/json)** (MIT, header-only) — used from the system
  if installed, otherwise downloaded by CMake `FetchContent` (pinned to v3.12.0 with a SHA-256).

```
cpp/
├── CMakeLists.txt
├── include/danumai/
│   ├── partner_signed_client.hpp   # umbrella header
│   └── partner/
│       ├── crypto.hpp              # build_signing_string, sign_hmac, sign_ed25519, sign, verify   (= src/crypto.js)
│       ├── client.hpp              # PartnerClient, build_signed_request, CurlTransport           (= src/client.js + src/handoff.js)
│       ├── verifier.hpp            # receiving-side check for your own /deduct endpoint
│       └── models.hpp              # options, HandoffRequest/HandoffResult, SignedResponse
├── src/
├── examples/handoff.cpp            # = examples/test-handoff-{hmac,ed25519}.js
└── tests/compatibility_tests.cpp   # self-contained, no test framework
```

## Build

Needs CMake 3.16+, a C++17 compiler and the dev packages (Debian/Ubuntu:
`sudo apt install cmake libssl-dev libcurl4-openssl-dev`; macOS: `brew install cmake openssl@3`).

```sh
cd cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure      # compatibility tests (offline)

# Uses the same repo-root .env as the Node examples (copy .env.example → .env).
# The .env is found by walking up from the working directory.
./build/handoff_example hmac
./build/handoff_example ed25519
```

To use it from your own CMake project:

```cmake
add_subdirectory(path/to/cpp)   # examples/tests are off when not the top-level project
target_link_libraries(your_app PRIVATE danumai::partner_signed_client)
```

## Handoff flow

```cpp
#include "danumai/partner_signed_client.hpp"
using namespace danumai::partner;

PartnerClient client;   // or PartnerClient(std::make_shared<YourTransport>())

HandoffOptions options;
options.base_url = "https://dev-api.banglareels.com";
options.scheme = SigningScheme::Hmac;            // or SigningScheme::Ed25519
options.secret = signing_secret;                 // HMAC secret, or Ed25519 private key PEM
options.partner_id = "your-partner-slug";        // sent as X-Partner-Id
options.partner_user_id = "YOUR_USER_889123";
options.phone_number = "+8801712345678";

SignedResponse response = client.handoff(options);

if (response.ok) {
    // The API wraps results as { status, statusCode, message, data } — data_as unwraps `data`.
    HandoffResult result = *response.data_as<HandoffResult>();
    // result.entry_url    → redirect the subscriber's browser here
    // result.handoff_code → single-use, ~60s TTL
}
```

For Ed25519, set `scheme = SigningScheme::Ed25519`. `secret` is then the PKCS#8 private key PEM
(`-----BEGIN PRIVATE KEY-----`). You can generate one with Node, or with
`openssl genpkey -algorithm ed25519`.

`handoff()` / `signed_request()` throw `std::invalid_argument` for missing options, `CryptoError`
for an unusable key and `TransportError` if the HTTP call itself fails. A non-2xx status is **not**
an exception — check `response.ok` / `response.status`.

## Any other signed endpoint

```cpp
SignedRequestOptions options;
options.base_url = "https://dev-api.banglareels.com";
options.path = "/api/v1/partner/auth/merge-confirm";
options.scheme = SigningScheme::Hmac;
options.secret = secret;
options.partner_id = "your-partner-slug";   // leave unset to simulate BanglaReels → your /deduct
options.body = Json{{"partnerUserId", "YOUR_USER_889123"}};

SignedResponse response = client.signed_request(options);
```

`Json` is `nlohmann::ordered_json`, which keeps keys in insertion order (plain `nlohmann::json`
sorts them). The body is serialized once with `dump()` — compact, no escaping of `+` or non-ASCII —
and those exact bytes are signed and sent, so the C++ client puts the same bytes on the wire as
`JSON.stringify` in the Node client. Keep amounts as strings (`"100.00"`), as in the Node examples;
floating-point numbers are not guaranteed to print the same as JavaScript. Strings must be valid
UTF-8 (`dump()` throws otherwise).

To build a signed request without sending it (e.g. to use your own HTTP library), call
`build_signed_request(options)`: it returns a `PreparedRequest` with the method, URL, headers and
the exact body bytes.

## Verifying BanglaReels' calls to your `/deduct`

Sign and verify against the **raw body bytes**. Read the body before parsing it, because a
re-serialized copy won't hash the same.

```cpp
#include "danumai/partner/verifier.hpp"

// Inside your HTTP server's handler (framework-specific header/body access):
bool valid = danumai::partner::verify_signed_request(
    SigningScheme::Hmac,
    outbound_signing_secret,             // HMAC secret, or Ed25519 PUBLIC key PEM
    req.header("X-Timestamp"),
    req.header("X-Request-Id"),
    req.header("X-Signature"),
    req.raw_body());                     // also enforces the ±300s timestamp window

if (!valid) return reply(401);

auto deduct = nlohmann::json::parse(req.raw_body());
// dedupe on X-Request-Id / idempotencyKey, then charge...
```

HMAC signatures are compared in constant time (`CRYPTO_memcmp`).

The protocol itself is described in the root [README](../README.md#how-the-signature-is-built).
