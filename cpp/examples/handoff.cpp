// C++ equivalent of examples/test-handoff-hmac.js and examples/test-handoff-ed25519.js.
// Reads the same repo-root .env as the Node examples (walks up from the working directory).
//
//   ./build/handoff_example hmac
//   ./build/handoff_example ed25519

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "danumai/partner_signed_client.hpp"

namespace fs = std::filesystem;
using namespace danumai::partner;

namespace {

std::string trim(const std::string& s) {
    const auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    const auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

/// Minimal .env loader — walks up from the working directory to the first .env; real env vars win.
void load_env() {
    for (fs::path dir = fs::current_path();; dir = dir.parent_path()) {
        const fs::path file = dir / ".env";
        if (fs::is_regular_file(file)) {
            std::ifstream in(file);
            for (std::string line; std::getline(in, line);) {
                line = trim(line);
                const auto eq = line.find('=');
                if (line.empty() || line[0] == '#' || eq == std::string::npos || eq == 0) continue;
                const std::string key = trim(line.substr(0, eq));
                if (std::getenv(key.c_str()) != nullptr) continue;  // real env vars win
                const std::string value = trim(line.substr(eq + 1));
#ifdef _WIN32
                ::_putenv_s(key.c_str(), value.c_str());
#else
                ::setenv(key.c_str(), value.c_str(), /*overwrite=*/0);
#endif
            }
            return;
        }
        if (dir == dir.root_path() || dir.parent_path() == dir) return;
    }
}

std::string env(const std::string& name) {
    const char* value = std::getenv(name.c_str());
    if (value == nullptr || *value == '\0') {
        throw std::runtime_error("Missing env var " + name +
                                 " - copy .env.example to .env and fill it in");
    }
    return value;
}

std::string replace_all(std::string s, const std::string& from, const std::string& to) {
    for (std::size_t pos = 0; (pos = s.find(from, pos)) != std::string::npos; pos += to.size()) {
        s.replace(pos, from.size(), to);
    }
    return s;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        load_env();

        const SigningScheme scheme = parse_scheme(argc > 1 ? argv[1] : "hmac");
        const std::string prefix = scheme == SigningScheme::Hmac ? "HMAC" : "ED25519";

        HandoffOptions options;
        options.base_url = env("API_BASE_URL");
        options.scheme = scheme;
        options.secret = scheme == SigningScheme::Hmac
                             ? env("HMAC_SECRET")
                             // .env can only carry the PEM with real newlines escaped as literal "\n".
                             : replace_all(env("ED25519_PRIVATE_KEY_PEM"), "\\n", "\n");
        options.partner_id = env(prefix + "_PARTNER_SLUG");
        options.partner_user_id = env(prefix + "_TEST_PARTNER_USER_ID");
        options.phone_number = env(prefix + "_TEST_PHONE_NUMBER");

        const SignedResponse response = PartnerClient().handoff(options);

        std::cout << "status: " << response.status << "\n";
        if (response.ok) {
            if (auto result = response.data_as<HandoffResult>()) {
                std::cout << "entryUrl: " << result->entry_url << " (expires in "
                          << result->expires_in << "s)\n";
            }
        }
        std::cout << "body: " << (response.json ? response.json->dump(2) : response.raw_body) << "\n";
        return response.ok ? EXIT_SUCCESS : EXIT_FAILURE;
    } catch (const std::exception& error) {
        std::cerr << "Request failed: " << error.what() << "\n";
        return EXIT_FAILURE;
    }
}
