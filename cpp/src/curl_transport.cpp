#include <cctype>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>

#include <curl/curl.h>

#include "danumai/partner/client.hpp"

namespace danumai::partner {
namespace {

struct CurlEasyDeleter {
    void operator()(CURL* handle) const noexcept { curl_easy_cleanup(handle); }
};
struct CurlSlistDeleter {
    void operator()(curl_slist* list) const noexcept { curl_slist_free_all(list); }
};
using CurlPtr = std::unique_ptr<CURL, CurlEasyDeleter>;
using SlistPtr = std::unique_ptr<curl_slist, CurlSlistDeleter>;

void global_init_once() {
    static std::once_flag flag;
    std::call_once(flag, [] {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            throw TransportError("curl_global_init failed");
        }
    });
}

std::size_t on_body(char* data, std::size_t size, std::size_t nmemb, void* user) {
    static_cast<std::string*>(user)->append(data, size * nmemb);
    return size * nmemb;
}

std::string trim(std::string s) {
    auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) s.pop_back();
    std::size_t start = 0;
    while (start < s.size() && is_space(static_cast<unsigned char>(s[start]))) ++start;
    return s.substr(start);
}

std::size_t on_header(char* data, std::size_t size, std::size_t nmemb, void* user) {
    auto* headers = static_cast<std::map<std::string, std::string>*>(user);
    const std::string line(data, size * nmemb);

    // A new status line (e.g. after "100 Continue") starts a fresh header block.
    if (line.rfind("HTTP/", 0) == 0) {
        headers->clear();
        return size * nmemb;
    }
    const auto colon = line.find(':');
    if (colon == std::string::npos) return size * nmemb;

    std::string name = line.substr(0, colon);
    for (char& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    std::string value = trim(line.substr(colon + 1));

    auto [it, inserted] = headers->emplace(std::move(name), value);
    if (!inserted) it->second += ", " + value;
    return size * nmemb;
}

void check(CURLcode code, const char* what) {
    if (code != CURLE_OK) {
        throw TransportError(std::string(what) + ": " + curl_easy_strerror(code));
    }
}

}  // namespace

CurlTransport::CurlTransport(std::chrono::milliseconds timeout) : timeout_(timeout) {
    global_init_once();
}

HttpResponse CurlTransport::send(const PreparedRequest& request) {
    CurlPtr curl(curl_easy_init());
    if (!curl) throw TransportError("curl_easy_init failed");
    CURL* h = curl.get();

    HttpResponse response;
    char error[CURL_ERROR_SIZE] = {0};

    SlistPtr headers;
    auto append_header = [&headers](const std::string& line) {
        curl_slist* next = curl_slist_append(headers.get(), line.c_str());
        if (next == nullptr) throw TransportError("curl_slist_append failed");
        headers.release();
        headers.reset(next);
    };
    for (const auto& [name, value] : request.headers) append_header(name + ": " + value);
    append_header("Expect:");  // never wait for "100 Continue"

    check(curl_easy_setopt(h, CURLOPT_URL, request.url.c_str()), "CURLOPT_URL");
    check(curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, request.method.c_str()), "CURLOPT_CUSTOMREQUEST");
    check(curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers.get()), "CURLOPT_HTTPHEADER");
    // Like fetch: a body-carrying method with no body still sends "Content-Length: 0".
    const bool body_method =
        request.method == "POST" || request.method == "PUT" || request.method == "PATCH";
    if (!request.body.empty() || body_method) {
        // Sent verbatim — these are the bytes that were signed.
        check(curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE,
                               static_cast<curl_off_t>(request.body.size())),
              "CURLOPT_POSTFIELDSIZE_LARGE");
        check(curl_easy_setopt(h, CURLOPT_POSTFIELDS, request.body.data()), "CURLOPT_POSTFIELDS");
    }
    check(curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_body), "CURLOPT_WRITEFUNCTION");
    check(curl_easy_setopt(h, CURLOPT_WRITEDATA, &response.body), "CURLOPT_WRITEDATA");
    check(curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, on_header), "CURLOPT_HEADERFUNCTION");
    check(curl_easy_setopt(h, CURLOPT_HEADERDATA, &response.headers), "CURLOPT_HEADERDATA");
    check(curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_.count())), "CURLOPT_TIMEOUT_MS");
    check(curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L), "CURLOPT_NOSIGNAL");
    check(curl_easy_setopt(h, CURLOPT_ERRORBUFFER, error), "CURLOPT_ERRORBUFFER");

    const CURLcode rc = curl_easy_perform(h);
    if (rc != CURLE_OK) {
        throw TransportError(std::string("HTTP request to ") + request.url + " failed: " +
                             (error[0] != '\0' ? error : curl_easy_strerror(rc)));
    }
    check(curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &response.status), "CURLINFO_RESPONSE_CODE");
    return response;
}

}  // namespace danumai::partner
