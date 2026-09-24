#include "danumai/partner/crypto.hpp"

#include <array>
#include <cctype>
#include <climits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

namespace danumai::partner {
namespace {

// ---- RAII wrappers for OpenSSL objects -------------------------------------------------------

template <typename T, void (*Free)(T*)>
struct OsslDeleter {
    void operator()(T* p) const noexcept { Free(p); }
};

void bio_free(BIO* bio) { BIO_free(bio); }

using BioPtr = std::unique_ptr<BIO, OsslDeleter<BIO, bio_free>>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, OsslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, OsslDeleter<EVP_MD_CTX, EVP_MD_CTX_free>>;
using MacPtr = std::unique_ptr<EVP_MAC, OsslDeleter<EVP_MAC, EVP_MAC_free>>;
using MacCtxPtr = std::unique_ptr<EVP_MAC_CTX, OsslDeleter<EVP_MAC_CTX, EVP_MAC_CTX_free>>;

// ---- helpers ---------------------------------------------------------------------------------

/// Throws CryptoError with the most recent OpenSSL error appended, and clears the error queue.
[[noreturn]] void throw_openssl(const std::string& what) {
    std::string message = what;
    if (unsigned long code = ERR_get_error(); code != 0) {
        std::array<char, 256> buf{};
        ERR_error_string_n(code, buf.data(), buf.size());
        message += ": ";
        message += buf.data();
    }
    ERR_clear_error();
    throw CryptoError(message);
}

const unsigned char* bytes(std::string_view s) {
    return reinterpret_cast<const unsigned char*>(s.data());
}

int checked_int(std::size_t size, const char* what) {
    if (size > static_cast<std::size_t>(INT_MAX)) throw CryptoError(std::string(what) + " is too large");
    return static_cast<int>(size);
}

std::string to_hex(const unsigned char* data, std::size_t len) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0f]);
    }
    return out;
}

std::string base64_encode(const unsigned char* data, std::size_t len) {
    std::string out(4 * ((len + 2) / 3), '\0');
    const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data,
                                        checked_int(len, "base64 input"));
    out.resize(static_cast<std::size_t>(written));
    return out;
}

/// Strict standard base64 (with padding). Returns false on malformed input.
bool base64_decode(std::string_view in, std::vector<unsigned char>& out) {
    if (in.empty() || in.size() % 4 != 0) return false;
    out.assign(in.size() / 4 * 3, 0);
    const int n = EVP_DecodeBlock(out.data(), bytes(in), static_cast<int>(in.size()));
    if (n < 0) return false;
    // EVP_DecodeBlock counts padding as zero bytes — drop them.
    std::size_t padding = 0;
    if (in.back() == '=') ++padding;
    if (in.size() >= 2 && in[in.size() - 2] == '=') ++padding;
    out.resize(static_cast<std::size_t>(n) - padding);
    return true;
}

BioPtr memory_bio(std::string_view pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), checked_int(pem.size(), "PEM")));
    if (!bio) throw_openssl("BIO_new_mem_buf failed");
    return bio;
}

void require_ed25519(const EVP_PKEY* key, const char* what) {
    if (EVP_PKEY_get_id(key) != EVP_PKEY_ED25519) {
        throw CryptoError(std::string("Expected an Ed25519 ") + what + ", got a different key type");
    }
}

PkeyPtr read_ed25519_private_key(std::string_view pem) {
    BioPtr bio = memory_bio(pem);
    PkeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if (!key) throw_openssl("Expected an Ed25519 private key in PKCS#8 PEM format");
    require_ed25519(key.get(), "private key");
    return key;
}

PkeyPtr read_ed25519_public_key(std::string_view pem) {
    BioPtr bio = memory_bio(pem);
    PkeyPtr key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
    if (!key) throw_openssl("Expected an Ed25519 public key in SPKI PEM format");
    require_ed25519(key.get(), "public key");
    return key;
}

std::string prefixed(std::string value) {
    std::string out(kSignatureVersion);
    out += '=';
    out += value;
    return out;
}

}  // namespace

SigningScheme parse_scheme(std::string_view name) {
    std::string lower;
    for (char c : name) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lower == "hmac") return SigningScheme::Hmac;
    if (lower == "ed25519") return SigningScheme::Ed25519;
    throw std::invalid_argument("Unsupported signing scheme \"" + std::string(name) +
                                "\" - expected \"hmac\" or \"ed25519\"");
}

std::string_view to_string(SigningScheme scheme) {
    switch (scheme) {
        case SigningScheme::Hmac: return "hmac";
        case SigningScheme::Ed25519: return "ed25519";
    }
    throw std::invalid_argument("Unknown SigningScheme value");
}

std::string build_signing_string(std::string_view timestamp, std::string_view request_id,
                                 std::string_view raw_body) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    if (EVP_Digest(raw_body.data(), raw_body.size(), digest.data(), &digest_len, EVP_sha256(),
                   nullptr) != 1) {
        throw_openssl("SHA-256 failed");
    }

    std::string out;
    out.reserve(timestamp.size() + request_id.size() + 2 + digest_len * 2);
    out.append(timestamp).append(".").append(request_id).append(".");
    out += to_hex(digest.data(), digest_len);
    return out;
}

std::string sign_hmac(std::string_view signing_string, std::string_view secret) {
    MacPtr mac(EVP_MAC_fetch(nullptr, OSSL_MAC_NAME_HMAC, nullptr));
    if (!mac) throw_openssl("EVP_MAC_fetch(HMAC) failed");
    MacCtxPtr ctx(EVP_MAC_CTX_new(mac.get()));
    if (!ctx) throw_openssl("EVP_MAC_CTX_new failed");

    char digest_name[] = "SHA256";
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_end(),
    };
    // A NULL key means "keep the previous key" to OpenSSL, so an empty secret still needs a
    // non-null pointer (HMAC with an empty key is well-defined, and what Node computes).
    static const unsigned char kEmpty = 0;
    const unsigned char* key = secret.empty() ? &kEmpty : bytes(secret);
    if (EVP_MAC_init(ctx.get(), key, secret.size(), params) != 1) throw_openssl("HMAC init failed");
    if (EVP_MAC_update(ctx.get(), bytes(signing_string), signing_string.size()) != 1) {
        throw_openssl("HMAC update failed");
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> out{};
    std::size_t out_len = 0;
    if (EVP_MAC_final(ctx.get(), out.data(), &out_len, out.size()) != 1) {
        throw_openssl("HMAC final failed");
    }
    return prefixed(to_hex(out.data(), out_len));
}

std::string sign_ed25519(std::string_view signing_string, std::string_view private_key_pem) {
    PkeyPtr key = read_ed25519_private_key(private_key_pem);

    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) throw_openssl("EVP_MD_CTX_new failed");
    // Ed25519 is a one-shot scheme: no digest (NULL md), EVP_DigestSign rather than Update/Final.
    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
        throw_openssl("Ed25519 sign init failed");
    }

    std::size_t sig_len = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &sig_len, bytes(signing_string), signing_string.size()) != 1) {
        throw_openssl("Ed25519 sign (size query) failed");
    }
    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSign(ctx.get(), sig.data(), &sig_len, bytes(signing_string), signing_string.size()) != 1) {
        throw_openssl("Ed25519 sign failed");
    }
    return prefixed(base64_encode(sig.data(), sig_len));
}

std::string sign(SigningScheme scheme, std::string_view signing_string, std::string_view secret) {
    switch (scheme) {
        case SigningScheme::Hmac: return sign_hmac(signing_string, secret);
        case SigningScheme::Ed25519: return sign_ed25519(signing_string, secret);
    }
    throw std::invalid_argument("Unknown SigningScheme value");
}

bool verify(SigningScheme scheme, std::string_view signing_string,
            std::string_view signature_header, std::string_view key) {
    const std::string prefix = std::string(kSignatureVersion) + "=";
    if (signature_header.size() <= prefix.size() ||
        signature_header.substr(0, prefix.size()) != prefix) {
        return false;
    }

    switch (scheme) {
        case SigningScheme::Hmac: {
            const std::string expected = sign_hmac(signing_string, key);
            return expected.size() == signature_header.size() &&
                   CRYPTO_memcmp(expected.data(), signature_header.data(), expected.size()) == 0;
        }
        case SigningScheme::Ed25519: {
            std::vector<unsigned char> sig;
            if (!base64_decode(signature_header.substr(prefix.size()), sig) || sig.size() != 64) {
                return false;
            }
            PkeyPtr public_key = read_ed25519_public_key(key);

            MdCtxPtr ctx(EVP_MD_CTX_new());
            if (!ctx) throw_openssl("EVP_MD_CTX_new failed");
            if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, public_key.get()) != 1) {
                throw_openssl("Ed25519 verify init failed");
            }
            const int rc = EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), bytes(signing_string),
                                            signing_string.size());
            ERR_clear_error();  // a bad signature leaves an error on the queue; it's not an error here
            return rc == 1;
        }
    }
    throw std::invalid_argument("Unknown SigningScheme value");
}

std::string generate_request_id() {
    std::array<unsigned char, 16> b{};
    if (RAND_bytes(b.data(), static_cast<int>(b.size())) != 1) throw_openssl("RAND_bytes failed");
    b[6] = static_cast<unsigned char>((b[6] & 0x0f) | 0x40);  // version 4
    b[8] = static_cast<unsigned char>((b[8] & 0x3f) | 0x80);  // RFC 4122 variant

    const std::string hex = to_hex(b.data(), b.size());
    return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" +
           hex.substr(16, 4) + "-" + hex.substr(20, 12);
}

}  // namespace danumai::partner
