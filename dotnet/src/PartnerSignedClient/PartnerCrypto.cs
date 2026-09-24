using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;

namespace DanumAi.PartnerSignedClient;

/// <summary>
/// Signing primitives — a byte-for-byte port of the Node package's <c>src/crypto.js</c>, which in
/// turn must match the backend's PartnerCryptoService. Not an independent protocol, a compatible
/// client for the same one.
/// </summary>
public static class PartnerCrypto
{
    /// <summary>Prefix on every signature header value (<c>v1=...</c>).</summary>
    public const string SignatureVersion = "v1";

    /// <summary>
    /// Binds timestamp, request id and body together so tampering with any one invalidates the
    /// signature: <c>{timestamp}.{requestId}.{hex(sha256(rawBody))}</c>.
    /// </summary>
    /// <param name="rawBody">The EXACT body string sent on the wire (empty string for no body).</param>
    public static string BuildSigningString(string timestamp, string requestId, string? rawBody)
    {
        var bodyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawBody ?? string.Empty)))
            .ToLowerInvariant();

        return $"{timestamp}.{requestId}.{bodyHash}";
    }

    /// <param name="secret">Raw HMAC secret (not the encrypted-at-rest form).</param>
    public static string SignHmac(string signingString, string secret)
    {
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(signingString));
        return $"{SignatureVersion}={Convert.ToHexString(mac).ToLowerInvariant()}";
    }

    /// <param name="privateKeyPem">Ed25519 private key, PKCS#8 PEM (<c>-----BEGIN PRIVATE KEY-----</c>).</param>
    public static string SignEd25519(string signingString, string privateKeyPem)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, ReadEd25519PrivateKey(privateKeyPem));

        var message = Encoding.UTF8.GetBytes(signingString);
        signer.BlockUpdate(message, 0, message.Length);

        return $"{SignatureVersion}={Convert.ToBase64String(signer.GenerateSignature())}";
    }

    /// <summary>
    /// Scheme-agnostic entry point — the "works for both HMAC and Ed25519" piece. Returns the
    /// already-prefixed (<c>v1=...</c>) signature header value.
    /// </summary>
    /// <param name="secret">HMAC secret, or Ed25519 private key PEM.</param>
    public static string Sign(SigningScheme scheme, string signingString, string secret) => scheme switch
    {
        SigningScheme.Hmac => SignHmac(signingString, secret),
        SigningScheme.Ed25519 => SignEd25519(signingString, secret),
        _ => throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "Expected Hmac or Ed25519"),
    };

    /// <summary>
    /// Verifies an <c>X-Signature</c> header value — the piece you need inside your own
    /// <c>/deduct</c> endpoint. Does NOT check the timestamp window; see <see cref="PartnerSignatureVerifier"/>.
    /// </summary>
    /// <param name="key">HMAC secret, or Ed25519 PUBLIC key PEM (<c>-----BEGIN PUBLIC KEY-----</c>).</param>
    public static bool Verify(SigningScheme scheme, string signingString, string signatureHeader, string key)
    {
        var prefix = $"{SignatureVersion}=";
        if (string.IsNullOrEmpty(signatureHeader) || !signatureHeader.StartsWith(prefix, StringComparison.Ordinal))
            return false;

        switch (scheme)
        {
            case SigningScheme.Hmac:
                return CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(signatureHeader),
                    Encoding.ASCII.GetBytes(SignHmac(signingString, key)));

            case SigningScheme.Ed25519:
                byte[] signature;
                try { signature = Convert.FromBase64String(signatureHeader[prefix.Length..]); }
                catch (FormatException) { return false; }

                var verifier = new Ed25519Signer();
                verifier.Init(false, ReadEd25519PublicKey(key));
                var message = Encoding.UTF8.GetBytes(signingString);
                verifier.BlockUpdate(message, 0, message.Length);
                return verifier.VerifySignature(signature);

            default:
                throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "Expected Hmac or Ed25519");
        }
    }

    private static Ed25519PrivateKeyParameters ReadEd25519PrivateKey(string pem) => ReadPem(pem) switch
    {
        Ed25519PrivateKeyParameters key => key,
        AsymmetricCipherKeyPair { Private: Ed25519PrivateKeyParameters key } => key,
        _ => throw new ArgumentException("Expected an Ed25519 private key in PKCS#8 PEM format", nameof(pem)),
    };

    private static Ed25519PublicKeyParameters ReadEd25519PublicKey(string pem) => ReadPem(pem) switch
    {
        Ed25519PublicKeyParameters key => key,
        _ => throw new ArgumentException("Expected an Ed25519 public key in SPKI PEM format", nameof(pem)),
    };

    private static object? ReadPem(string pem)
    {
        using var reader = new StringReader(pem);
        return new PemReader(reader).ReadObject();
    }
}
