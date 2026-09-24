namespace DanumAi.PartnerSignedClient;

/// <summary>
/// Receiving-side check for a signed request — use it in your own <c>/deduct</c> endpoint to
/// validate what BanglaReels sends you. Mirrors what the backend's PartnerSignatureGuard does for
/// the into-BanglaReels direction: timestamp window, then signature over the exact raw body.
/// </summary>
public static class PartnerSignatureVerifier
{
    /// <summary>Allowed clock skew between sender and receiver (±300s).</summary>
    public static readonly TimeSpan DefaultTolerance = TimeSpan.FromSeconds(300);

    /// <param name="key">HMAC secret, or the sender's Ed25519 PUBLIC key PEM.</param>
    /// <param name="timestamp">The <c>X-Timestamp</c> header.</param>
    /// <param name="requestId">The <c>X-Request-Id</c> header.</param>
    /// <param name="signature">The <c>X-Signature</c> header.</param>
    /// <param name="rawBody">The request body EXACTLY as received — read it before any model binding.</param>
    public static bool Verify(
        SigningScheme scheme,
        string key,
        string? timestamp,
        string? requestId,
        string? signature,
        string rawBody,
        DateTimeOffset? now = null,
        TimeSpan? tolerance = null)
    {
        if (string.IsNullOrEmpty(timestamp) || string.IsNullOrEmpty(requestId) || string.IsNullOrEmpty(signature))
            return false;

        if (!long.TryParse(timestamp, out var unixSeconds))
            return false;

        var skew = Math.Abs((now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() - unixSeconds);
        if (skew > (tolerance ?? DefaultTolerance).TotalSeconds)
            return false;

        var signingString = PartnerCrypto.BuildSigningString(timestamp, requestId, rawBody);
        return PartnerCrypto.Verify(scheme, signingString, signature, key);
    }
}
