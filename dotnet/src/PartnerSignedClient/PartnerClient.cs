using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DanumAi.PartnerSignedClient;

/// <summary>
/// The universal signed-request client — works for both HMAC and Ed25519, calls the target URL,
/// and returns the response. Compatible with BOTH directions of BanglaReels' partner protocol:
/// <list type="bullet">
///   <item>Calling INTO BanglaReels (any endpoint under PartnerSignatureGuard): set
///   <see cref="SignedRequestOptions.PartnerId"/> so <c>X-Partner-Id</c> is sent.</item>
///   <item>Simulating what BanglaReels sends OUT to a partner's own <c>/deduct</c> endpoint: leave
///   <see cref="SignedRequestOptions.PartnerId"/> null — that direction never sends it.</item>
/// </list>
/// </summary>
public sealed class PartnerClient
{
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        // Matches JSON.stringify dropping `undefined` fields in the Node client.
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // JSON.stringify doesn't \u-escape '+' (phone numbers) or non-ASCII (Bangla names); match it
        // so both clients put the same bytes on the wire.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly HttpClient _http;

    /// <param name="httpClient">
    /// Optional — pass one from IHttpClientFactory in ASP.NET Core apps. A private instance is
    /// created otherwise.
    /// </param>
    public PartnerClient(HttpClient? httpClient = null)
    {
        _http = httpClient ?? new HttpClient();
    }

    /// <summary>Signs and sends a request to any partner-signed endpoint.</summary>
    public async Task<SignedResponse> SignedRequestAsync(SignedRequestOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(options.BaseUrl, nameof(options.BaseUrl));
        ArgumentException.ThrowIfNullOrEmpty(options.Path, nameof(options.Path));
        ArgumentException.ThrowIfNullOrEmpty(options.Secret, nameof(options.Secret));

        var requestId = options.RequestId ?? Guid.NewGuid().ToString();
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        // Signed and sent as the EXACT same string — re-serializing after signing (e.g. a different
        // key order) would produce a body whose hash no longer matches the signature.
        var rawBody = options.Body is null ? string.Empty : JsonSerializer.Serialize(options.Body, JsonOptions);

        var signingString = PartnerCrypto.BuildSigningString(timestamp, requestId, rawBody);
        var signature = PartnerCrypto.Sign(options.Scheme, signingString, options.Secret);

        var path = options.Path.StartsWith('/') ? options.Path : $"/{options.Path}";
        using var request = new HttpRequestMessage(options.Method, $"{options.BaseUrl.TrimEnd('/')}{path}");

        if (rawBody.Length > 0)
            request.Content = new StringContent(rawBody, Encoding.UTF8, "application/json");

        request.Headers.TryAddWithoutValidation("X-Request-Id", requestId);
        request.Headers.TryAddWithoutValidation("X-Timestamp", timestamp);
        request.Headers.TryAddWithoutValidation("X-Signature", signature);
        if (!string.IsNullOrEmpty(options.PartnerId))
            request.Headers.TryAddWithoutValidation("X-Partner-Id", options.PartnerId);

        foreach (var (name, value) in options.ExtraHeaders ?? new Dictionary<string, string>())
        {
            // Content-* headers live on the content in .NET, not on the request.
            if (!request.Headers.TryAddWithoutValidation(name, value) && request.Content is not null)
            {
                request.Content.Headers.Remove(name);
                request.Content.Headers.TryAddWithoutValidation(name, value);
            }
        }

        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var responseText = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return new SignedResponse
        {
            Status = (int)response.StatusCode,
            Ok = response.IsSuccessStatusCode,
            Headers = response.Headers
                .Concat(response.Content.Headers)
                .ToDictionary(h => h.Key.ToLowerInvariant(), h => string.Join(", ", h.Value)),
            RawBody = responseText,
            Json = IsJson(response) ? TryParseJson(responseText) : null,
        };
    }

    /// <summary>
    /// The actual flow: sign + call <c>POST {apiPrefix}/partner/auth/handoff</c> and get back
    /// <c>{ handoffCode, expiresIn, entryUrl, hasActiveSubscription, pendingMerge? }</c> —
    /// read it with <c>response.DataAs&lt;HandoffResult&gt;()</c> (the API wraps it in an envelope).
    /// </summary>
    public Task<SignedResponse> HandoffAsync(HandoffOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(options.PartnerId, nameof(options.PartnerId));
        ArgumentException.ThrowIfNullOrEmpty(options.PartnerUserId, nameof(options.PartnerUserId));
        ArgumentException.ThrowIfNullOrEmpty(options.PhoneNumber, nameof(options.PhoneNumber));

        return SignedRequestAsync(new SignedRequestOptions
        {
            BaseUrl = options.BaseUrl,
            Path = $"{options.ApiPrefix}/partner/auth/handoff",
            Method = HttpMethod.Post,
            Scheme = options.Scheme,
            Secret = options.Secret,
            PartnerId = options.PartnerId,
            RequestId = options.RequestId,
            Body = new HandoffRequest(options.PartnerUserId, options.PhoneNumber, options.Name, options.Email, options.ReturnPath),
        }, cancellationToken);
    }

    private static bool IsJson(HttpResponseMessage response) =>
        response.Content.Headers.ContentType?.MediaType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true;

    private static JsonElement? TryParseJson(string text)
    {
        try
        {
            using var doc = JsonDocument.Parse(text);
            return doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
