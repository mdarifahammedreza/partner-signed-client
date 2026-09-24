using System.Text.Json;
using System.Text.Json.Serialization;

namespace DanumAi.PartnerSignedClient;

/// <summary>Options for <see cref="PartnerClient.SignedRequestAsync"/>.</summary>
public sealed class SignedRequestOptions
{
    /// <summary>e.g. <c>https://dev-api.banglareels.com</c> or a partner's own API base.</summary>
    public required string BaseUrl { get; init; }

    /// <summary>e.g. <c>/api/v1/partner/auth/merge-confirm</c>.</summary>
    public required string Path { get; init; }

    /// <summary>Defaults to POST.</summary>
    public HttpMethod Method { get; init; } = HttpMethod.Post;

    /// <summary>Serialized to JSON (camelCase, nulls omitted); <c>null</c> for no body.</summary>
    public object? Body { get; init; }

    public required SigningScheme Scheme { get; init; }

    /// <summary>HMAC secret, or Ed25519 private key PEM.</summary>
    public required string Secret { get; init; }

    /// <summary><c>X-Partner-Id</c> — omit for the outbound (BanglaReels→partner) direction.</summary>
    public string? PartnerId { get; init; }

    /// <summary>
    /// <c>X-Request-Id</c> — reuse the same value on any retry of the same attempt; auto-generated
    /// (UUID) if omitted.
    /// </summary>
    public string? RequestId { get; init; }

    public IDictionary<string, string>? ExtraHeaders { get; init; }
}

/// <summary>Options for <see cref="PartnerClient.HandoffAsync"/>.</summary>
public sealed class HandoffOptions
{
    /// <summary>e.g. <c>https://dev-api.banglareels.com</c>.</summary>
    public required string BaseUrl { get; init; }

    public string ApiPrefix { get; init; } = "/api/v1";

    public required SigningScheme Scheme { get; init; }

    /// <summary>HMAC secret, or Ed25519 private key PEM.</summary>
    public required string Secret { get; init; }

    /// <summary>Your partner slug (<c>X-Partner-Id</c>).</summary>
    public required string PartnerId { get; init; }

    /// <summary>Your own user id; must match what you'll later send on payment callbacks.</summary>
    public required string PartnerUserId { get; init; }

    /// <summary>E.164 preferred.</summary>
    public required string PhoneNumber { get; init; }

    public string? Name { get; init; }
    public string? Email { get; init; }
    public string? ReturnPath { get; init; }
    public string? RequestId { get; init; }
}

/// <summary>Body of <c>POST partner/auth/handoff</c> — matches PartnerHandoffDto, same field order.</summary>
public sealed record HandoffRequest(
    [property: JsonPropertyName("partnerUserId")] string PartnerUserId,
    [property: JsonPropertyName("phoneNumber")] string PhoneNumber,
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("returnPath")] string? ReturnPath);

/// <summary>Successful handoff response (HandoffResult).</summary>
public sealed record HandoffResult(
    [property: JsonPropertyName("handoffCode")] string HandoffCode,
    [property: JsonPropertyName("expiresIn")] int ExpiresIn,
    [property: JsonPropertyName("entryUrl")] string EntryUrl,
    [property: JsonPropertyName("hasActiveSubscription")] bool HasActiveSubscription,
    [property: JsonPropertyName("pendingMerge")] JsonElement? PendingMerge);

/// <summary>What every signed call returns.</summary>
public sealed class SignedResponse
{
    public required int Status { get; init; }
    public required bool Ok { get; init; }
    public required IReadOnlyDictionary<string, string> Headers { get; init; }

    /// <summary>The response body as text, always populated.</summary>
    public required string RawBody { get; init; }

    /// <summary>Parsed JSON when the response declares a JSON content-type and parses; otherwise <c>null</c>.</summary>
    public JsonElement? Json { get; init; }

    /// <summary>Deserializes <see cref="Json"/> into <typeparamref name="T"/>; <c>default</c> when there's no JSON body.</summary>
    public T? BodyAs<T>() => Json is { } json ? json.Deserialize<T>(PartnerClient.JsonOptions) : default;

    /// <summary>
    /// Deserializes the payload inside BanglaReels' response envelope
    /// (<c>{ status, statusCode, message, data, ... }</c>) — e.g. <c>DataAs&lt;HandoffResult&gt;()</c>.
    /// Falls back to the root object when there's no <c>data</c> property.
    /// </summary>
    public T? DataAs<T>()
    {
        if (Json is not { } json) return default;

        var payload = json.ValueKind == JsonValueKind.Object && json.TryGetProperty("data", out var data) ? data : json;
        return payload.Deserialize<T>(PartnerClient.JsonOptions);
    }
}
