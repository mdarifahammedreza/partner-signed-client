# DanumAi.PartnerSignedClient (.NET)

.NET port of the Node package in the repo root: the same **HMAC** and **Ed25519** partner
signed-request protocol, byte-for-byte compatible. The tests check it against signatures produced
by the Node `src/crypto.js`.

Targets .NET 8+. Its only dependency is [`BouncyCastle.Cryptography`](https://www.nuget.org/packages/BouncyCastle.Cryptography),
because the .NET base library has no Ed25519.

```
dotnet/
├── PartnerSignedClient.sln
├── src/PartnerSignedClient/        # the library
│   ├── PartnerCrypto.cs            # BuildSigningString, SignHmac, SignEd25519, Sign, Verify   (= src/crypto.js)
│   ├── PartnerClient.cs            # SignedRequestAsync, HandoffAsync                          (= src/client.js + src/handoff.js)
│   ├── PartnerSignatureVerifier.cs # receiving-side check for your own /deduct endpoint
│   ├── Models.cs                   # options, HandoffRequest/HandoffResult, SignedResponse
│   └── SigningScheme.cs
├── examples/HandoffExample/        # = examples/test-handoff-{hmac,ed25519}.js
└── tests/PartnerSignedClient.Tests/
```

## Run

```sh
cd dotnet
dotnet test                                                    # compatibility tests (offline)

# Uses the same repo-root .env as the Node examples (copy .env.example → .env)
dotnet run --project examples/HandoffExample -- hmac
dotnet run --project examples/HandoffExample -- ed25519
```

## Handoff flow

```csharp
using DanumAi.PartnerSignedClient;

var client = new PartnerClient();   // or new PartnerClient(httpClientFromFactory)

var response = await client.HandoffAsync(new HandoffOptions
{
    BaseUrl = "https://dev-api.banglareels.com",
    Scheme = SigningScheme.Hmac,                  // or SigningScheme.Ed25519
    Secret = config["SigningSecret"]!,            // HMAC secret, or Ed25519 private key PEM
    PartnerId = "your-partner-slug",              // sent as X-Partner-Id
    PartnerUserId = "YOUR_USER_889123",
    PhoneNumber = "+8801712345678",
});

if (response.Ok)
{
    // The API wraps results as { status, statusCode, message, data } — DataAs unwraps `data`.
    var result = response.DataAs<HandoffResult>()!;
    // result.EntryUrl → redirect the subscriber's browser here
    // result.HandoffCode → single-use, ~60s TTL
}
```

For Ed25519, set `Scheme = SigningScheme.Ed25519`. `Secret` is then the PKCS#8 private key PEM
(`-----BEGIN PRIVATE KEY-----`). You can generate one with Node, or with
`openssl genpkey -algorithm ed25519`.

## Any other signed endpoint

```csharp
var response = await client.SignedRequestAsync(new SignedRequestOptions
{
    BaseUrl = "https://dev-api.banglareels.com",
    Path = "/api/v1/partner/auth/merge-confirm",
    Scheme = SigningScheme.Hmac,
    Secret = secret,
    PartnerId = "your-partner-slug",   // leave null to simulate BanglaReels → your /deduct
    Body = new { partnerUserId = "YOUR_USER_889123" },
});
```

`Body` is serialized with camelCase names, with null fields left out, and without escaping `+` or
non-ASCII characters. This matches `JSON.stringify`, so the .NET client sends exactly the same
bytes as the Node client.

## Verifying BanglaReels' calls to your `/deduct` (ASP.NET Core)

Sign and verify against the **raw body bytes**. Read the body before model binding, because a
re-serialized copy won't hash the same.

```csharp
app.MapPost("/deduct", async (HttpRequest req) =>
{
    using var reader = new StreamReader(req.Body);
    var rawBody = await reader.ReadToEndAsync();

    var valid = PartnerSignatureVerifier.Verify(
        SigningScheme.Hmac,
        key: outboundSigningSecret,          // HMAC secret, or Ed25519 PUBLIC key PEM
        timestamp: req.Headers["X-Timestamp"],
        requestId: req.Headers["X-Request-Id"],
        signature: req.Headers["X-Signature"],
        rawBody: rawBody);                   // also enforces the ±300s timestamp window

    if (!valid) return Results.Unauthorized();

    var deduct = JsonSerializer.Deserialize<DeductRequest>(rawBody);
    // dedupe on X-Request-Id / idempotencyKey, then charge...
    return Results.Ok();
});
```

The protocol itself is described in the root [README](../README.md#how-the-signature-is-built).
