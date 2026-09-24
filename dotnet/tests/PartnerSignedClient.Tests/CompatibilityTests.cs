using System.Net;
using System.Text;
using DanumAi.PartnerSignedClient;
using Xunit;

namespace PartnerSignedClient.Tests;

/// <summary>
/// Expected values below were produced by the Node package (src/crypto.js) with the same inputs —
/// these tests prove the .NET port is byte-for-byte compatible, not just self-consistent.
/// </summary>
public class CompatibilityTests
{
    private const string PrivateKeyPem = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEICqluVmfy4RygW/w10w4mU2qd2RMl1m+VcGY+Ht/tenr
        -----END PRIVATE KEY-----
        """;

    private const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAwUUCAZnYdD/YD/OKg74wzRbPfJtuA6nDknhqFnrxnz4=
        -----END PUBLIC KEY-----
        """;

    private const string NodeBody = "{\"partnerUserId\":\"USER_1\",\"phoneNumber\":\"+8801712345678\",\"name\":\"রেজা\"}";
    private const string NodeSigningString = "1700000000.req-123.afc0e72029cb181220d7ac92b6321c59ff563606d4fff55371d1eba4177bb1f9";
    private const string NodeHmac = "v1=e5125595fc9ec8bc1c6dc3b0a7ec636b7cbd73fe532c1becd77469a3b571e032";
    private const string NodeEd25519 = "v1=fw3pu56QonGoY/ID0IJNzZilLwqdKpHRA9HJXsekMQKtMcSMpbVK6E/63DQPmEHtz4jaFltGQAjtWaKh0G5AAg==";

    [Fact]
    public void SigningString_MatchesNode() =>
        Assert.Equal(NodeSigningString, PartnerCrypto.BuildSigningString("1700000000", "req-123", NodeBody));

    [Fact]
    public void SigningString_EmptyBody_HashesEmptyString() =>
        Assert.Equal(
            "1.r.e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            PartnerCrypto.BuildSigningString("1", "r", null));

    [Fact]
    public void Hmac_MatchesNode() =>
        Assert.Equal(NodeHmac, PartnerCrypto.Sign(SigningScheme.Hmac, NodeSigningString, "test-secret"));

    [Fact]
    public void Ed25519_MatchesNode() =>
        Assert.Equal(NodeEd25519, PartnerCrypto.Sign(SigningScheme.Ed25519, NodeSigningString, PrivateKeyPem));

    [Fact]
    public void Verify_AcceptsValid_RejectsTampered()
    {
        Assert.True(PartnerCrypto.Verify(SigningScheme.Hmac, NodeSigningString, NodeHmac, "test-secret"));
        Assert.True(PartnerCrypto.Verify(SigningScheme.Ed25519, NodeSigningString, NodeEd25519, PublicKeyPem));

        var tampered = NodeSigningString.Replace("req-123", "req-124");
        Assert.False(PartnerCrypto.Verify(SigningScheme.Hmac, tampered, NodeHmac, "test-secret"));
        Assert.False(PartnerCrypto.Verify(SigningScheme.Ed25519, tampered, NodeEd25519, PublicKeyPem));
        Assert.False(PartnerCrypto.Verify(SigningScheme.Hmac, NodeSigningString, NodeHmac, "wrong-secret"));
    }

    [Fact]
    public void Verifier_RejectsStaleTimestamp()
    {
        var sentAt = DateTimeOffset.FromUnixTimeSeconds(1700000000);

        Assert.True(PartnerSignatureVerifier.Verify(
            SigningScheme.Hmac, "test-secret", "1700000000", "req-123", NodeHmac, NodeBody, now: sentAt.AddSeconds(299)));
        Assert.False(PartnerSignatureVerifier.Verify(
            SigningScheme.Hmac, "test-secret", "1700000000", "req-123", NodeHmac, NodeBody, now: sentAt.AddSeconds(301)));
    }

    [Theory]
    [InlineData(SigningScheme.Hmac, "test-secret", "test-secret")]
    [InlineData(SigningScheme.Ed25519, PrivateKeyPem, PublicKeyPem)]
    public async Task Handoff_SendsNodeIdenticalBody_AndVerifiableHeaders(SigningScheme scheme, string secret, string verifyKey)
    {
        var handler = new CapturingHandler();
        var client = new PartnerClient(new HttpClient(handler));

        var response = await client.HandoffAsync(new HandoffOptions
        {
            BaseUrl = "https://example.test/",
            Scheme = scheme,
            Secret = secret,
            PartnerId = "acme",
            PartnerUserId = "USER_1",
            PhoneNumber = "+8801712345678",
            Name = "রেজা",
        });

        var request = handler.Request!;
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://example.test/api/v1/partner/auth/handoff", request.RequestUri!.ToString());
        Assert.Equal(NodeBody, handler.Body);
        Assert.Equal("acme", request.Headers.GetValues("X-Partner-Id").Single());

        Assert.True(PartnerSignatureVerifier.Verify(
            scheme,
            verifyKey,
            request.Headers.GetValues("X-Timestamp").Single(),
            request.Headers.GetValues("X-Request-Id").Single(),
            request.Headers.GetValues("X-Signature").Single(),
            handler.Body!));

        var result = response.DataAs<HandoffResult>();
        Assert.Equal(201, response.Status);
        Assert.Equal("CODE", result!.HandoffCode);
        Assert.Equal("https://app.test/entry?code=CODE", result.EntryUrl);
    }

    [Fact]
    public async Task SignedRequest_WithoutPartnerId_OmitsHeader()
    {
        var handler = new CapturingHandler();
        await new PartnerClient(new HttpClient(handler)).SignedRequestAsync(new SignedRequestOptions
        {
            BaseUrl = "https://partner.test",
            Path = "deduct",
            Scheme = SigningScheme.Hmac,
            Secret = "s",
            Body = new { partnerUserId = "U", amount = "100.00" },
        });

        Assert.Equal("https://partner.test/deduct", handler.Request!.RequestUri!.ToString());
        Assert.False(handler.Request.Headers.Contains("X-Partner-Id"));
        Assert.Equal("{\"partnerUserId\":\"U\",\"amount\":\"100.00\"}", handler.Body);
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);

            return new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent(
                    "{\"status\":true,\"statusCode\":200,\"message\":\"Request successful\",\"data\":{\"handoffCode\":\"CODE\",\"expiresIn\":60,\"entryUrl\":\"https://app.test/entry?code=CODE\",\"hasActiveSubscription\":false}}",
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }
}
