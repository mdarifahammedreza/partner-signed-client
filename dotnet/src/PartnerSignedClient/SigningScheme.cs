namespace DanumAi.PartnerSignedClient;

/// <summary>The two signing schemes BanglaReels' partner protocol supports.</summary>
public enum SigningScheme
{
    /// <summary>HMAC-SHA256 with a shared secret; signature is hex-encoded.</summary>
    Hmac,

    /// <summary>Ed25519 with the partner's private key (PKCS#8 PEM); signature is base64-encoded.</summary>
    Ed25519,
}
