using System.Security.Cryptography;

namespace SimpleAuth.Crypto;

/// <summary>
/// Generates signing keys for OAuth token issuance.
/// Supports EC P-256 (preferred) and RSA-2048.
/// </summary>
internal static class SigningKeyGenerator
{
    /// <summary>
    /// Creates a new EC P-256 signing key with a deterministic key ID.
    /// </summary>
    internal static (ECDsa Key, string KeyId) CreateEcKey()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string kid = BuildKeyId("ec");
        return (key, kid);
    }

    /// <summary>
    /// Creates a new RSA-2048 signing key with a deterministic key ID.
    /// </summary>
    internal static (RSA Key, string KeyId) CreateRsaKey()
    {
        var key = RSA.Create(keySizeInBits: 2048);
        string kid = BuildKeyId("rsa");
        return (key, kid);
    }

    /// <summary>
    /// Exports an EC private key to PEM format.
    /// </summary>
    internal static string ExportEcPrivateKeyPem(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key.ExportECPrivateKeyPem();
    }

    /// <summary>
    /// Exports an RSA private key to PEM format (PKCS#8).
    /// </summary>
    internal static string ExportRsaPrivateKeyPem(RSA key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>
    /// Imports an EC private key from PEM.
    /// </summary>
    internal static ECDsa ImportEcPrivateKeyPem(string pem)
    {
        ArgumentException.ThrowIfNullOrEmpty(pem);
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return key;
    }

    /// <summary>
    /// Imports an RSA private key from PEM.
    /// </summary>
    internal static RSA ImportRsaPrivateKeyPem(string pem)
    {
        ArgumentException.ThrowIfNullOrEmpty(pem);
        var key = RSA.Create();
        key.ImportFromPem(pem);
        return key;
    }

    /// <summary>
    /// Builds a deterministic key ID: <c>{alg}-{yyyyMMddHHmmss}-{4hex}</c>.
    /// Example: <c>ec-20260120-143022-a3f2</c>.
    /// </summary>
    private static string BuildKeyId(string alg)
    {
        string timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        Span<byte> entropy = stackalloc byte[2];
        System.Security.Cryptography.RandomNumberGenerator.Fill(entropy);
        string hex = Convert.ToHexString(entropy).ToLowerInvariant();
        return $"{alg}-{timestamp}-{hex}";
    }
}
