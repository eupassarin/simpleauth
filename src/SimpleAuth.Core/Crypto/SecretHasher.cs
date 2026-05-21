using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace SimpleAuth.Crypto;

/// <summary>
/// Hashes and verifies client and resource secrets using PBKDF2-SHA256.
/// Secrets are NEVER stored in plaintext — only the hash is persisted.
/// </summary>
public static class SecretHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 310_000; // OWASP 2023 recommendation for PBKDF2-SHA256

    /// <summary>
    /// Hashes a plaintext secret and returns a storable string.
    /// Format: <c>v1:{base64(salt)}:{base64(hash)}</c>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="secret"/> is null or empty.</exception>
    public static string Hash(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);

        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = DeriveKey(secret, salt);

        return $"v1:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    /// <summary>
    /// Verifies a plaintext secret against a previously hashed value.
    /// Returns <see langword="false"/> for any invalid or malformed stored hash.
    /// </summary>
    public static bool Verify(string secret, string storedHash)
    {
        if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(storedHash))
        {
            return false;
        }

        ReadOnlySpan<char> span = storedHash;

        int firstColon = span.IndexOf(':');
        if (firstColon < 0)
        {
            return false;
        }

        ReadOnlySpan<char> version = span[..firstColon];
        if (!version.SequenceEqual("v1"))
        {
            return false;
        }

        ReadOnlySpan<char> rest = span[(firstColon + 1)..];
        int secondColon = rest.IndexOf(':');
        if (secondColon < 0)
        {
            return false;
        }

        ReadOnlySpan<char> saltBase64 = rest[..secondColon];
        ReadOnlySpan<char> hashBase64 = rest[(secondColon + 1)..];

        byte[] salt;
        byte[] expectedHash;

        try
        {
            salt = Convert.FromBase64String(saltBase64.ToString());
            expectedHash = Convert.FromBase64String(hashBase64.ToString());
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length != SaltSize || expectedHash.Length != HashSize)
        {
            return false;
        }

        byte[] actualHash = DeriveKey(secret, salt);

        // Constant-time comparison — prevents timing attacks
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    private static byte[] DeriveKey(string secret, byte[] salt) =>
        KeyDerivation.Pbkdf2(
            password: secret,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: Iterations,
            numBytesRequested: HashSize);
}
