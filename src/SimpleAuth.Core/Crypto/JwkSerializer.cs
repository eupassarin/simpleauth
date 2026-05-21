using System.Security.Cryptography;
using System.Text.Json;
using SimpleAuth.Serialization;

namespace SimpleAuth.Crypto;

/// <summary>
/// Converts signing keys to JWK (JSON Web Key) format per RFC 7517.
/// Only public material is exported — private keys never leave this layer.
/// </summary>
internal static class JwkSerializer
{
    /// <summary>
    /// Exports an EC public key as a JWK object.
    /// </summary>
    internal static Jwk FromEcKey(ECDsa key, string keyId, string algorithm = "ES256")
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        ECPoint q = parameters.Q;

        return new Jwk(
            Kty: "EC",
            Use: "sig",
            Kid: keyId,
            Alg: algorithm,
            Crv: "P-256",
            X: Base64UrlEncode(q.X!),
            Y: Base64UrlEncode(q.Y!),
            N: null,
            E: null);
    }

    /// <summary>
    /// Exports an RSA public key as a JWK object.
    /// </summary>
    internal static Jwk FromRsaKey(RSA key, string keyId, string algorithm = "RS256")
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        RSAParameters parameters = key.ExportParameters(includePrivateParameters: false);

        return new Jwk(
            Kty: "RSA",
            Use: "sig",
            Kid: keyId,
            Alg: algorithm,
            Crv: null,
            X: null,
            Y: null,
            N: Base64UrlEncode(parameters.Modulus!),
            E: Base64UrlEncode(parameters.Exponent!));
    }

    /// <summary>
    /// Serializes a JWKS document (array of JWKs) to a UTF-8 JSON byte array
    /// for caching and direct HTTP response writing.
    /// </summary>
    internal static ReadOnlyMemory<byte> BuildJwks(IEnumerable<Jwk> keys)
    {
        var document = new JwksDocument(Keys: [.. keys]);
        return new ReadOnlyMemory<byte>(
            JsonSerializer.SerializeToUtf8Bytes(document, AuthJsonContext.Default.JwksDocument));
    }

    private static string Base64UrlEncode(byte[] input)
    {
        // Avoid allocating a string twice via Convert.ToBase64String + replace
        Span<char> buffer = input.Length <= 64
            ? stackalloc char[((input.Length + 2) / 3) * 4]
            : new char[((input.Length + 2) / 3) * 4];

        bool ok = Convert.TryToBase64Chars(input, buffer, out int charsWritten);
        if (!ok)
        {
            return string.Empty;
        }

        for (int i = 0; i < charsWritten; i++)
        {
            buffer[i] = buffer[i] switch
            {
                '+' => '-',
                '/' => '_',
                _ => buffer[i],
            };
        }

        while (charsWritten > 0 && buffer[charsWritten - 1] == '=')
        {
            charsWritten--;
        }

        return new string(buffer[..charsWritten]);
    }
}

/// <summary>A JSON Web Key (public material only).</summary>
/// <param name="Kty">Key type: <c>EC</c> or <c>RSA</c>.</param>
/// <param name="Use">Key use: <c>sig</c>.</param>
/// <param name="Kid">Key ID.</param>
/// <param name="Alg">Algorithm: <c>ES256</c>, <c>RS256</c>, etc.</param>
/// <param name="Crv">EC curve (EC keys only): <c>P-256</c>.</param>
/// <param name="X">EC public key X coordinate (EC keys only).</param>
/// <param name="Y">EC public key Y coordinate (EC keys only).</param>
/// <param name="N">RSA modulus (RSA keys only).</param>
/// <param name="E">RSA public exponent (RSA keys only).</param>
internal sealed record Jwk(
    string Kty,
    string Use,
    string Kid,
    string? Alg,
    string? Crv,
    string? X,
    string? Y,
    string? N,
    string? E);

/// <summary>The <c>jwks.json</c> document: <c>{ "keys": [ ... ] }</c>.</summary>
/// <param name="Keys">The collection of public JWKs.</param>
internal sealed record JwksDocument(IReadOnlyList<Jwk> Keys);
