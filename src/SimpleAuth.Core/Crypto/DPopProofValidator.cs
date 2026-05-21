using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SimpleAuth.Crypto;

/// <summary>The outcome of a DPoP proof validation attempt.</summary>
internal readonly struct DPopValidationResult
{
    private DPopValidationResult(bool valid, string? jkt, string? error)
    {
        IsValid = valid;
        JktThumbprint = jkt;
        Error = error;
    }

    internal bool IsValid { get; }

    /// <summary>JWK thumbprint of the DPoP public key. Non-null when <see cref="IsValid"/> is true.</summary>
    internal string? JktThumbprint { get; }

    /// <summary>Human-readable failure reason. Non-null when <see cref="IsValid"/> is false.</summary>
    internal string? Error { get; }

    internal static DPopValidationResult Ok(string jkt) => new(true, jkt, null);
    internal static DPopValidationResult Fail(string error) => new(false, null, error);
}

/// <summary>
/// Validates DPoP proof JWTs per RFC 9449 §4.3.
/// Validates signature, header, payload claims, and replay protection via <see cref="IJtiStore"/>.
/// </summary>
internal static class DPopProofValidator
{
    /// <summary>Maximum age of a DPoP proof's <c>iat</c> claim (seconds).</summary>
    private const int MaxIatSkewSeconds = 60;

    /// <summary>
    /// Validates a DPoP proof JWT presented at the token endpoint or a resource endpoint.
    /// </summary>
    /// <param name="dpopProof">Raw DPoP JWT string from the <c>DPoP</c> header.</param>
    /// <param name="expectedHtm">Expected HTTP method (e.g., <c>POST</c>).</param>
    /// <param name="expectedHtu">Expected HTTP URI (scheme + authority + path, no query).</param>
    /// <param name="jtiStore">Store used to detect and prevent proof replay.</param>
    /// <param name="accessToken">
    /// If non-null, the validator also verifies the <c>ath</c> claim equals
    /// base64url(SHA-256(<paramref name="accessToken"/>)).
    /// Required for DPoP-bound resource access (RFC 9449 §7.1).
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    internal static async Task<DPopValidationResult> ValidateAsync(
        string dpopProof,
        string expectedHtm,
        string expectedHtu,
        IJtiStore jtiStore,
        string? accessToken = null,
        CancellationToken cancellationToken = default)
    {
        // 1 — Structural check: header.payload.signature
        string[] parts = dpopProof.Split('.');
        if (parts.Length != 3)
        {
            return DPopValidationResult.Fail("DPoP proof is not a valid JWT.");
        }

        // 2 — Decode header
        JsonElement headerElement;
        try
        {
            byte[] headerBytes = Base64UrlDecode(parts[0]);
            using JsonDocument doc = JsonDocument.Parse(headerBytes);
            headerElement = doc.RootElement.Clone();
        }
        catch
        {
            return DPopValidationResult.Fail("DPoP proof header could not be decoded.");
        }

        // 3 — Validate typ claim (must be "dpop+jwt")
        if (!headerElement.TryGetProperty("typ", out JsonElement typProp) ||
            !string.Equals(typProp.GetString(), "dpop+jwt", StringComparison.OrdinalIgnoreCase))
        {
            return DPopValidationResult.Fail("DPoP proof must have typ=dpop+jwt.");
        }

        // 4 — Validate alg (must not be symmetric or none)
        if (!headerElement.TryGetProperty("alg", out JsonElement algProp))
        {
            return DPopValidationResult.Fail("DPoP proof is missing the alg header.");
        }

        string alg = algProp.GetString() ?? string.Empty;
        if (!IsAsymmetricAlgorithm(alg))
        {
            return DPopValidationResult.Fail($"DPoP proof uses disallowed algorithm '{alg}'.");
        }

        // 5 — Extract embedded public key
        if (!headerElement.TryGetProperty("jwk", out JsonElement jwkElement))
        {
            return DPopValidationResult.Fail("DPoP proof header is missing the jwk field.");
        }

        // RFC 9449 §4.3 step 2: the jwk MUST NOT contain private key material.
        if (ContainsPrivateKeyMaterial(jwkElement))
        {
            return DPopValidationResult.Fail("DPoP proof jwk MUST NOT contain private key parameters.");
        }

        SecurityKey? publicKey;
        string jkt;
        try
        {
            (publicKey, jkt) = BuildSecurityKeyAndThumbprint(jwkElement);
        }
        catch (Exception ex)
        {
            return DPopValidationResult.Fail($"DPoP proof jwk could not be parsed: {ex.Message}");
        }

        if (publicKey is null)
        {
            return DPopValidationResult.Fail("DPoP proof jwk key type is not supported.");
        }

        // 6 — Validate JWT signature using the embedded public key
        var handler = new JsonWebTokenHandler();

        // DPoP proofs intentionally have no issuer, audience, or exp claim (RFC 9449 §4.2).
        // Freshness is validated manually via the iat claim below.
#pragma warning disable CA5404 // DPoP proofs have no issuer, audience, or exp — validated manually
        TokenValidationResult validationResult = await handler.ValidateTokenAsync(dpopProof, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = true,
            RequireExpirationTime = false,
            IssuerSigningKey = publicKey,
        });
#pragma warning restore CA5404

        if (!validationResult.IsValid)
        {
            return DPopValidationResult.Fail($"DPoP proof signature is invalid: {validationResult.Exception?.Message}");
        }

        JsonWebToken jwt = (JsonWebToken)validationResult.SecurityToken;

        // 7 — htm claim must match the HTTP method
        string htm = jwt.GetClaim("htm")?.Value ?? string.Empty;
        if (!string.Equals(htm, expectedHtm, StringComparison.OrdinalIgnoreCase))
        {
            return DPopValidationResult.Fail($"DPoP htm mismatch: expected {expectedHtm}, got {htm}.");
        }

        // 8 — htu claim must match the HTTP target URI (ignoring query string per RFC 9449 §4.2)
        string htu = jwt.GetClaim("htu")?.Value ?? string.Empty;
        if (!string.Equals(NormalizeUri(htu), NormalizeUri(expectedHtu), StringComparison.OrdinalIgnoreCase))
        {
            return DPopValidationResult.Fail($"DPoP htu mismatch.");
        }

        // 9 — iat must be fresh (within the acceptable skew window)
        if (!jwt.TryGetPayloadValue("iat", out long iatUnix))
        {
            return DPopValidationResult.Fail("DPoP proof is missing the iat claim.");
        }

        DateTime iat = DateTimeOffset.FromUnixTimeSeconds(iatUnix).UtcDateTime;
        DateTime now = DateTime.UtcNow;
        if (Math.Abs((now - iat).TotalSeconds) > MaxIatSkewSeconds)
        {
            return DPopValidationResult.Fail("DPoP proof iat is outside the acceptable window.");
        }

        // 10 — jti must be unique (replay protection)
        string jti = jwt.Id ?? string.Empty;
        if (string.IsNullOrWhiteSpace(jti))
        {
            return DPopValidationResult.Fail("DPoP proof is missing the jti claim.");
        }

        bool stored = await jtiStore.TryConsumeAsync(
            jti,
            expiry: now.AddSeconds(MaxIatSkewSeconds * 2),
            cancellationToken);

        if (!stored)
        {
            return DPopValidationResult.Fail("DPoP proof jti has already been used (replay detected).");
        }

        // 11 — ath (access token hash) — required when an access token is provided
        if (accessToken is not null)
        {
            string expectedAth = ComputeAth(accessToken);
            string? ath = jwt.GetClaim("ath")?.Value;
            if (ath is null || ath.Length != expectedAth.Length ||
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(ath),
                    Encoding.UTF8.GetBytes(expectedAth)))
            {
                return DPopValidationResult.Fail("DPoP proof ath does not match the presented access token.");
            }
        }

        return DPopValidationResult.Ok(jkt);
    }

    /// <summary>Computes the JWK thumbprint (RFC 7638) for a public key JSON element.</summary>
    internal static string ComputeThumbprint(JsonElement jwkElement)
    {
        (_, string jkt) = BuildSecurityKeyAndThumbprint(jwkElement);
        return jkt;
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    /// <summary>Checks if a JWK JSON element contains private key parameters (d, p, q, dp, dq, qi).</summary>
    private static bool ContainsPrivateKeyMaterial(JsonElement jwk)
    {
        return jwk.TryGetProperty("d", out _) ||
               jwk.TryGetProperty("p", out _) ||
               jwk.TryGetProperty("q", out _) ||
               jwk.TryGetProperty("dp", out _) ||
               jwk.TryGetProperty("dq", out _) ||
               jwk.TryGetProperty("qi", out _);
    }

    /// <summary>Builds a <see cref="SecurityKey"/> and JWK thumbprint from a jwk JSON element.</summary>
    private static (SecurityKey? Key, string Thumbprint) BuildSecurityKeyAndThumbprint(JsonElement jwk)
    {
        string kty = jwk.TryGetProperty("kty", out JsonElement ktyEl)
            ? ktyEl.GetString() ?? string.Empty
            : string.Empty;

        if (string.Equals(kty, "EC", StringComparison.Ordinal))
        {
            string crv = jwk.GetProperty("crv").GetString() ?? string.Empty;
            string x = jwk.GetProperty("x").GetString() ?? string.Empty;
            string y = jwk.GetProperty("y").GetString() ?? string.Empty;

            ECCurve curve = crv switch
            {
                "P-256" => ECCurve.NamedCurves.nistP256,
                "P-384" => ECCurve.NamedCurves.nistP384,
                "P-521" => ECCurve.NamedCurves.nistP521,
                _ => throw new NotSupportedException($"Unsupported EC curve: {crv}"),
            };

            var ecParams = new ECParameters
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = Base64UrlDecode(x),
                    Y = Base64UrlDecode(y),
                },
            };

            // ECDsaSecurityKey wraps but does NOT own the key — dispose is caller's concern.
            // The key's lifetime here is transient (single request validation).
#pragma warning disable CA2000
            ECDsa ecdsa = ECDsa.Create(ecParams);
#pragma warning restore CA2000
            string thumbprint = ComputeEcThumbprint(crv, x, y);
            return (new ECDsaSecurityKey(ecdsa), thumbprint);
        }

        if (string.Equals(kty, "RSA", StringComparison.Ordinal))
        {
            string n = jwk.GetProperty("n").GetString() ?? string.Empty;
            string e = jwk.GetProperty("e").GetString() ?? string.Empty;

            var rsaParams = new RSAParameters
            {
                Modulus = Base64UrlDecode(n),
                Exponent = Base64UrlDecode(e),
            };

#pragma warning disable CA2000
            RSA rsa = RSA.Create(rsaParams);
#pragma warning restore CA2000
            string thumbprint = ComputeRsaThumbprint(e, n);
            return (new RsaSecurityKey(rsa), thumbprint);
        }

        return (null, string.Empty);
    }

    /// <summary>
    /// Computes RFC 7638 JWK thumbprint for an EC key.
    /// Canonical form: {"crv":"P-256","kty":"EC","x":"...","y":"..."} (alphabetical key order).
    /// </summary>
    private static string ComputeEcThumbprint(string crv, string x, string y)
    {
        // Keys MUST be in alphabetical order per RFC 7638 §3.3.
        string json = $"{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return HashToThumbprint(json);
    }

    /// <summary>
    /// Computes RFC 7638 JWK thumbprint for an RSA key.
    /// Canonical form: {"e":"...","kty":"RSA","n":"..."} (alphabetical key order).
    /// </summary>
    private static string ComputeRsaThumbprint(string e, string n)
    {
        string json = $"{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}";
        return HashToThumbprint(json);
    }

    private static string HashToThumbprint(string canonicalJson)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJson), hash);
        return Base64UrlEncode(hash);
    }

    /// <summary>
    /// Computes <c>ath</c> claim value: base64url(SHA-256(ascii(access_token))).
    /// RFC 9449 §4.2.
    /// </summary>
    private static string ComputeAth(string accessToken)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.ASCII.GetBytes(accessToken), hash);
        return Base64UrlEncode(hash);
    }

    private static bool IsAsymmetricAlgorithm(string alg) =>
        alg.StartsWith("ES", StringComparison.Ordinal) ||
        alg.StartsWith("RS", StringComparison.Ordinal) ||
        alg.StartsWith("PS", StringComparison.Ordinal) ||
        alg.StartsWith("EdDSA", StringComparison.Ordinal);

    /// <summary>Strips query string and fragment from a URI for htu comparison.</summary>
    private static string NormalizeUri(string uri)
    {
        int q = uri.IndexOf('?', StringComparison.Ordinal);
        if (q >= 0)
        {
            uri = uri[..q];
        }

        int f = uri.IndexOf('#', StringComparison.Ordinal);
        if (f >= 0)
        {
            uri = uri[..f];
        }

        return uri.TrimEnd('/');
    }

    private static byte[] Base64UrlDecode(string input)
    {
        string padded = (input.Length % 4) switch
        {
            2 => input + "==",
            3 => input + "=",
            _ => input,
        };

        return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes)
    {
        Span<char> buffer = stackalloc char[48];
        Convert.TryToBase64Chars(bytes, buffer, out int written);
        for (int i = 0; i < written; i++)
        {
            buffer[i] = buffer[i] switch
            {
                '+' => '-',
                '/' => '_',
                _ => buffer[i],
            };
        }

        while (written > 0 && buffer[written - 1] == '=')
        {
            written--;
        }

        return new string(buffer[..written]);
    }
}
