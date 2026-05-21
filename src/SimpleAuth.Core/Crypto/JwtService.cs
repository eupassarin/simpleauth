using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SimpleAuth.Crypto;

/// <summary>
/// Issues signed JWTs (access tokens and ID tokens) using
/// <see cref="JsonWebTokenHandler"/> from Microsoft.IdentityModel.
/// </summary>
[SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated by DI registration.")]
internal sealed class JwtService
{
    private readonly string _issuer;
    private SigningKeyHolder _current;

    internal JwtService(string issuer, SigningKeyHolder signingKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentNullException.ThrowIfNull(signingKey);

        _issuer = issuer;
        _current = signingKey;
    }

    /// <summary>Replaces the active signing key (key rotation).</summary>
    internal void RotateKey(SigningKeyHolder newKey)
    {
        ArgumentNullException.ThrowIfNull(newKey);
        _current = newKey;
    }

    /// <summary>
    /// Issues an access token with <c>typ: at+jwt</c> per RFC 9068.
    /// </summary>
    internal string IssueAccessToken(
        string? subject,
        string clientId,
        IReadOnlyList<string> scopes,
        IReadOnlyList<string> audiences,
        TimeSpan lifetime,
        IEnumerable<Claim>? additionalClaims = null,
        string? cnfJkt = null)
    {
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = audiences.Count == 1 ? audiences[0] : null,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.Add(lifetime),
            SigningCredentials = _current.Credentials,
            TokenType = "at+jwt",
            Claims = BuildAccessTokenClaims(subject, clientId, scopes, audiences, additionalClaims, cnfJkt),
        };

        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(descriptor);
    }

    /// <summary>
    /// Issues an OIDC ID token per OpenID Connect Core 1.0 §2.
    /// </summary>
    internal string IssueIdToken(
        string subject,
        string clientId,
        string? nonce,
        string? accessToken,
        TimeSpan lifetime,
        IEnumerable<Claim>? identityClaims = null)
    {
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["sub"] = subject,
            ["azp"] = clientId,
        };

        if (nonce is not null)
        {
            claims["nonce"] = nonce;
        }

        if (accessToken is not null)
        {
            claims["at_hash"] = ComputeAtHash(accessToken);
        }

        if (identityClaims is not null)
        {
            foreach (Claim claim in identityClaims)
            {
                claims[claim.Type] = claim.Value;
            }
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = clientId,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.Add(lifetime),
            SigningCredentials = _current.Credentials,
            Claims = claims,
        };

        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(descriptor);
    }

    /// <summary>
    /// Computes <c>at_hash</c> claim: left-most half of SHA-256 of the access token,
    /// Base64Url-encoded per OIDC Core §3.3.2.11.
    /// </summary>
    private static string ComputeAtHash(string accessToken)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(accessToken);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bytes, hash);

        ReadOnlySpan<byte> leftHalf = hash[..16];
        Span<char> buffer = stackalloc char[24]; // ceil(16 / 3) * 4 = 24
        bool ok = Convert.TryToBase64Chars(leftHalf, buffer, out int written);

        if (!ok)
        {
            return string.Empty;
        }

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

    private static Dictionary<string, object> BuildAccessTokenClaims(
        string? subject,
        string clientId,
        IReadOnlyList<string> scopes,
        IReadOnlyList<string> audiences,
        IEnumerable<Claim>? additionalClaims,
        string? cnfJkt = null)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["client_id"] = clientId,
        };

        if (subject is not null)
        {
            claims["sub"] = subject;
        }

        if (scopes.Count > 0)
        {
            claims["scope"] = string.Join(' ', scopes);
        }

        // Multiple audiences go in a JSON array (JWT spec)
        if (audiences.Count > 1)
        {
            claims["aud"] = audiences.ToArray();
        }

        // DPoP key binding — cnf.jkt per RFC 9449 §6
        if (cnfJkt is not null)
        {
            claims["cnf"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["jkt"] = cnfJkt,
            };
        }

        if (additionalClaims is not null)
        {
            foreach (Claim claim in additionalClaims)
            {
                claims[claim.Type] = claim.Value;
            }
        }

        return claims;
    }
}

/// <summary>
/// Wraps a signing key with its <see cref="SigningCredentials"/> for use by <see cref="JwtService"/>.
/// </summary>
[SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated by DI registration.")]
internal sealed class SigningKeyHolder
{
    /// <summary>Underlying key material.</summary>
    internal object Key { get; }

    /// <summary>Security key used for JWT validation.</summary>
    internal SecurityKey SecurityKey { get; }

    /// <summary>Key ID matching the JWK in the JWKS document.</summary>
    internal string KeyId { get; }

    /// <summary>Algorithm: <c>ES256</c>, <c>RS256</c>, etc.</summary>
    internal string Algorithm { get; }

    /// <summary>Ready-to-use signing credentials for <see cref="SecurityTokenDescriptor"/>.</summary>
    internal SigningCredentials Credentials { get; }

    private SigningKeyHolder(object key, string keyId, string algorithm, SigningCredentials credentials)
    {
        Key = key;
        SecurityKey = credentials.Key ?? throw new InvalidOperationException("Signing credentials must contain a security key.");
        KeyId = keyId;
        Algorithm = algorithm;
        Credentials = credentials;
    }

    /// <summary>Creates a holder from an EC key.</summary>
    internal static SigningKeyHolder FromEcKey(ECDsa key, string keyId)
    {
        var securityKey = new ECDsaSecurityKey(key) { KeyId = keyId };
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);
        return new SigningKeyHolder(key, keyId, SecurityAlgorithms.EcdsaSha256, credentials);
    }

    /// <summary>Creates a holder from an RSA key.</summary>
    internal static SigningKeyHolder FromRsaKey(RSA key, string keyId)
    {
        var securityKey = new RsaSecurityKey(key) { KeyId = keyId };
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
        return new SigningKeyHolder(key, keyId, SecurityAlgorithms.RsaSha256, credentials);
    }
}
