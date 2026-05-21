namespace SimpleAuth;

/// <summary>
/// A hashed credential (secret, X.509 thumbprint, or JWK) for a <see cref="Client"/>.
/// The <see cref="Value"/> field is ALWAYS the SHA-256 hex of the raw secret — never plaintext.
/// </summary>
public sealed class ClientCredential
{
    /// <summary>SHA-256 hex of the raw secret. Never store the plaintext value here.</summary>
    public required string Value { get; init; }

    /// <summary>
    /// Credential type discriminator.
    /// Allowed values: <c>"SharedSecret"</c>, <c>"X509Thumbprint"</c>, <c>"JsonWebKey"</c>.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>Optional human-readable description of this credential.</summary>
    public string? Description { get; init; }

    /// <summary>Optional UTC expiry. If set, the credential is rejected after this time.</summary>
    public DateTime? Expiration { get; init; }
}

/// <summary>
/// A hashed credential for a <see cref="ProtectedResource"/> (used by introspection callers).
/// The <see cref="Value"/> field is ALWAYS SHA-256 hex — never plaintext.
/// </summary>
public sealed class ResourceCredential
{
    /// <summary>SHA-256 hex of the raw secret.</summary>
    public required string Value { get; init; }

    /// <summary>Credential type. Allowed: <c>"SharedSecret"</c>.</summary>
    public required string Type { get; init; }

    /// <summary>Optional human-readable description.</summary>
    public string? Description { get; init; }

    /// <summary>Optional UTC expiry.</summary>
    public DateTime? Expiration { get; init; }
}

/// <summary>A static claim that is always included in tokens issued for a <see cref="Client"/>.</summary>
public sealed class ClientClaim
{
    /// <summary>Claim type (e.g., <c>"role"</c>, <c>"tenant"</c>).</summary>
    public required string Type { get; init; }

    /// <summary>Claim value.</summary>
    public required string Value { get; init; }
}

/// <summary>A JSON Web Key set (inline JWKS) for a client using <c>private_key_jwt</c> authentication.</summary>
public sealed class ClientJwks
{
    /// <summary>Raw JSON of the JWKS document. Must contain public keys only.</summary>
    public required string Json { get; init; }
}
