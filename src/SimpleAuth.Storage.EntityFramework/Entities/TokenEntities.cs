using System.ComponentModel.DataAnnotations;

namespace SimpleAuth.EntityFramework.Entities;

/// <summary>EF Core entity for an authorization code.</summary>
internal sealed class AuthorizationCodeEntity
{
    /// <summary>SHA-256 hash of the opaque code handle.</summary>
    [Key]
    [MaxLength(64)]
    public required string Handle { get; set; }

    [MaxLength(200)]
    public required string ClientId { get; set; }

    [MaxLength(500)]
    public required string SubjectId { get; set; }

    [MaxLength(2000)]
    public required string RedirectUri { get; set; }

    [MaxLength(256)]
    public required string CodeChallenge { get; set; }

    /// <summary>JSON: string[]</summary>
    public required string GrantedScopes { get; set; }

    public required DateTime CreatedAt { get; set; }
    public required DateTime ExpiresAt { get; set; }

    [MaxLength(500)]
    public string? Nonce { get; set; }

    [MaxLength(200)]
    public string? SessionId { get; set; }

    public bool IsConsumed { get; set; }
}

/// <summary>EF Core entity for a refresh token.</summary>
internal sealed class RefreshTokenEntity
{
    [Key]
    [MaxLength(64)]
    public required string Handle { get; set; }

    [MaxLength(200)]
    public required string ClientId { get; set; }

    [MaxLength(500)]
    public required string SubjectId { get; set; }

    /// <summary>JSON: string[]</summary>
    public required string GrantedScopes { get; set; }

    public required DateTime CreatedAt { get; set; }
    public required DateTime ExpiresAt { get; set; }
    public DateTime? SlidingExpiresAt { get; set; }

    [MaxLength(200)]
    public string? SessionId { get; set; }

    public bool IsRevoked { get; set; }
    public int Generation { get; set; }

    /// <summary>JWK thumbprint for DPoP binding (RFC 9449 §10.1).</summary>
    [MaxLength(128)]
    public string? DPopJkt { get; set; }
}

/// <summary>EF Core entity for an issued (reference) access token.</summary>
internal sealed class IssuedTokenEntity
{
    [Key]
    [MaxLength(64)]
    public required string Handle { get; set; }

    [MaxLength(200)]
    public required string ClientId { get; set; }

    [MaxLength(500)]
    public string? SubjectId { get; set; }

    /// <summary>JSON: string[]</summary>
    public required string GrantedScopes { get; set; }

    public required DateTime CreatedAt { get; set; }
    public required DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }

    [MaxLength(64)]
    public string? RefreshTokenHandle { get; set; }

    [MaxLength(128)]
    public string? JktThumbprint { get; set; }
}

/// <summary>EF Core entity for a PAR entry (RFC 9126).</summary>
internal sealed class ParEntryEntity
{
    [Key]
    [MaxLength(500)]
    public required string RequestUri { get; set; }

    [MaxLength(200)]
    public required string ClientId { get; set; }

    [MaxLength(2000)]
    public required string RedirectUri { get; set; }

    [MaxLength(1000)]
    public required string Scope { get; set; }

    [MaxLength(256)]
    public required string CodeChallenge { get; set; }

    [MaxLength(10)]
    public required string CodeChallengeMethod { get; set; }

    [MaxLength(10)]
    public required string ResponseType { get; set; }

    [MaxLength(500)]
    public string? State { get; set; }

    [MaxLength(500)]
    public string? Nonce { get; set; }

    public required DateTime CreatedAt { get; set; }
    public required DateTime ExpiresAt { get; set; }
}

/// <summary>EF Core entity for a signing key.</summary>
internal sealed class SigningKeyEntity
{
    [Key]
    [MaxLength(100)]
    public required string KeyId { get; set; }

    [MaxLength(10)]
    public required string Algorithm { get; set; }

    [MaxLength(10000)]
    public required string PrivateKeyPem { get; set; }

    public required DateTime CreatedAt { get; set; }
    public required DateTime RetireAt { get; set; }
    public required DateTime RemoveAt { get; set; }
    public bool IsPrimary { get; set; }
}

/// <summary>EF Core entity tracking consumed JTIs for replay prevention.</summary>
internal sealed class JtiRecordEntity
{
    [Key]
    [MaxLength(200)]
    public required string Jti { get; set; }

    public required DateTime ExpiresAt { get; set; }
}

/// <summary>EF Core entity for stored user consent decisions.</summary>
internal sealed class UserConsentEntity
{
    [MaxLength(500)]
    public required string SubjectId { get; set; }

    [MaxLength(200)]
    public required string ClientId { get; set; }

    /// <summary>JSON: string[]</summary>
    public required string GrantedScopes { get; set; }

    public required DateTime CreatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
}

/// <summary>EF Core entity for an API scope.</summary>
internal sealed class ScopeEntity
{
    [Key]
    [MaxLength(200)]
    public required string Name { get; set; }

    [MaxLength(300)]
    public string? DisplayName { get; set; }

    [MaxLength(1000)]
    public string? Description { get; set; }

    public bool ShowInDiscoveryDocument { get; set; } = true;
    public bool Required { get; set; }
    public bool Emphasize { get; set; }
    public bool Enabled { get; set; } = true;
}

/// <summary>EF Core entity for an OIDC identity scope.</summary>
internal sealed class IdentityScopeEntity
{
    [Key]
    [MaxLength(200)]
    public required string Name { get; set; }

    [MaxLength(300)]
    public string? DisplayName { get; set; }

    [MaxLength(1000)]
    public string? Description { get; set; }

    /// <summary>JSON: string[]</summary>
    public required string ClaimTypes { get; set; }

    public bool Required { get; set; }
    public bool Emphasize { get; set; }
    public bool ShowInDiscoveryDocument { get; set; } = true;
    public bool Enabled { get; set; } = true;
}

/// <summary>EF Core entity for a protected resource (API).</summary>
internal sealed class ProtectedResourceEntity
{
    [Key]
    [MaxLength(500)]
    public required string Name { get; set; }

    [MaxLength(300)]
    public string? DisplayName { get; set; }

    /// <summary>JSON: string[] — scope names belonging to this resource.</summary>
    public required string Scopes { get; set; }

    public bool Enabled { get; set; } = true;
}
