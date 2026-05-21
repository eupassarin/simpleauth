using System.ComponentModel.DataAnnotations;

namespace SimpleAuth.EntityFramework.Entities;

/// <summary>EF Core entity for a registered OAuth 2.1 client.</summary>
internal sealed class ClientEntity
{
    [Key]
    [MaxLength(200)]
    public required string ClientId { get; set; }

    [MaxLength(200)]
    public required string ClientName { get; set; }

    [MaxLength(1000)]
    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    // ── Collections serialised as JSON strings ──────────────────────────────

    /// <summary>JSON: string[]</summary>
    public required string AllowedGrantTypes { get; set; }

    /// <summary>JSON: string[]</summary>
    public required string RedirectUris { get; set; }

    /// <summary>JSON: string[]</summary>
    public required string PostLogoutRedirectUris { get; set; }

    /// <summary>JSON: string[]</summary>
    public required string AllowedCorsOrigins { get; set; }

    /// <summary>JSON: string[]</summary>
    public required string AllowedScopes { get; set; }

    /// <summary>JSON: ClientCredential[]</summary>
    public required string ClientCredentials { get; set; }

    /// <summary>JSON: ClientClaim[]</summary>
    public required string Claims { get; set; }

    // ── Authentication ──────────────────────────────────────────────────────

    [MaxLength(100)]
    public required string TokenEndpointAuthMethod { get; set; }

    public bool RequireClientSecret { get; set; } = true;

    /// <summary>JSON: ClientJwks? — inline JWKS for private_key_jwt.</summary>
    public string? JwksJson { get; set; }

    [MaxLength(2000)]
    public string? JwksUri { get; set; }

    // ── PKCE ────────────────────────────────────────────────────────────────

    public bool RequirePkce { get; set; } = true;

    // ── Grants ──────────────────────────────────────────────────────────────

    public bool AllowOfflineAccess { get; set; }

    // ── Lifetimes (stored as seconds) ───────────────────────────────────────

    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int AuthorizationCodeLifetimeSeconds { get; set; } = 300;
    public int RefreshTokenLifetimeSeconds { get; set; } = 2592000;
    public int IdentityTokenLifetimeSeconds { get; set; } = 300;

    // ── Token behaviour ─────────────────────────────────────────────────────

    public int RefreshTokenUsage { get; set; }     // TokenUsage enum
    public int RefreshTokenExpiration { get; set; } // TokenExpiration enum
    public int AccessTokenType { get; set; }        // AccessTokenType enum

    // ── Consent ─────────────────────────────────────────────────────────────

    public bool RequireConsent { get; set; } = true;
    public bool AllowRememberConsent { get; set; } = true;

    // ── Claims ──────────────────────────────────────────────────────────────

    public bool AlwaysIncludeUserClaimsInIdToken { get; set; }

    // ── Subject ─────────────────────────────────────────────────────────────

    public int SubjectType { get; set; } // SubjectType enum

    [MaxLength(500)]
    public string? PairwiseSectorIdentifierUri { get; set; }
}
