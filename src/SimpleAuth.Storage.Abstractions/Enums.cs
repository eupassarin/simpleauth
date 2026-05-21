namespace SimpleAuth;

/// <summary>Controls whether a refresh token can be reused or is one-time-only.</summary>
public enum TokenUsage
{
    /// <summary>The refresh token can be reused multiple times until expiry.</summary>
    ReUse,

    /// <summary>The refresh token is invalidated after a single use; a new one is issued.</summary>
    OneTimeOnly,
}

/// <summary>Controls whether a token's lifetime extends on activity.</summary>
public enum TokenExpiration
{
    /// <summary>Token expires at a fixed point regardless of activity.</summary>
    Absolute,

    /// <summary>Token lifetime resets on each successful use.</summary>
    Sliding,
}

/// <summary>Format of an issued access token.</summary>
public enum AccessTokenType
{
    /// <summary>JWT access token — self-contained, verifiable without introspection.</summary>
    Jwt,

    /// <summary>Opaque reference token — requires introspection to validate.</summary>
    Reference,
}

/// <summary>Pairwise or public subject identifier strategy per OIDC Core §8.</summary>
public enum SubjectType
{
    /// <summary>The same <c>sub</c> is returned to all clients.</summary>
    Public,

    /// <summary>
    /// A client-specific <c>sub</c> is derived from the sector identifier.
    /// Computed as <c>BASE64URL(HMAC-SHA256(sector_identifier + public_sub, pairwise_salt))</c>.
    /// </summary>
    Pairwise,
}

/// <summary>Indicates which token type triggered a claims enrichment request.</summary>
public enum ClaimsSource
{
    /// <summary>Claims are being added to an ID token.</summary>
    IdentityToken,

    /// <summary>Claims are being added to a JWT access token.</summary>
    AccessToken,

    /// <summary>Claims are being returned from the UserInfo endpoint.</summary>
    UserInfo,
}
