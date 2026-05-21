namespace SimpleAuth;

/// <summary>
/// Registered OAuth 2.1 / OIDC client.
/// All redirect URIs are validated by exact string match — no wildcards, no trailing-slash tolerance.
/// </summary>
public sealed class Client
{
    // ── Identity ────────────────────────────────────────────────────────────────

    /// <summary>Unique client identifier (<c>client_id</c> in RFC 6749 §2.2).</summary>
    public required string ClientId { get; init; }

    /// <summary>Human-readable display name shown in consent UI.</summary>
    public required string ClientName { get; init; }

    /// <summary>Optional description shown in consent and admin UI.</summary>
    public string? Description { get; init; }

    /// <summary>
    /// Whether this client is active. Disabled clients are rejected at every protocol endpoint.
    /// </summary>
    public bool Enabled { get; init; } = true;

    // ── Grant types ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Grant types this client may request.
    /// Allowed values: <see cref="GrantType.AuthorizationCode"/>,
    /// <see cref="GrantType.ClientCredentials"/>, <see cref="GrantType.RefreshToken"/>.
    /// </summary>
    public required IReadOnlyList<string> AllowedGrantTypes { get; init; }

    // ── Redirect URIs ───────────────────────────────────────────────────────────

    /// <summary>
    /// Registered redirect URIs. The <c>redirect_uri</c> in an authorization request
    /// MUST exactly match one entry — RFC 9700 §2.1.
    /// </summary>
    public IReadOnlyList<string> RedirectUris { get; init; } = [];

    /// <summary>Registered post-logout redirect URIs for end-session requests.</summary>
    public IReadOnlyList<string> PostLogoutRedirectUris { get; init; } = [];

    /// <summary>Origins allowed for CORS pre-flight on the token and revocation endpoints.</summary>
    public IReadOnlyList<string> AllowedCorsOrigins { get; init; } = [];

    // ── Authentication ──────────────────────────────────────────────────────────

    /// <summary>
    /// Token endpoint authentication method.
    /// Allowed values: <see cref="AuthMethod.ClientSecretBasic"/>,
    /// <see cref="AuthMethod.ClientSecretPost"/>, <see cref="AuthMethod.PrivateKeyJwt"/>,
    /// <see cref="AuthMethod.None"/>.
    /// </summary>
    public string TokenEndpointAuthMethod { get; init; } = AuthMethod.ClientSecretBasic;

    /// <summary>Whether this client must present a credential. Public clients set this to false.</summary>
    public bool RequireClientSecret { get; init; } = true;

    /// <summary>Hashed credentials for this client. See <see cref="ClientCredential"/>.</summary>
    public IReadOnlyList<ClientCredential> ClientCredentials { get; init; } = [];

    /// <summary>
    /// Inline JWKS for <c>private_key_jwt</c> authentication.
    /// Mutually exclusive with a remote JWKS URI.
    /// </summary>
    public ClientJwks? Jwks { get; init; }

    /// <summary>Remote JWKS URI for <c>private_key_jwt</c>. Fetched and cached at startup.</summary>
    public string? JwksUri { get; init; }

    // ── PKCE ────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Whether PKCE is required. Always true for public clients.
    /// Defaults to true for confidential clients as well per OAuth 2.1 best practice.
    /// </summary>
    public bool RequirePkce { get; init; } = true;

    // ── Scopes ──────────────────────────────────────────────────────────────────

    /// <summary>Scopes this client is allowed to request.</summary>
    public IReadOnlyList<string> AllowedScopes { get; init; } = [];

    /// <summary>
    /// Whether this client may request offline access (refresh tokens).
    /// Requires <c>offline_access</c> in <see cref="AllowedScopes"/> and
    /// <see cref="GrantType.RefreshToken"/> in <see cref="AllowedGrantTypes"/>.
    /// </summary>
    public bool AllowOfflineAccess { get; init; }

    // ── Token lifetimes ─────────────────────────────────────────────────────────

    /// <summary>Access token lifetime. Default: 1 hour.</summary>
    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Authorization code lifetime. Default: 5 minutes (RFC 6749 §4.1.2 recommends short).</summary>
    public TimeSpan AuthorizationCodeLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Refresh token absolute lifetime. Default: 30 days.</summary>
    public TimeSpan RefreshTokenLifetime { get; init; } = TimeSpan.FromDays(30);

    /// <summary>
    /// ID token lifetime. Must be short — the OIDC Core spec recommends minutes not hours.
    /// Default: 5 minutes.
    /// </summary>
    public TimeSpan IdentityTokenLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Refresh token usage strategy.</summary>
    public TokenUsage RefreshTokenUsage { get; init; } = TokenUsage.OneTimeOnly;

    /// <summary>Refresh token expiration strategy.</summary>
    public TokenExpiration RefreshTokenExpiration { get; init; } = TokenExpiration.Absolute;

    // ── Token format ────────────────────────────────────────────────────────────

    /// <summary>Format of issued access tokens.</summary>
    public AccessTokenType AccessTokenType { get; init; } = AccessTokenType.Jwt;

    // ── Claims ──────────────────────────────────────────────────────────────────

    /// <summary>Static claims always included in tokens for this client.</summary>
    public IReadOnlyList<ClientClaim> Claims { get; init; } = [];

    /// <summary>
    /// Whether to always include user claims in the ID token,
    /// even when a UserInfo endpoint call would suffice.
    /// </summary>
    public bool AlwaysIncludeUserClaimsInIdToken { get; init; }

    // ── Consent ─────────────────────────────────────────────────────────────────

    /// <summary>Whether this client requires explicit user consent. Default: true.</summary>
    public bool RequireConsent { get; init; } = true;

    /// <summary>Whether to remember consent across sessions for this client.</summary>
    public bool AllowRememberConsent { get; init; } = true;

    // ── Subject ─────────────────────────────────────────────────────────────────

    /// <summary>Subject identifier strategy. Default: public.</summary>
    public SubjectType SubjectType { get; init; } = SubjectType.Public;

    /// <summary>
    /// Sector identifier URI used to compute pairwise subjects (RFC OIDC Core §8.1).
    /// Required when <see cref="SubjectType"/> is <see cref="SubjectType.Pairwise"/>.
    /// </summary>
    public string? PairwiseSectorIdentifierUri { get; init; }
}
