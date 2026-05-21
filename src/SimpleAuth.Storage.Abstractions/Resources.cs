namespace SimpleAuth;

/// <summary>
/// An OAuth 2.0 scope as defined in RFC 6749 §3.3, associated with an API.
/// Scopes are the unit of access clients request and resource servers validate.
/// </summary>
public sealed class Scope
{
    /// <summary>Scope name as it appears in token requests (e.g., <c>"api1"</c>, <c>"read"</c>).</summary>
    public required string Name { get; init; }

    /// <summary>Human-readable display name for consent UI.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Human-readable description shown in consent UI.</summary>
    public string? Description { get; init; }

    /// <summary>Whether this scope is shown in discovery. Default: true.</summary>
    public bool ShowInDiscoveryDocument { get; init; } = true;

    /// <summary>Whether this scope is required. If false, the user may opt out in consent.</summary>
    public bool Required { get; init; }

    /// <summary>Whether to emphasize this scope on the consent page.</summary>
    public bool Emphasize { get; init; }

    /// <summary>Whether this scope is enabled. Disabled scopes are rejected at authorization.</summary>
    public bool Enabled { get; init; } = true;
}

/// <summary>
/// An identity scope mapping an OIDC scope name to the set of claims it grants.
/// Models the OIDC Core §5.4 standard claim scopes (<c>profile</c>, <c>email</c>, etc.)
/// as well as custom identity scopes.
/// </summary>
public sealed class IdentityScope
{
    /// <summary>Scope name (e.g., <c>"openid"</c>, <c>"profile"</c>, <c>"email"</c>).</summary>
    public required string Name { get; init; }

    /// <summary>Human-readable display name for consent UI.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Human-readable description shown in consent UI.</summary>
    public string? Description { get; init; }

    /// <summary>
    /// Claim types granted when this scope is requested.
    /// The claims are provided by <c>IClaimsEnricher</c> implementations.
    /// </summary>
    public IReadOnlyList<string> ClaimTypes { get; init; } = [];

    /// <summary>Whether this scope is required; users cannot uncheck it in consent.</summary>
    public bool Required { get; init; }

    /// <summary>Whether to emphasize this scope on the consent page.</summary>
    public bool Emphasize { get; init; }

    /// <summary>Whether this scope is shown in the discovery document.</summary>
    public bool ShowInDiscoveryDocument { get; init; } = true;

    /// <summary>Whether this scope is enabled.</summary>
    public bool Enabled { get; init; } = true;
}

/// <summary>
/// A protected resource as defined in RFC 8707 (Resource Indicators for OAuth 2.0).
/// A resource groups one or more <see cref="Scope"/> values and owns the credentials
/// used by resource servers to call the introspection endpoint.
/// </summary>
public sealed class ProtectedResource
{
    /// <summary>Unique resource name. Typically a URI matching the resource server audience.</summary>
    public required string Name { get; init; }

    /// <summary>Human-readable display name.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Scope names that belong to this resource.</summary>
    public IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>
    /// Credentials used by the resource server when calling the introspection endpoint.
    /// See <see cref="ResourceCredential"/>.
    /// </summary>
    public IReadOnlyList<ResourceCredential> ApiCredentials { get; init; } = [];

    /// <summary>Whether this resource is enabled.</summary>
    public bool Enabled { get; init; } = true;
}

/// <summary>
/// Standard OIDC scope names per OIDC Core §5.4.
/// Use these constants when registering default <see cref="IdentityScope"/> entries.
/// </summary>
public static class StandardScope
{
    /// <summary>The mandatory OpenID Connect scope. Triggers ID token issuance.</summary>
    public const string OpenId = "openid";

    /// <summary>Profile claims: <c>name</c>, <c>family_name</c>, <c>given_name</c>, etc.</summary>
    public const string Profile = "profile";

    /// <summary>Email claims: <c>email</c>, <c>email_verified</c>.</summary>
    public const string Email = "email";

    /// <summary>Address claim: <c>address</c>.</summary>
    public const string Address = "address";

    /// <summary>Phone claims: <c>phone_number</c>, <c>phone_number_verified</c>.</summary>
    public const string Phone = "phone";

    /// <summary>Offline access — enables refresh token issuance.</summary>
    public const string OfflineAccess = "offline_access";
}

/// <summary>
/// Standard OAuth 2.1 grant type names (RFC 6749 + OAuth 2.1 draft).
/// Only three grant types exist in OAuth 2.1; implicit and ROPC are removed.
/// </summary>
public static class GrantType
{
    /// <summary>Authorization Code grant with mandatory PKCE (OAuth 2.1 §4.1).</summary>
    public const string AuthorizationCode = "authorization_code";

    /// <summary>Client Credentials grant for machine-to-machine flows (OAuth 2.1 §4.2).</summary>
    public const string ClientCredentials = "client_credentials";

    /// <summary>Refresh Token grant (OAuth 2.1 §4.3). Requires <c>offline_access</c> scope.</summary>
    public const string RefreshToken = "refresh_token";
}

/// <summary>Token endpoint authentication method names per OIDC Discovery §3.</summary>
public static class AuthMethod
{
    /// <summary>HTTP Basic authentication with <c>client_id:client_secret</c> (RFC 6749 §2.3.1).</summary>
    public const string ClientSecretBasic = "client_secret_basic";

    /// <summary>Credentials in the request body as form parameters.</summary>
    public const string ClientSecretPost = "client_secret_post";

    /// <summary>Signed JWT assertion per RFC 7523.</summary>
    public const string PrivateKeyJwt = "private_key_jwt";

    /// <summary>No authentication — public clients only.</summary>
    public const string None = "none";
}

/// <summary>Pre-built standard <see cref="IdentityScope"/> registrations per OIDC Core §5.4.</summary>
public static class Resources
{
    /// <summary>The minimal set of standard identity scopes: openid, profile, email.</summary>
    public static IReadOnlyList<IdentityScope> Standard =>
    [
        new IdentityScope
        {
            Name = StandardScope.OpenId,
            DisplayName = "Your user identifier",
            Required = true,
        },
        new IdentityScope
        {
            Name = StandardScope.Profile,
            DisplayName = "Your profile information",
            Description = "Name, display name, and profile picture.",
            ClaimTypes = ["name", "family_name", "given_name", "middle_name", "nickname",
                          "preferred_username", "profile", "picture", "website",
                          "gender", "birthdate", "zoneinfo", "locale", "updated_at"],
            Emphasize = true,
        },
        new IdentityScope
        {
            Name = StandardScope.Email,
            DisplayName = "Your email address",
            ClaimTypes = ["email", "email_verified"],
            Emphasize = true,
        },
        new IdentityScope
        {
            Name = StandardScope.Address,
            DisplayName = "Your address",
            ClaimTypes = ["address"],
            Emphasize = true,
        },
        new IdentityScope
        {
            Name = StandardScope.Phone,
            DisplayName = "Your phone number",
            ClaimTypes = ["phone_number", "phone_number_verified"],
            Emphasize = true,
        },
    ];
}
