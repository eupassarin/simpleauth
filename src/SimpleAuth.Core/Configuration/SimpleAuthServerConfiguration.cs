using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using SimpleAuth.Crypto;

namespace SimpleAuth.Configuration;

/// <summary>
/// Top-level configuration object passed to <c>AddSimpleAuth</c>.
/// </summary>
public sealed class SimpleAuthServerConfiguration
{
    /// <summary>Issuer URL for tokens and discovery.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>Store-related configuration.</summary>
    public StoreConfiguration Store { get; } = new();

    /// <summary>Signing-key configuration.</summary>
    public KeyConfiguration Keys { get; } = new();

    /// <summary>Discovery document configuration.</summary>
    public DiscoveryConfiguration Discovery { get; } = new();

    /// <summary>Rate-limit configuration for the protocol endpoints.</summary>
    public RateLimitConfiguration RateLimit { get; } = new();

    /// <summary>Pushed Authorization Request (RFC 9126) configuration.</summary>
    public PushedAuthorizationConfiguration Par { get; } = new();

    /// <summary>User interaction (login/consent) configuration.</summary>
    public InteractionConfiguration Interaction { get; } = new();

    /// <summary>Validates the configuration before the server starts.</summary>
    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            throw new InvalidOperationException("SimpleAuth requires a non-empty issuer.");
        }

        // OIDC Discovery §3: Issuer MUST be an HTTPS URL (localhost permitted for development).
        if (!Uri.TryCreate(Issuer, UriKind.Absolute, out Uri? issuerUri) ||
            (issuerUri.Scheme != "https" && issuerUri.Host != "localhost"))
        {
            throw new InvalidOperationException("Issuer must be an absolute HTTPS URL (http is only allowed for localhost development).");
        }

        Keys.EnsureConfigured();
    }
}

/// <summary>Configuration for stores.</summary>
public sealed class StoreConfiguration
{
    /// <summary>In-memory seed data used for development and tests.</summary>
    public InMemoryStoreConfiguration InMemory { get; } = new();

    /// <summary>Configures the server to use in-memory stores.</summary>
    public void UseInMemory(Action<InMemoryStoreConfiguration>? configure = null) => configure?.Invoke(InMemory);
}

/// <summary>Seed data for the in-memory store package.</summary>
public sealed class InMemoryStoreConfiguration
{
    /// <summary>Seed clients.</summary>
    public List<Client> Clients { get; } = [];

    /// <summary>Seed scopes.</summary>
    public List<Scope> Scopes { get; } = [];

    /// <summary>Seed identity scopes.</summary>
    public List<IdentityScope> IdentityScopes { get; } = [];

    /// <summary>Seed protected resources.</summary>
    public List<ProtectedResource> Resources { get; } = [];

    /// <summary>Seed authorization codes.</summary>
    public List<AuthorizationCode> AuthorizationCodes { get; } = [];

    /// <summary>Seed refresh tokens.</summary>
    public List<RefreshToken> RefreshTokens { get; } = [];

    /// <summary>Seed issued tokens.</summary>
    public List<IssuedToken> IssuedTokens { get; } = [];

    /// <summary>Seed signing keys.</summary>
    public List<SigningKeyInfo> SigningKeys { get; } = [];

    /// <summary>Seed consents.</summary>
    public List<UserConsent> Consents { get; } = [];
}

/// <summary>Configuration for the signing key material.</summary>
public sealed class KeyConfiguration
{
    /// <summary>Configured EC development key, if any.</summary>
    public ECDsa? EcKey { get; private set; }

    /// <summary>Configured RSA development key, if any.</summary>
    public RSA? RsaKey { get; private set; }

    /// <summary>Configured key identifier.</summary>
    public string? KeyId { get; private set; }

    /// <summary>Configured algorithm name.</summary>
    public string? Algorithm { get; private set; }

    /// <summary>Configures a throwaway EC P-256 development key.</summary>
    public void UseDevelopmentKey()
    {
        EcKey?.Dispose();
        RsaKey?.Dispose();
        (EcKey, KeyId) = SigningKeyGenerator.CreateEcKey();
        RsaKey = null;
        Algorithm = "ES256";
    }

    /// <summary>Configures a throwaway RSA-2048 development key.</summary>
    public void UseDevelopmentRsaKey()
    {
        EcKey?.Dispose();
        RsaKey?.Dispose();
        (RsaKey, KeyId) = SigningKeyGenerator.CreateRsaKey();
        EcKey = null;
        Algorithm = "RS256";
    }

    /// <summary>Creates the active signing key holder.</summary>
    internal SigningKeyHolder BuildSigningKeyHolder()
    {
        if (EcKey is not null && KeyId is not null)
        {
            return SigningKeyHolder.FromEcKey(EcKey, KeyId);
        }

        if (RsaKey is not null && KeyId is not null)
        {
            return SigningKeyHolder.FromRsaKey(RsaKey, KeyId);
        }

        UseDevelopmentKey();
        return BuildSigningKeyHolder();
    }

    /// <summary>Ensures some signing key has been configured.</summary>
    internal void EnsureConfigured()
    {
        if (EcKey is null && RsaKey is null)
        {
            UseDevelopmentKey();
        }
    }
}

/// <summary>Discovery-document behavior toggles.</summary>
public sealed class DiscoveryConfiguration
{
    /// <summary>Whether the authorize endpoint should be advertised.</summary>
    public bool IncludeAuthorizationEndpoint { get; set; } = true;

    /// <summary>Whether to advertise the userinfo endpoint.</summary>
    public bool IncludeUserInfoEndpoint { get; set; } = true;

    /// <summary>Whether to advertise the introspection endpoint.</summary>
    public bool IncludeIntrospectionEndpoint { get; set; }

    /// <summary>Whether to advertise the revocation endpoint.</summary>
    public bool IncludeRevocationEndpoint { get; set; }
}

/// <summary>Rate-limit settings for the protocol endpoints.</summary>
public sealed class RateLimitConfiguration
{
    /// <summary>
    /// Whether rate limiting is enabled. Defaults to <see langword="true"/>.
    /// Set to <see langword="false"/> to disable entirely (e.g., in tests).
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Maximum token-endpoint requests allowed per <see cref="TokenWindow"/> per IP address.
    /// Defaults to 20.
    /// </summary>
    public int TokenPermitLimit { get; set; } = 20;

    /// <summary>Sliding window for the token-endpoint rate limit. Defaults to 1 minute.</summary>
    public TimeSpan TokenWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Maximum authorize-endpoint requests allowed per <see cref="AuthorizeWindow"/> per IP address.
    /// Defaults to 30.
    /// </summary>
    public int AuthorizePermitLimit { get; set; } = 30;

    /// <summary>Sliding window for the authorize-endpoint rate limit. Defaults to 1 minute.</summary>
    public TimeSpan AuthorizeWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>HTTP status code returned when the limit is exceeded. Defaults to 429.</summary>
    public int RejectionStatusCode { get; set; } = StatusCodes.Status429TooManyRequests;
}

/// <summary>Pushed Authorization Request (RFC 9126) settings.</summary>
public sealed class PushedAuthorizationConfiguration
{
    /// <summary>
    /// Whether the PAR endpoint (<c>POST /connect/par</c>) is enabled.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// When <see langword="true"/>, all authorize requests MUST use PAR.
    /// Direct calls to <c>/connect/authorize</c> without a <c>request_uri</c> are rejected.
    /// Defaults to <see langword="false"/>.
    /// </summary>
    public bool Required { get; set; }

    /// <summary>
    /// How long a PAR entry lives before the authorize endpoint must consume it.
    /// RFC 9126 §2.2 recommends between 5 s and 600 s.
    /// Defaults to 90 seconds.
    /// </summary>
    public TimeSpan RequestLifetime { get; set; } = TimeSpan.FromSeconds(90);
}

/// <summary>Configuration for user interaction pages (login, consent, error).</summary>
public sealed class InteractionConfiguration
{
    /// <summary>Path to the login page. Default: "/account/login".</summary>
    public string LoginPath { get; set; } = "/account/login";

    /// <summary>Path to the consent page. Default: "/account/consent".</summary>
    public string ConsentPath { get; set; } = "/account/consent";

    /// <summary>Path to the error page. Default: "/account/error".</summary>
    public string ErrorPath { get; set; } = "/account/error";

    /// <summary>Name of the query parameter used to pass the return URL. Default: "returnUrl".</summary>
    public string ReturnUrlParameter { get; set; } = "returnUrl";

    /// <summary>
    /// Whether to enable the built-in minimal login/consent UI pages.
    /// Set to false if you provide your own pages.
    /// Default: true.
    /// </summary>
    public bool EnableBuiltInPages { get; set; } = true;

    /// <summary>Cookie authentication scheme name used by SimpleAuth. Default: "SimpleAuth.Cookie".</summary>
    public string CookieScheme { get; set; } = "SimpleAuth.Cookie";
}
