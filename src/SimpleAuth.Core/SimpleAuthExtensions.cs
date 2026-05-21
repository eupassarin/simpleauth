using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SimpleAuth.Configuration;
using SimpleAuth.Crypto;
using SimpleAuth.Endpoints;
using SimpleAuth.Serialization;

namespace SimpleAuth;

/// <summary>
/// Entry-point extensions for wiring SimpleAuth into ASP.NET Core.
/// </summary>
public static class SimpleAuthExtensions
{
    /// <summary>
    /// Registers SimpleAuth services using the provided configuration lambda.
    /// </summary>
    public static IServiceCollection AddSimpleAuth(
        this IServiceCollection services,
        Action<SimpleAuthServerConfiguration> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var configuration = new SimpleAuthServerConfiguration();
        configure(configuration);
        configuration.Validate();

        var signingKey = BuildSigningKey(configuration);
        ReadOnlyMemory<byte> jwks = BuildJwks(signingKey);
        ReadOnlyMemory<byte> discovery = BuildDiscovery(configuration);

        var clientStore = new InMemoryClientStore(configuration.Store.InMemory.Clients);
        var resourceStore = new InMemoryResourceStore(
            configuration.Store.InMemory.Scopes,
            configuration.Store.InMemory.IdentityScopes,
            configuration.Store.InMemory.Resources);
        var authorizationCodeStore = new InMemoryAuthorizationCodeStore(configuration.Store.InMemory.AuthorizationCodes);
        var refreshTokenStore = new InMemoryRefreshTokenStore(configuration.Store.InMemory.RefreshTokens);
        var tokenStore = new InMemoryTokenStore(configuration.Store.InMemory.IssuedTokens);
        var signingKeyInfo = CreateSigningKeyInfo(signingKey, configuration.Issuer);
        var signingKeyStore = new InMemorySigningKeyStore([signingKeyInfo, .. configuration.Store.InMemory.SigningKeys]);
        var jtiStore = new InMemoryJtiStore();
        var consentStore = new InMemoryConsentStore();

        services.AddSingleton(configuration);
        services.AddSingleton(signingKey);
        services.AddSingleton(new SimpleAuthServerState(configuration.Issuer, discovery, jwks));
        services.AddSingleton<IClientStore>(clientStore);
        services.AddSingleton<IResourceStore>(resourceStore);
        services.AddSingleton<IAuthorizationCodeStore>(authorizationCodeStore);
        services.AddSingleton<IRefreshTokenStore>(refreshTokenStore);
        services.AddSingleton<ITokenStore>(tokenStore);
        services.AddSingleton<ISigningKeyStore>(signingKeyStore);
        services.AddSingleton<IJtiStore>(jtiStore);
        services.AddSingleton<IConsentStore>(consentStore);
        services.AddSingleton<IParStore>(new InMemoryParStore());
        services.AddSingleton(provider => new JwtService(configuration.Issuer, provider.GetRequiredService<SigningKeyHolder>()));

        if (configuration.Interaction.EnableBuiltInPages)
        {
            services.AddAuthentication(configuration.Interaction.CookieScheme)
                .AddCookie(configuration.Interaction.CookieScheme, options =>
                {
                    options.LoginPath = configuration.Interaction.LoginPath;
                    options.Cookie.Name = "SimpleAuth.Session";
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SameSite = SameSiteMode.Lax;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    options.ExpireTimeSpan = TimeSpan.FromHours(8);
                });
        }

        if (configuration.RateLimit.Enabled)
        {
            RegisterRateLimiter(services, configuration.RateLimit);
        }

        return services;
    }

    /// <summary>
    /// Maps the SimpleAuth HTTP endpoints into the app pipeline.
    /// </summary>
    public static WebApplication MapSimpleAuth(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var configuration = app.Services.GetRequiredService<SimpleAuthServerConfiguration>();

        if (configuration.Interaction.EnableBuiltInPages)
        {
            app.UseAuthentication();
        }

        if (configuration.RateLimit.Enabled)
        {
            app.UseRateLimiter();
        }

        app.MapSimpleAuthWellKnown();
        app.MapSimpleAuthConnect();

        if (configuration.Interaction.EnableBuiltInPages)
        {
            app.MapGet(configuration.Interaction.LoginPath, InteractionEndpoints.HandleLoginAsync);
            app.MapPost(configuration.Interaction.LoginPath, InteractionEndpoints.HandleLoginAsync);
            app.MapGet(configuration.Interaction.ConsentPath, InteractionEndpoints.HandleConsentAsync);
            app.MapPost(configuration.Interaction.ConsentPath, InteractionEndpoints.HandleConsentAsync);
            app.MapGet("/account/logout", InteractionEndpoints.HandleLogoutAsync);
            app.MapPost("/account/logout", InteractionEndpoints.HandleLogoutAsync);
        }

        return app;
    }

    private static void RegisterRateLimiter(IServiceCollection services, RateLimitConfiguration cfg)
    {
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = cfg.RejectionStatusCode;

            // Token endpoint: tight limit, keyed per IP.
            options.AddPolicy(RateLimitPolicyNames.Token, context =>
            {
                string partitionKey = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = cfg.TokenPermitLimit,
                    Window = cfg.TokenWindow,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0,
                });
            });

            // Authorize endpoint: slightly more lenient, keyed per IP.
            options.AddPolicy(RateLimitPolicyNames.Authorize, context =>
            {
                string partitionKey = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = cfg.AuthorizePermitLimit,
                    Window = cfg.AuthorizeWindow,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0,
                });
            });
        });
    }

    private static SigningKeyHolder BuildSigningKey(SimpleAuthServerConfiguration configuration)
    {
        if (configuration.Keys.EcKey is not null && !string.IsNullOrWhiteSpace(configuration.Keys.KeyId))
        {
            return SigningKeyHolder.FromEcKey(configuration.Keys.EcKey, configuration.Keys.KeyId);
        }

        if (configuration.Keys.RsaKey is not null && !string.IsNullOrWhiteSpace(configuration.Keys.KeyId))
        {
            return SigningKeyHolder.FromRsaKey(configuration.Keys.RsaKey, configuration.Keys.KeyId);
        }

        return configuration.Keys.BuildSigningKeyHolder();
    }

    private static ReadOnlyMemory<byte> BuildJwks(SigningKeyHolder signingKey)
    {
        if (signingKey.Key is ECDsa ecKey)
        {
            string kid = signingKey.KeyId;
            Jwk jwk = JwkSerializer.FromEcKey(ecKey, kid, signingKey.Algorithm);
            return JwkSerializer.BuildJwks([jwk]);
        }

        if (signingKey.Key is RSA rsaKey)
        {
            string kid = signingKey.KeyId;
            Jwk jwk = JwkSerializer.FromRsaKey(rsaKey, kid, signingKey.Algorithm);
            return JwkSerializer.BuildJwks([jwk]);
        }

        throw new InvalidOperationException("Unsupported signing key type.");
    }

    private static ReadOnlyMemory<byte> BuildDiscovery(SimpleAuthServerConfiguration configuration)
    {
        string baseUrl = configuration.Issuer.TrimEnd('/');
        var document = new DiscoveryDocument
        {
            Issuer = configuration.Issuer,
            AuthorizationEndpoint = $"{baseUrl}/connect/authorize",
            TokenEndpoint = $"{baseUrl}/connect/token",
            UserInfoEndpoint = configuration.Discovery.IncludeUserInfoEndpoint ? $"{baseUrl}/connect/userinfo" : null,
            JwksUri = $"{baseUrl}/.well-known/jwks.json",
            EndSessionEndpoint = $"{baseUrl}/connect/endsession",
            IntrospectionEndpoint = configuration.Discovery.IncludeIntrospectionEndpoint ? $"{baseUrl}/connect/introspect" : null,
            RevocationEndpoint = configuration.Discovery.IncludeRevocationEndpoint ? $"{baseUrl}/connect/revocation" : null,
            ResponseTypesSupported = ["code"],
            ResponseModesSupported = ["query", "form_post"],
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.ClientCredentials, GrantType.RefreshToken],
            SubjectTypesSupported = ["public", "pairwise"],
            IdTokenSigningAlgValuesSupported = [configuration.Keys.Algorithm ?? "ES256"],
            ScopesSupported = [StandardScope.OpenId, StandardScope.Profile, StandardScope.Email, StandardScope.Address, StandardScope.Phone, StandardScope.OfflineAccess],
            TokenEndpointAuthMethodsSupported = [AuthMethod.ClientSecretBasic, AuthMethod.ClientSecretPost, AuthMethod.PrivateKeyJwt, AuthMethod.None],
            ClaimsSupported = ["sub", "iss", "aud", "exp", "iat", "nonce", "name", "email", "email_verified"],
            CodeChallengeMethodsSupported = ["S256"],
            PushedAuthorizationRequestEndpoint = configuration.Par.Enabled ? $"{baseUrl}/connect/par" : null,
            RequirePushedAuthorizationRequests = configuration.Par.Enabled && configuration.Par.Required ? true : null,
            DPopSigningAlgValuesSupported = ["ES256", "ES384", "RS256", "RS384", "PS256"],
        };

        return new ReadOnlyMemory<byte>(JsonSerializer.SerializeToUtf8Bytes(document, AuthJsonContext.Default.DiscoveryDocument));
    }

    private static SigningKeyInfo CreateSigningKeyInfo(SigningKeyHolder signingKey, string issuer)
    {
        DateTime createdAt = DateTime.UtcNow;
        DateTime retireAt = createdAt.AddHours(12);
        DateTime removeAt = createdAt.AddDays(7);

        if (signingKey.Key is ECDsa ecKey)
        {
            return new SigningKeyInfo
            {
                KeyId = signingKey.KeyId,
                Algorithm = signingKey.Algorithm,
                PrivateKeyPem = SigningKeyGenerator.ExportEcPrivateKeyPem(ecKey),
                CreatedAt = createdAt,
                RetireAt = retireAt,
                RemoveAt = removeAt,
                IsPrimary = true,
            };
        }

        if (signingKey.Key is RSA rsaKey)
        {
            return new SigningKeyInfo
            {
                KeyId = signingKey.KeyId,
                Algorithm = signingKey.Algorithm,
                PrivateKeyPem = SigningKeyGenerator.ExportRsaPrivateKeyPem(rsaKey),
                CreatedAt = createdAt,
                RetireAt = retireAt,
                RemoveAt = removeAt,
                IsPrimary = true,
            };
        }

        throw new InvalidOperationException($"Unsupported signing key type for issuer '{issuer}'.");
    }
}

/// <summary>Internal singleton state for cached discovery and JWKS documents.</summary>
internal sealed class SimpleAuthServerState
{
    /// <summary>Creates the server state.</summary>
    internal SimpleAuthServerState(string issuer, ReadOnlyMemory<byte> discoveryJson, ReadOnlyMemory<byte> jwksJson)
    {
        Issuer = issuer;
        DiscoveryJson = discoveryJson;
        JwksJson = jwksJson;
    }

    /// <summary>Issuer URL.</summary>
    internal string Issuer { get; }

    /// <summary>Cached discovery JSON bytes.</summary>
    internal ReadOnlyMemory<byte> DiscoveryJson { get; }

    /// <summary>Cached JWKS JSON bytes.</summary>
    internal ReadOnlyMemory<byte> JwksJson { get; }
}

/// <summary>Named rate-limiter policies used by SimpleAuth endpoints.</summary>
internal static class RateLimitPolicyNames
{
    internal const string Token = "simpleauth-token";
    internal const string Authorize = "simpleauth-authorize";
}
