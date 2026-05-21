using System.Security.Claims;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Primitives;
using SimpleAuth.Crypto;
using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// Shared test server factory used by all conformance test classes.
/// Configures a server with multiple client types to cover the full OIDC surface.
/// </summary>
public sealed class ConformanceFixture : IAsyncLifetime
{
    private WebApplication? _app;

    public HttpClient Client { get; private set; } = null!;
    public string Issuer => "https://auth.conformance.test";

    public async Task InitializeAsync()
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();

        builder.Services.AddSimpleAuth(server =>
        {
            server.Issuer = Issuer;
            server.Keys.UseDevelopmentKey();
            server.Discovery.IncludeIntrospectionEndpoint = true;
            server.Discovery.IncludeRevocationEndpoint = true;
            server.Discovery.IncludeUserInfoEndpoint = true;

            server.Par.Enabled = true;
            server.Par.Required = false;

            server.RateLimit.Enabled = false;

            server.Store.UseInMemory(store =>
            {
                // ── Confidential client (client_secret_basic + client_secret_post) ──
                store.Clients.Add(new Client
                {
                    ClientId = "confidential-code",
                    ClientName = "Confidential Code Client",
                    AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
                    AllowedScopes = [StandardScope.OpenId, StandardScope.Profile, StandardScope.Email, StandardScope.OfflineAccess, "api"],
                    RedirectUris = ["https://client.example/callback", "https://client.example/callback2"],
                    PostLogoutRedirectUris = ["https://client.example/signout"],
                    RequireClientSecret = true,
                    RequirePkce = true,
                    AllowOfflineAccess = true,
                    AccessTokenType = AccessTokenType.Jwt,
                    RequireConsent = false,
                    ClientCredentials =
                    [
                        new ClientCredential { Type = "SharedSecret", Value = SecretHasher.Hash("secret123") },
                    ],
                });

                // ── Public client (no secret, PKCE required) ──
                store.Clients.Add(new Client
                {
                    ClientId = "public-spa",
                    ClientName = "Public SPA Client",
                    AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
                    AllowedScopes = [StandardScope.OpenId, StandardScope.Profile, StandardScope.Email, StandardScope.OfflineAccess],
                    RedirectUris = ["https://spa.example/callback"],
                    RequireClientSecret = false,
                    RequirePkce = true,
                    AllowOfflineAccess = true,
                    AccessTokenType = AccessTokenType.Reference,
                    RequireConsent = false,
                });

                // ── Client Credentials only ──
                store.Clients.Add(new Client
                {
                    ClientId = "m2m-service",
                    ClientName = "Machine Client",
                    AllowedGrantTypes = [GrantType.ClientCredentials],
                    AllowedScopes = ["api"],
                    RequireClientSecret = true,
                    ClientCredentials =
                    [
                        new ClientCredential { Type = "SharedSecret", Value = SecretHasher.Hash("m2m-secret") },
                    ],
                });

                // ── Client with private_key_jwt auth ──
                store.Clients.Add(new Client
                {
                    ClientId = "pkjwt-client",
                    ClientName = "Private Key JWT Client",
                    AllowedGrantTypes = [GrantType.ClientCredentials],
                    AllowedScopes = ["api"],
                    RequireClientSecret = false,
                    TokenEndpointAuthMethod = AuthMethod.PrivateKeyJwt,
                    ClientCredentials = [],
                });

                // ── Scopes ──
                store.Scopes.Add(new Scope { Name = "api", DisplayName = "API Access" });

                // ── Identity scopes ──
                foreach (IdentityScope scope in Resources.Standard)
                {
                    store.IdentityScopes.Add(scope);
                }
            });
        });

        // Claims enricher that returns profile + email claims
        builder.Services.AddSingleton<IClaimsEnricher, TestClaimsEnricher>();

        _app = builder.Build();

        // Test auth middleware: X-Test-User header injects authenticated user
        _app.Use(async (ctx, next) =>
        {
            if (ctx.Request.Headers.TryGetValue("X-Test-User", out StringValues sub) &&
                !StringValues.IsNullOrEmpty(sub))
            {
                ctx.User = new ClaimsPrincipal(
                    new ClaimsIdentity(
                    [
                        new Claim("sub", sub.ToString()),
                        new Claim("name", $"Test User {sub}"),
                        new Claim("email", $"{sub}@test.example"),
                        new Claim("email_verified", "true"),
                    ], "test"));
            }

            await next(ctx);
        });

        _app.MapSimpleAuth();
        await _app.StartAsync();

        Client = _app.GetTestClient();
        Client.BaseAddress = new Uri("http://localhost");
    }

    public async Task DisposeAsync()
    {
        Client.Dispose();
        if (_app is not null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }
}

/// <summary>Test claims enricher providing profile and email claims.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:AvoidUninstantiatedInternalClasses", Justification = "DI.")]
internal sealed class TestClaimsEnricher : IClaimsEnricher
{
    public ValueTask EnrichAsync(ClaimsEnrichmentContext context, CancellationToken cancellationToken = default)
    {
        if (context.GrantedScopes.Contains(StandardScope.Profile, StringComparer.Ordinal))
        {
            context.Claims.Add(new Claim("name", $"Test User {context.SubjectId}"));
            context.Claims.Add(new Claim("preferred_username", context.SubjectId));
        }

        if (context.GrantedScopes.Contains(StandardScope.Email, StringComparer.Ordinal))
        {
            context.Claims.Add(new Claim("email", $"{context.SubjectId}@test.example"));
            context.Claims.Add(new Claim("email_verified", "true"));
        }

        return ValueTask.CompletedTask;
    }
}
