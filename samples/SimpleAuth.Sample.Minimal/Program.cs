using SimpleAuth;

// ──────────────────────────────────────────────────────────────────────────────
// SimpleAuth — Minimal Sample
// OAuth 2.1 + OpenID Connect server in ~40 lines of code.
// ──────────────────────────────────────────────────────────────────────────────

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddSimpleAuth(server =>
{
    server.Issuer = "https://localhost:5001";

    server.Keys.UseDevelopmentKey(); // EC P-256, throw-away key — use a real key in production.

    server.Store.UseInMemory(store =>
    {
        // Machine-to-machine client (client_credentials grant).
        store.Clients.Add(new Client
        {
            ClientId = "m2m-client",
            ClientName = "Machine-to-Machine Client",
            AllowedGrantTypes = [GrantType.ClientCredentials],
            AllowedScopes = ["api"],
            RequireClientSecret = true,
            ClientCredentials =
            [
                new ClientCredential
                {
                    Type = "SharedSecret",
                    // Hashed value of "super-secret" — use SecretHasher.Hash("…") to generate.
                    Value = "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
                },
            ],
        });

        // Interactive browser client (authorization_code + PKCE).
        store.Clients.Add(new Client
        {
            ClientId = "webapp",
            ClientName = "Web Application",
            AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            AllowedScopes = [StandardScope.OpenId, StandardScope.OfflineAccess, "api"],
            RedirectUris = ["https://localhost:5002/signin-oidc"],
            PostLogoutRedirectUris = ["https://localhost:5002/signout-callback-oidc"],
            RequireClientSecret = false,
            RequirePkce = true,
            AllowOfflineAccess = true,
            AccessTokenType = AccessTokenType.Reference,
        });

        // A scope that protects the sample API.
        store.Scopes.Add(new Scope
        {
            Name = "api",
            DisplayName = "Sample API",
            Description = "Access to the sample API.",
        });
    });

    server.Discovery.IncludeIntrospectionEndpoint = true;
    server.Discovery.IncludeRevocationEndpoint = true;
});

// Optionally register a custom claims enricher — IClaimsEnricher implementations
// are called before every ID token and UserInfo response.
builder.Services.AddSingleton<IClaimsEnricher, SampleClaimsEnricher>();

WebApplication app = builder.Build();

// Expose all SimpleAuth endpoints under /.well-known/* and /connect/*.
app.MapSimpleAuth();

// A minimal protected resource — validates the bearer token via the TokenStore.
app.MapGet("/api/hello", HandleApiHello);

await app.RunAsync();

static Task HandleApiHello(HttpContext ctx)
{
    string? auth = ctx.Request.Headers.Authorization.ToString();
    if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        ctx.Response.StatusCode = 401;
        return Task.CompletedTask;
    }

    return ctx.Response.WriteAsync("Hello from the protected API!");
}

// ──────────────────────────────────────────────────────────────────────────────
// Sample claims enricher — adds user profile claims from an external source.
// Replace with your database / LDAP / gRPC call in a real application.
// ──────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Demonstrates how to inject custom identity claims into every
/// ID token and UserInfo response via <see cref="IClaimsEnricher"/>.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:AvoidUninstantiatedInternalClasses", Justification = "Instantiated by DI.")]
internal sealed class SampleClaimsEnricher : IClaimsEnricher
{
    public ValueTask EnrichAsync(ClaimsEnrichmentContext context, System.Threading.CancellationToken cancellationToken = default)
    {
        // Add claims based on the requested scopes.
        if (context.GrantedScopes.Contains(StandardScope.Profile, System.StringComparer.Ordinal))
        {
            context.Claims.Add(new System.Security.Claims.Claim("name", $"User {context.SubjectId}"));
            context.Claims.Add(new System.Security.Claims.Claim("preferred_username", context.SubjectId));
        }

        if (context.GrantedScopes.Contains(StandardScope.Email, System.StringComparer.Ordinal))
        {
            context.Claims.Add(new System.Security.Claims.Claim("email", $"{context.SubjectId}@example.com"));
            context.Claims.Add(new System.Security.Claims.Claim("email_verified", "true"));
        }

        return ValueTask.CompletedTask;
    }
}
