using Microsoft.EntityFrameworkCore;
using SimpleAuth;
using SimpleAuth.EntityFramework;
using SimpleAuth.Sample.Full;

// ── Builder ──────────────────────────────────────────────────────────────────

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// ── EF Core (SQLite) ──────────────────────────────────────────────────────────

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(
        builder.Configuration.GetConnectionString("SimpleAuth")
        ?? "Data Source=simpleauth.db"));

// ── SimpleAuth ────────────────────────────────────────────────────────────────
//
// Clients and API scopes are configured statically in-memory.
// Authorization codes, refresh tokens, access tokens, PAR entries, JTIs, and
// user consents are persisted in SQLite via EF Core.
//
builder.Services.AddSimpleAuth(server =>
{
    server.Issuer = builder.Configuration["SimpleAuth:Issuer"] ?? "https://localhost:5001";

    // ── Development key — replace with a persisted key in production ──────
    server.Keys.UseDevelopmentKey();

    server.Store.UseInMemory(store =>
    {
        // ── Browser app: Authorization Code + PKCE ────────────────────────
        store.Clients.Add(new Client
        {
            ClientId = "webapp",
            ClientName = "Demo Web App",
            AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            RedirectUris = ["https://localhost:5002/signin-oidc"],
            PostLogoutRedirectUris = ["https://localhost:5002/signout-callback-oidc"],
            AllowedScopes = [StandardScope.OpenId, StandardScope.Profile, StandardScope.Email, "api1"],
            AllowOfflineAccess = true,
            RequireConsent = true,
            ClientCredentials =
            [
                // Use SecretHasher.Hash("webapp_secret") to generate this value
                new ClientCredential
                {
                    Type = "SharedSecret",
                    Value = "A6BDE26DB3DAB9649ADDC9F5BF8F0A93A39D28F5BA79CC7ACCFDB3DFA4C00C84",
                },
            ],
        });

        // ── Machine-to-machine: Client Credentials ────────────────────────
        store.Clients.Add(new Client
        {
            ClientId = "m2m",
            ClientName = "Background Service",
            AllowedGrantTypes = [GrantType.ClientCredentials],
            AllowedScopes = ["api1"],
            RequireConsent = false,
            ClientCredentials =
            [
                new ClientCredential
                {
                    Type = "SharedSecret",
                    Value = "B74A5D2E71C13988E0F8D1B89402D5E9F6B3DA4C02E93CC8ADCFDB3DFA4C00C8",
                },
            ],
        });

        // ── OIDC identity scopes ──────────────────────────────────────────
        foreach (IdentityScope scope in Resources.Standard)
        {
            store.IdentityScopes.Add(scope);
        }

        // ── API scope ─────────────────────────────────────────────────────
        store.Scopes.Add(new Scope
        {
            Name = "api1",
            DisplayName = "Demo API",
            Description = "Access to the demo API.",
        });
    });
});

// Override only the transactional stores with EF Core (codes, tokens, PAR, consent, JTIs).
// Clients, resources, and signing keys remain in-memory.
builder.Services.AddSimpleAuthEntityFrameworkTransactionalStores<AppDbContext>();

// Register a claims enricher to inject user profile claims into ID tokens / UserInfo
builder.Services.AddSingleton<IClaimsEnricher, SampleClaimsEnricher>();

// ── Build ─────────────────────────────────────────────────────────────────────

WebApplication app = builder.Build();

// ── Apply EF migrations on startup ───────────────────────────────────────────

using (IServiceScope scope = app.Services.CreateScope())
{
    AppDbContext db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.MigrateAsync();
}

// ── Middleware ────────────────────────────────────────────────────────────────

app.MapSimpleAuth();

// ── Demo protected API endpoint ───────────────────────────────────────────────

app.MapGet("/api/hello", HandleApiHello);

static async Task HandleApiHello(HttpContext ctx)
{
    string? auth = ctx.Request.Headers.Authorization.ToString();

    if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        ctx.Response.StatusCode = 401;
        return;
    }

    await ctx.Response.WriteAsync($"Hello! Token: {auth[7..20]}…");
}

app.MapGet("/", () => Results.Redirect("/.well-known/openid-configuration"));

await app.RunAsync();

// ── Claims enricher ───────────────────────────────────────────────────────────

[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:AvoidUninstantiatedInternalClasses", Justification = "Instantiated by DI.")]
internal sealed class SampleClaimsEnricher : IClaimsEnricher
{
    public ValueTask EnrichAsync(ClaimsEnrichmentContext context, CancellationToken cancellationToken = default)
    {
        if (context.GrantedScopes.Contains(StandardScope.Profile, StringComparer.Ordinal))
        {
            context.Claims.Add(new System.Security.Claims.Claim("name", $"User {context.SubjectId}"));
            context.Claims.Add(new System.Security.Claims.Claim("preferred_username", context.SubjectId));
        }

        if (context.GrantedScopes.Contains(StandardScope.Email, StringComparer.Ordinal))
        {
            context.Claims.Add(new System.Security.Claims.Claim("email", $"{context.SubjectId}@example.com"));
            context.Claims.Add(new System.Security.Claims.Claim("email_verified", "true"));
        }

        return ValueTask.CompletedTask;
    }
}
