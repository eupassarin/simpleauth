using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using SimpleAuth;
using SimpleAuth.Crypto;

// ──────────────────────────────────────────────────────────────────────────────
// SimpleAuth — OpenID Foundation Conformance Suite Deployment
//
// This sample is specifically configured to run against the OpenID Foundation
// Conformance Suite at https://www.certification.openid.net/
//
// It pre-registers the test clients that the conformance suite uses and
// provides an auto-login mechanism for automated testing.
//
// Deploy this to a publicly accessible URL, then configure the conformance
// suite to point to it.
// ──────────────────────────────────────────────────────────────────────────────

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Read configuration from environment or appsettings
string issuer = builder.Configuration["SimpleAuth:Issuer"]
    ?? Environment.GetEnvironmentVariable("SIMPLEAUTH_ISSUER")
    ?? "https://localhost:5001";

string testUserSub = builder.Configuration["SimpleAuth:TestUser:Sub"]
    ?? Environment.GetEnvironmentVariable("SIMPLEAUTH_TEST_USER_SUB")
    ?? "test-user";

string testUserName = builder.Configuration["SimpleAuth:TestUser:Name"]
    ?? Environment.GetEnvironmentVariable("SIMPLEAUTH_TEST_USER_NAME")
    ?? "Test User";

string testUserEmail = builder.Configuration["SimpleAuth:TestUser:Email"]
    ?? Environment.GetEnvironmentVariable("SIMPLEAUTH_TEST_USER_EMAIL")
    ?? "test@simpleauth.dev";

// The conformance suite redirect URIs (configured when creating the test plan)
string conformanceSuiteBase = builder.Configuration["SimpleAuth:ConformanceSuite:BaseUrl"]
    ?? Environment.GetEnvironmentVariable("SIMPLEAUTH_CONFORMANCE_BASE")
    ?? "https://www.certification.openid.net";

builder.Services.AddSimpleAuth(server =>
{
    server.Issuer = issuer;
    server.Keys.UseDevelopmentKey();

    server.Store.UseInMemory(store =>
    {
        // ══════════════════════════════════════════════════════════════════════
        // CONFORMANCE SUITE TEST CLIENTS
        // These match the client configurations expected by the OIDF suite.
        // When creating a test plan, use these client_id/secret values.
        // ══════════════════════════════════════════════════════════════════════

        // ── Client 1: client_secret_basic (default for Basic OP profile) ──
        store.Clients.Add(new Client
        {
            ClientId = "simpleauth-basic",
            ClientName = "Conformance Suite - Basic",
            AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            AllowedScopes =
            [
                StandardScope.OpenId,
                StandardScope.Profile,
                StandardScope.Email,
                StandardScope.Address,
                StandardScope.Phone,
                StandardScope.OfflineAccess,
            ],
            RedirectUris =
            [
                $"{conformanceSuiteBase}/test/a/simpleauth/callback",
                $"{conformanceSuiteBase}/test/a/simpleauth-basic/callback",
            ],
            PostLogoutRedirectUris =
            [
                $"{conformanceSuiteBase}/test/a/simpleauth/post_logout_redirect",
                $"{conformanceSuiteBase}/test/a/simpleauth-basic/post_logout_redirect",
            ],
            RequireClientSecret = true,
            RequirePkce = true,
            AllowOfflineAccess = true,
            RequireConsent = false,
            TokenEndpointAuthMethod = AuthMethod.ClientSecretBasic,
            AccessTokenType = AccessTokenType.Jwt,
            ClientCredentials =
            [
                new ClientCredential
                {
                    Type = "SharedSecret",
                    Value = SecretHasher.Hash("conformance-secret-basic"),
                },
            ],
        });

        // ── Client 2: client_secret_post ──
        store.Clients.Add(new Client
        {
            ClientId = "simpleauth-post",
            ClientName = "Conformance Suite - Post",
            AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            AllowedScopes =
            [
                StandardScope.OpenId,
                StandardScope.Profile,
                StandardScope.Email,
                StandardScope.Address,
                StandardScope.Phone,
                StandardScope.OfflineAccess,
            ],
            RedirectUris =
            [
                $"{conformanceSuiteBase}/test/a/simpleauth/callback",
                $"{conformanceSuiteBase}/test/a/simpleauth-post/callback",
            ],
            PostLogoutRedirectUris =
            [
                $"{conformanceSuiteBase}/test/a/simpleauth/post_logout_redirect",
                $"{conformanceSuiteBase}/test/a/simpleauth-post/post_logout_redirect",
            ],
            RequireClientSecret = true,
            RequirePkce = true,
            AllowOfflineAccess = true,
            RequireConsent = false,
            TokenEndpointAuthMethod = AuthMethod.ClientSecretPost,
            AccessTokenType = AccessTokenType.Jwt,
            ClientCredentials =
            [
                new ClientCredential
                {
                    Type = "SharedSecret",
                    Value = SecretHasher.Hash("conformance-secret-post"),
                },
            ],
        });

        // ── Client 3: Public client (no secret, PKCE only) ──
        store.Clients.Add(new Client
        {
            ClientId = "simpleauth-public",
            ClientName = "Conformance Suite - Public",
            AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            AllowedScopes =
            [
                StandardScope.OpenId,
                StandardScope.Profile,
                StandardScope.Email,
                StandardScope.OfflineAccess,
            ],
            RedirectUris =
            [
                $"{conformanceSuiteBase}/test/a/simpleauth/callback",
                $"{conformanceSuiteBase}/test/a/simpleauth-public/callback",
            ],
            PostLogoutRedirectUris =
            [
                $"{conformanceSuiteBase}/test/a/simpleauth/post_logout_redirect",
                $"{conformanceSuiteBase}/test/a/simpleauth-public/post_logout_redirect",
            ],
            RequireClientSecret = false,
            RequirePkce = true,
            AllowOfflineAccess = true,
            RequireConsent = false,
            TokenEndpointAuthMethod = AuthMethod.None,
            AccessTokenType = AccessTokenType.Jwt,
        });

        // ── Client 4: Second client (used by some tests that need 2 clients) ──
        store.Clients.Add(new Client
        {
            ClientId = "simpleauth-second",
            ClientName = "Conformance Suite - Second Client",
            AllowedGrantTypes = [GrantType.AuthorizationCode],
            AllowedScopes =
            [
                StandardScope.OpenId,
                StandardScope.Profile,
                StandardScope.Email,
            ],
            RedirectUris =
            [
                $"{conformanceSuiteBase}/test/a/simpleauth/callback",
                $"{conformanceSuiteBase}/test/a/simpleauth-second/callback",
            ],
            RequireClientSecret = true,
            RequirePkce = true,
            RequireConsent = false,
            TokenEndpointAuthMethod = AuthMethod.ClientSecretBasic,
            AccessTokenType = AccessTokenType.Jwt,
            ClientCredentials =
            [
                new ClientCredential
                {
                    Type = "SharedSecret",
                    Value = SecretHasher.Hash("conformance-secret-second"),
                },
            ],
        });

        // ── OIDC Identity Scopes ──
        foreach (IdentityScope scope in Resources.Standard)
        {
            store.IdentityScopes.Add(scope);
        }
    });

    server.Discovery.IncludeIntrospectionEndpoint = true;
    server.Discovery.IncludeRevocationEndpoint = true;

    // Auto-login: conformance suite tests need user interaction.
    // The built-in login page will be used — just type the test user sub.
    server.Interaction.EnableBuiltInPages = true;
});

// Claims enricher returns the configured test user profile
builder.Services.AddSingleton<IClaimsEnricher>(new ConformanceClaimsEnricher(
    testUserSub, testUserName, testUserEmail));

WebApplication app = builder.Build();

// ── Auto-login endpoint for conformance suite automation ──────────────────────
// POST /autologin?sub=test-user → sets cookie and redirects to returnUrl
// This enables automated test execution without manual login.
app.MapPost("/autologin", HandleAutoLogin);

// ── Status endpoint for health checks ─────────────────────────────────────────
app.MapGet("/status", () => Results.Ok(new
{
    status = "ok",
    server = "SimpleAuth Conformance Deployment",
    issuer,
    testUser = testUserSub,
    conformanceSuiteBase,
}));

// SimpleAuth endpoints
app.MapSimpleAuth();

app.MapGet("/", () => Results.Content($$"""
<!DOCTYPE html>
<html>
<head><title>SimpleAuth — Conformance Suite Deployment</title>
<style>body{font-family:system-ui;max-width:700px;margin:2rem auto;padding:1rem;background:#111;color:#eee}
h1{color:#60a5fa}code{background:#222;padding:0.2rem 0.4rem;border-radius:3px;font-size:0.9rem}
a{color:#60a5fa}pre{background:#1a1a2e;padding:1rem;border-radius:8px;overflow-x:auto;font-size:0.8rem}
.card{background:#1a1d27;border:1px solid #2d3248;border-radius:8px;padding:1.5rem;margin:1rem 0}
.badge{display:inline-block;padding:0.2rem 0.5rem;border-radius:3px;font-size:0.75rem;font-weight:600;background:rgba(34,197,94,0.15);color:#22c55e}
</style></head>
<body>
<h1>⚡ SimpleAuth Conformance Suite</h1>
<p>This server is configured for the <a href="https://www.certification.openid.net/">OpenID Foundation Conformance Suite</a>.</p>

<div class="card">
<h3>🔗 Endpoints</h3>
<ul>
<li>Discovery: <a href="/.well-known/openid-configuration"><code>/.well-known/openid-configuration</code></a></li>
<li>Authorize: <code>/connect/authorize</code></li>
<li>Token: <code>/connect/token</code></li>
<li>UserInfo: <code>/connect/userinfo</code></li>
<li>JWKS: <a href="/.well-known/jwks.json"><code>/.well-known/jwks.json</code></a></li>
<li>Status: <a href="/status"><code>/status</code></a></li>
</ul>
</div>

<div class="card">
<h3>🔑 Pre-registered Test Clients</h3>
<table style="width:100%;font-size:0.85rem;border-collapse:collapse">
<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:0.5rem">Client ID</th><th style="text-align:left">Secret</th><th>Auth Method</th></tr>
<tr style="border-bottom:1px solid #222"><td style="padding:0.3rem"><code>simpleauth-basic</code></td><td><code>conformance-secret-basic</code></td><td>client_secret_basic</td></tr>
<tr style="border-bottom:1px solid #222"><td style="padding:0.3rem"><code>simpleauth-post</code></td><td><code>conformance-secret-post</code></td><td>client_secret_post</td></tr>
<tr style="border-bottom:1px solid #222"><td style="padding:0.3rem"><code>simpleauth-public</code></td><td>—</td><td>none (public)</td></tr>
<tr><td style="padding:0.3rem"><code>simpleauth-second</code></td><td><code>conformance-secret-second</code></td><td>client_secret_basic</td></tr>
</table>
</div>

<div class="card">
<h3>👤 Test User</h3>
<p>Sub: <code>{{testUserSub}}</code> | Name: {{testUserName}} | Email: {{testUserEmail}}</p>
<p style="font-size:0.8rem;color:#888">Use the built-in login page at <code>/account/login</code>. Enter the test user sub as username.</p>
</div>

<div class="card">
<h3>📋 How to Run Conformance Tests</h3>
<ol style="font-size:0.85rem;line-height:2">
<li>Go to <a href="https://www.certification.openid.net/">certification.openid.net</a> and login</li>
<li>Create a new test plan → select <strong>"OpenID Connect Core: Basic OP"</strong></li>
<li>Configure the plan:
<pre>
Server metadata URL: {{issuer}}/.well-known/openid-configuration
Client ID:          simpleauth-basic
Client Secret:      conformance-secret-basic
</pre></li>
<li>Run the tests — when prompted to login, enter <code>{{testUserSub}}</code> as username</li>
<li>All tests should pass for the Basic OP profile ✅</li>
</ol>
</div>

<div class="card">
<h3>🐳 Deploy with Docker</h3>
<pre>docker build -t simpleauth-conformance .
docker run -p 8080:8080 \
  -e SIMPLEAUTH_ISSUER=https://your-domain.com \
  -e SIMPLEAUTH_CONFORMANCE_BASE=https://www.certification.openid.net \
  simpleauth-conformance</pre>
</div>

<p style="text-align:center;margin-top:2rem"><span class="badge">✓ Ready for certification</span></p>
</body></html>
""", "text/html"));

await app.RunAsync();

// ── Auto-login handler ────────────────────────────────────────────────────────

static async Task HandleAutoLogin(HttpContext ctx)
{
    string sub = ctx.Request.Form["sub"].ToString();
    string returnUrl = ctx.Request.Form["returnUrl"].ToString();

    if (string.IsNullOrWhiteSpace(sub))
    {
        sub = "test-user";
    }

    if (string.IsNullOrWhiteSpace(returnUrl))
    {
        returnUrl = "/";
    }

    var claims = new List<Claim>
    {
        new("sub", sub),
        new(ClaimTypes.NameIdentifier, sub),
        new("name", $"User {sub}"),
    };

    var identity = new ClaimsIdentity(claims, "SimpleAuth.Cookie");
    var principal = new ClaimsPrincipal(identity);

    await ctx.SignInAsync("SimpleAuth.Cookie", principal);

    ctx.Response.StatusCode = 302;
    ctx.Response.Headers.Location = returnUrl;
}

// ── Claims enricher ───────────────────────────────────────────────────────────

internal sealed class ConformanceClaimsEnricher(string testSub, string testName, string testEmail) : IClaimsEnricher
{
    public ValueTask EnrichAsync(ClaimsEnrichmentContext context, CancellationToken cancellationToken = default)
    {
        // Return full profile claims for the test user
        if (context.GrantedScopes.Contains(StandardScope.Profile, StringComparer.Ordinal))
        {
            context.Claims.Add(new Claim("name", testName));
            context.Claims.Add(new Claim("given_name", "Test"));
            context.Claims.Add(new Claim("family_name", "User"));
            context.Claims.Add(new Claim("preferred_username", testSub));
            context.Claims.Add(new Claim("updated_at", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
        }

        if (context.GrantedScopes.Contains(StandardScope.Email, StringComparer.Ordinal))
        {
            context.Claims.Add(new Claim("email", testEmail));
            context.Claims.Add(new Claim("email_verified", "true"));
        }

        if (context.GrantedScopes.Contains(StandardScope.Phone, StringComparer.Ordinal))
        {
            context.Claims.Add(new Claim("phone_number", "+1-555-0100"));
            context.Claims.Add(new Claim("phone_number_verified", "true"));
        }

        if (context.GrantedScopes.Contains(StandardScope.Address, StringComparer.Ordinal))
        {
            context.Claims.Add(new Claim("address", """{"street_address":"123 Test St","locality":"Testville","region":"TS","postal_code":"12345","country":"BR"}"""));
        }

        return ValueTask.CompletedTask;
    }
}
