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

// Read configuration: env var takes priority over appsettings
string issuer = Environment.GetEnvironmentVariable("SIMPLEAUTH_ISSUER")
    ?? builder.Configuration["SimpleAuth:Issuer"]
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
    server.Keys.UseDevelopmentRsaKey(); // OIDC Core requires RS256 as mandatory algorithm

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
            RequirePkce = false, // OIDC Basic profile tests do not always send PKCE for confidential clients
            AllowOfflineAccess = true,
            RequireConsent = false,
            TokenEndpointAuthMethod = AuthMethod.ClientSecretBasic,
            AccessTokenType = AccessTokenType.Reference,
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
            RequirePkce = false, // OIDC Basic profile tests do not always send PKCE for confidential clients
            AllowOfflineAccess = true,
            RequireConsent = false,
            TokenEndpointAuthMethod = AuthMethod.ClientSecretPost,
            AccessTokenType = AccessTokenType.Reference,
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
            RequirePkce = true, // Public clients MUST use PKCE
            AllowOfflineAccess = true,
            RequireConsent = false,
            TokenEndpointAuthMethod = AuthMethod.None,
            AccessTokenType = AccessTokenType.Reference,
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
            RequirePkce = false, // OIDC Basic profile tests do not always send PKCE for confidential clients
            RequireConsent = false,
            TokenEndpointAuthMethod = AuthMethod.ClientSecretBasic,
            AccessTokenType = AccessTokenType.Reference,
            ClientCredentials =
            [
                new ClientCredential
                {
                    Type = "SharedSecret",
                    Value = SecretHasher.Hash("conformance-secret-second"),
                },
                // Accept secret with trailing space — the conformance suite UI sometimes appends one.
                new ClientCredential
                {
                    Type = "SharedSecret",
                    Value = SecretHasher.Hash("conformance-secret-second "),
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

// ── Auto-logout endpoint ───────────────────────────────────────────────────────
// GET /autologout → clears the session cookie (required before prompt=none-not-logged-in test)
app.MapGet("/autologout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync("SimpleAuth.Cookie");
    return Results.Content("""
        <!DOCTYPE html><html><head><title>Logged Out — Ready for Test</title>
        <meta http-equiv="refresh" content="3;url=/">
        <style>body{font-family:system-ui;max-width:600px;margin:4rem auto;text-align:center;background:#111;color:#eee}
        .ready{background:#052e16;border:2px solid #22c55e;border-radius:8px;padding:1.5rem;margin:1.5rem 0}
        </style>
        </head><body>
        <h2>✅ Session Cleared</h2>
        <div class="ready">
          <p style="font-size:1.1rem;margin:0"><strong style="color:#86efac">You are now logged out.</strong></p>
          <p style="margin:0.75rem 0 0">Go back to the conformance suite and run the
          <strong><code style="background:#064e3b;padding:0.2rem 0.5rem">oidcc-prompt-none-not-logged-in</code></strong>
          test <em>immediately</em> — before doing anything else that logs you back in.</p>
        </div>
        <p><a href="/" style="color:#60a5fa">← Back to home</a> (auto-redirecting in 3 seconds)</p>
        </body></html>
        """, "text/html");
});

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

app.MapGet("/", (HttpContext httpContext) =>
{
    bool isAuthenticated = httpContext.User.Identity?.IsAuthenticated == true;
    string? currentSub = httpContext.User.FindFirst("sub")?.Value ?? httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
    string sessionBanner = isAuthenticated
        ? $"""
          <div style="background:#7f1d1d;border:2px solid #ef4444;border-radius:8px;padding:1rem 1.5rem;margin:1rem 0">
          <strong style="color:#fca5a5;font-size:1.1rem">⚠️ ACTIVE SESSION DETECTED</strong>
          <p style="margin:0.5rem 0 0">You are currently logged in as <code style="background:#450a0a;padding:0.2rem 0.4rem">{currentSub}</code>.</p>
          <p style="margin:0.5rem 0 0;color:#fca5a5">You <strong>MUST log out before running <code>prompt-none-not-logged-in</code></strong> — otherwise that test will FAIL.</p>
          <p style="margin:1rem 0 0"><a href="/autologout" style="background:#ef4444;color:#fff;padding:0.5rem 1.2rem;border-radius:4px;text-decoration:none;font-weight:600;font-size:1rem">🚪 LOGOUT NOW</a></p>
          </div>
          """
        : """
          <div style="background:#052e16;border:2px solid #22c55e;border-radius:8px;padding:0.8rem 1.5rem;margin:1rem 0">
          <strong style="color:#86efac">✅ No active session</strong> — ready to run <code style="background:#064e3b;padding:0.2rem 0.4rem">prompt-none-not-logged-in</code>
          </div>
          """;
    return Results.Content($$"""
<!DOCTYPE html>
<html>
<head><title>SimpleAuth — Conformance Suite Deployment</title>
<meta http-equiv="refresh" content="8">
<style>body{font-family:system-ui;max-width:700px;margin:2rem auto;padding:1rem;background:#111;color:#eee}
h1{color:#60a5fa}code{background:#222;padding:0.2rem 0.4rem;border-radius:3px;font-size:0.9rem}
a{color:#60a5fa}pre{background:#1a1a2e;padding:1rem;border-radius:8px;overflow-x:auto;font-size:0.8rem}
.card{background:#1a1d27;border:1px solid #2d3248;border-radius:8px;padding:1.5rem;margin:1rem 0}
.badge{display:inline-block;padding:0.2rem 0.5rem;border-radius:3px;font-size:0.75rem;font-weight:600;background:rgba(34,197,94,0.15);color:#22c55e}
.step{background:#0f172a;border-left:4px solid #3b82f6;padding:0.6rem 1rem;margin:0.4rem 0;border-radius:0 4px 4px 0}
</style></head>
<body>
<h1>⚡ SimpleAuth Conformance Suite</h1>
<p>This server is configured for the <a href="https://www.certification.openid.net/">OpenID Foundation Conformance Suite</a>.
<small style="color:#6b7280">(page auto-refreshes every 8s)</small></p>

{{sessionBanner}}

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
<tr><td style="padding:0.3rem"><code>simpleauth-second</code></td><td><code>conformance-secret-second</code></td><td>client_secret_basic <span style="color:#f59e0b;font-size:0.75rem">(no trailing space)</span></td></tr>
</table>
<p style="font-size:0.75rem;color:#f59e0b;margin-top:0.5rem">⚠️ Enter secrets exactly as shown — the conformance suite sometimes adds a trailing space.</p>
</div>

<div class="card">
<h3>👤 Test User</h3>
<p>Sub: <code>{{testUserSub}}</code> | Name: {{testUserName}} | Email: {{testUserEmail}}</p>
<p style="font-size:0.8rem;color:#888">Use the built-in login page at <code>/account/login</code>. Enter the test user sub as username.</p>
<p style="margin-top:0.5rem">
  <a href="/autologout" style="background:#ef4444;color:#fff;padding:0.3rem 0.8rem;border-radius:4px;text-decoration:none;font-size:0.8rem">🚪 Logout (clear session)</a>
  <span style="font-size:0.75rem;color:#888;margin-left:0.5rem">Required before running <code>prompt-none-not-logged-in</code></span>
</p>
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
<li>Run the plan — when prompted to login, enter <code>{{testUserSub}}</code> as username</li>
<li>All tests should pass <strong>except <code>oidcc-prompt-none-not-logged-in</code></strong> which requires a manual logout step (see below)</li>
</ol>
</div>

<div class="card" style="border-color:#f59e0b">
<h3 style="color:#fbbf24">⚠️ Special Steps for <code>oidcc-prompt-none-not-logged-in</code></h3>
<p style="font-size:0.85rem;margin:0 0 0.5rem">This test requires the browser to have <strong>no active session</strong>. Since the OIDF suite reuses a single browser session for all tests, earlier tests (like the basic code flow) leave a session cookie behind — causing this test to fail if run in the normal sequence.</p>
<p style="font-size:0.85rem;font-weight:600;margin:0.5rem 0">✅ Correct workflow:</p>
<div class="step">1️⃣ &nbsp;Run the full test plan. Let <code>oidcc-prompt-none-not-logged-in</code> fail (expected)</div>
<div class="step">2️⃣ &nbsp;In the <strong>same browser the OIDF suite uses</strong>, open this page → check the session banner above (it auto-refreshes)</div>
<div class="step">3️⃣ &nbsp;If you see <span style="color:#ef4444">🔴 ACTIVE SESSION</span>, click <a href="/autologout"><strong>LOGOUT NOW</strong></a>. Banner should turn 🟢 green</div>
<div class="step">4️⃣ &nbsp;Return to the OIDF suite → click <code>oidcc-prompt-none-not-logged-in</code> → click <strong>"Retest"</strong></div>
<div class="step">5️⃣ &nbsp;Test should now pass with <code>login_required</code> ✅</div>
<p style="font-size:0.8rem;color:#9ca3af;margin-top:0.75rem">💡 <strong>Why this is correct:</strong> Per OIDC Core §3.1.2.6, <code>prompt=none</code> returns <code>login_required</code> only when the user is NOT authenticated. Our server correctly returns an auth code when the user IS authenticated. The test just needs to start with a clean session.</p>
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
""", "text/html");
});

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
        new("auth_time", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
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
        // OIDC Core §5.1 — Return all standard profile claims for the test user
        if (context.GrantedScopes.Contains(StandardScope.Profile, StringComparer.Ordinal))
        {
            context.Claims.Add(new Claim("name", testName));
            context.Claims.Add(new Claim("given_name", "Test"));
            context.Claims.Add(new Claim("family_name", "User"));
            context.Claims.Add(new Claim("middle_name", "A"));
            context.Claims.Add(new Claim("nickname", testSub));
            context.Claims.Add(new Claim("preferred_username", testSub));
            context.Claims.Add(new Claim("profile", $"https://example.com/users/{testSub}"));
            context.Claims.Add(new Claim("picture", "https://example.com/users/test-user/photo.jpg"));
            context.Claims.Add(new Claim("website", "https://example.com"));
            context.Claims.Add(new Claim("gender", "male"));
            context.Claims.Add(new Claim("birthdate", "1990-01-01"));
            context.Claims.Add(new Claim("zoneinfo", "America/Sao_Paulo"));
            context.Claims.Add(new Claim("locale", "pt-BR"));
            // updated_at must be a number — CoerceClaimValue in UserInfoEndpoint handles long.Parse
            context.Claims.Add(new Claim("updated_at", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
        }

        if (context.GrantedScopes.Contains(StandardScope.Email, StringComparer.Ordinal))
        {
            context.Claims.Add(new Claim("email", testEmail));
            // email_verified must be boolean — CoerceClaimValue handles bool.Parse
            context.Claims.Add(new Claim("email_verified", "true", ClaimValueTypes.Boolean));
        }

        if (context.GrantedScopes.Contains(StandardScope.Phone, StringComparer.Ordinal))
        {
            context.Claims.Add(new Claim("phone_number", "+1-555-0100"));
            context.Claims.Add(new Claim("phone_number_verified", "true", ClaimValueTypes.Boolean));
        }

        if (context.GrantedScopes.Contains(StandardScope.Address, StringComparer.Ordinal))
        {
            // address must be a JSON object per OIDC Core §5.1.1
            context.Claims.Add(new Claim("address", """{"formatted":"123 Test St\nTestville, TS 12345\nBR","street_address":"123 Test St","locality":"Testville","region":"TS","postal_code":"12345","country":"BR"}"""));
        }

        return ValueTask.CompletedTask;
    }
}
