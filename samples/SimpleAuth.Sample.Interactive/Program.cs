using SimpleAuth;
using SimpleAuth.Crypto;

// ──────────────────────────────────────────────────────────────────────────────
// SimpleAuth — Interactive Testing Dashboard
// Serves the OAuth 2.1 + OIDC server alongside an interactive HTML dashboard
// that demonstrates and tests every feature.
// ──────────────────────────────────────────────────────────────────────────────

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddSimpleAuth(server =>
{
    server.Issuer = "https://localhost:5001";

    server.Keys.UseDevelopmentKey();

    server.Store.UseInMemory(store =>
    {
        // ── Public client: Authorization Code + PKCE (used by the dashboard) ──
        store.Clients.Add(new Client
        {
            ClientId = "interactive-dashboard",
            ClientName = "Interactive Dashboard",
            AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            AllowedScopes =
            [
                StandardScope.OpenId,
                StandardScope.Profile,
                StandardScope.Email,
                StandardScope.OfflineAccess,
                "api",
            ],
            RedirectUris =
            [
                "https://localhost:5001/callback",
                "https://localhost:5001/callback-form-post",
            ],
            PostLogoutRedirectUris = ["https://localhost:5001/"],
            RequireClientSecret = false,
            RequirePkce = true,
            AllowOfflineAccess = true,
            RequireConsent = true,
            AccessTokenType = AccessTokenType.Reference,
        });

        // ── Confidential client: Client Credentials + Introspection ──
        store.Clients.Add(new Client
        {
            ClientId = "m2m-demo",
            ClientName = "Machine-to-Machine Demo",
            AllowedGrantTypes = [GrantType.ClientCredentials],
            AllowedScopes = ["api"],
            RequireClientSecret = true,
            RequireConsent = false,
            AccessTokenType = AccessTokenType.Jwt,
            ClientCredentials =
            [
                new ClientCredential
                {
                    Type = "SharedSecret",
                    // Hash of "demo-secret" — generated with SecretHasher
                    Value = SecretHasher.Hash("demo-secret"),
                },
            ],
        });

        // ── Confidential client for introspection/revocation testing ──
        store.Clients.Add(new Client
        {
            ClientId = "resource-server",
            ClientName = "Resource Server (Introspection)",
            AllowedGrantTypes = [GrantType.ClientCredentials],
            AllowedScopes = ["api"],
            RequireClientSecret = true,
            RequireConsent = false,
            ClientCredentials =
            [
                new ClientCredential
                {
                    Type = "SharedSecret",
                    Value = SecretHasher.Hash("resource-secret"),
                },
            ],
        });

        // ── API scope ──
        store.Scopes.Add(new Scope
        {
            Name = "api",
            DisplayName = "Demo API",
            Description = "Access to the demonstration API.",
        });

        // ── OIDC identity scopes ──
        foreach (IdentityScope scope in Resources.Standard)
        {
            store.IdentityScopes.Add(scope);
        }
    });

    server.Discovery.IncludeIntrospectionEndpoint = true;
    server.Discovery.IncludeRevocationEndpoint = true;

    server.Interaction.EnableBuiltInPages = true;
});

builder.Services.AddSingleton<IClaimsEnricher, DemoClaimsEnricher>();

WebApplication app = builder.Build();

// Serve the interactive dashboard from wwwroot/
app.UseDefaultFiles();
app.UseStaticFiles();

// SimpleAuth endpoints
app.MapSimpleAuth();

// Callback page for authorization code (captures ?code=...&state=...)
app.MapGet("/callback", HandleCallback);

// Form-post callback (POST from auto-submitting form)
app.MapPost("/callback-form-post", HandleFormPostCallback);

app.MapGet("/", () => Results.Redirect("/index.html"));

await app.RunAsync();

static Task HandleCallback(HttpContext ctx)
{
    ctx.Response.ContentType = "text/html; charset=utf-8";
    return ctx.Response.WriteAsync("""
    <!DOCTYPE html>
    <html><head><title>Callback</title><script>
    const params = new URLSearchParams(window.location.search);
    if (window.opener) {
        window.opener.postMessage({ type: 'auth-callback', code: params.get('code'), state: params.get('state') }, '*');
        window.close();
    } else {
        window.location.href = '/#callback?code=' + params.get('code') + '&state=' + (params.get('state') || '');
    }
    </script></head><body><p>Processing callback...</p></body></html>
    """);
}

static async Task HandleFormPostCallback(HttpContext ctx)
{
    var form = await ctx.Request.ReadFormAsync();
    string code = form["code"].ToString();
    string state = form["state"].ToString();
    string codePreview = code.Length > 8 ? code[..8] + "..." : code;

    // Escape for safe interpolation into JavaScript string literals (prevents XSS)
    string jsCode = System.Text.Encodings.Web.JavaScriptEncoder.Default.Encode(code);
    string jsState = System.Text.Encodings.Web.JavaScriptEncoder.Default.Encode(state);
    string htmlCode = System.Net.WebUtility.HtmlEncode(codePreview);

    ctx.Response.ContentType = "text/html; charset=utf-8";
    await ctx.Response.WriteAsync(
        "<!DOCTYPE html><html><head><title>Form Post Callback</title><script>" +
        "if(window.opener){window.opener.postMessage({type:'form-post-callback',code:'" + jsCode + "',state:'" + jsState + "'},'*');window.close();}else{" +
        "window.location.href='/#callback?code=" + jsCode + "&state=" + jsState + "&mode=form_post';}" +
        "</script></head><body><p>Form post received. Code: <code>" + htmlCode + "</code></p></body></html>");
}

// ── Claims enricher ───────────────────────────────────────────────────────────

[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:AvoidUninstantiatedInternalClasses", Justification = "DI")]
internal sealed class DemoClaimsEnricher : IClaimsEnricher
{
    public ValueTask EnrichAsync(ClaimsEnrichmentContext context, CancellationToken cancellationToken = default)
    {
        if (context.GrantedScopes.Contains(StandardScope.Profile, StringComparer.Ordinal))
        {
            context.Claims.Add(new System.Security.Claims.Claim("name", $"Demo User ({context.SubjectId})"));
            context.Claims.Add(new System.Security.Claims.Claim("preferred_username", context.SubjectId));
            context.Claims.Add(new System.Security.Claims.Claim("given_name", "Demo"));
            context.Claims.Add(new System.Security.Claims.Claim("family_name", "User"));
        }

        if (context.GrantedScopes.Contains(StandardScope.Email, StringComparer.Ordinal))
        {
            context.Claims.Add(new System.Security.Claims.Claim("email", $"{context.SubjectId}@simpleauth.dev"));
            context.Claims.Add(new System.Security.Claims.Claim("email_verified", "true"));
        }

        return ValueTask.CompletedTask;
    }
}
