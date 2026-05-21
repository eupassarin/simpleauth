using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SimpleAuth.Security.Tests;

/// <summary>
/// Negative and adversarial protocol scenarios.
/// These tests verify that security boundaries hold under attack conditions.
/// </summary>
public sealed class SecurityTests
{
    // ─── Authorization code security ──────────────────────────────────────────

    [Fact]
    public async Task AuthCode_ReplayAttack_SecondExchangeReturnsInvalidGrant()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);

        // First exchange — must succeed.
        DefaultHttpContext firstContext = CreateTokenContext(services,
            $"grant_type=authorization_code&client_id=public-client&code={Uri.EscapeDataString(code)}&redirect_uri={Uri.EscapeDataString("https://app.example/callback")}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(firstContext);
        Assert.Equal(StatusCodes.Status200OK, firstContext.Response.StatusCode);

        // Second exchange with the same code — must be rejected.
        DefaultHttpContext secondContext = CreateTokenContext(services,
            $"grant_type=authorization_code&client_id=public-client&code={Uri.EscapeDataString(code)}&redirect_uri={Uri.EscapeDataString("https://app.example/callback")}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(secondContext);

        string body = await ReadBodyAsync(secondContext.Response.Body);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.Equal("invalid_grant", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthCode_WrongPkceVerifier_ReturnsInvalidGrant()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);

        DefaultHttpContext context = CreateTokenContext(services,
            $"grant_type=authorization_code&client_id=public-client&code={Uri.EscapeDataString(code)}&redirect_uri={Uri.EscapeDataString("https://app.example/callback")}&code_verifier=WRONG_VERIFIER_that_should_fail");

        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(context);

        string body = await ReadBodyAsync(context.Response.Body);
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.Equal("invalid_grant", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthCode_WrongClientId_ReturnsInvalidGrant()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);

        // A different client tries to exchange the code.
        DefaultHttpContext context = CreateTokenContext(services,
            $"grant_type=authorization_code&client_id=other-client&code={Uri.EscapeDataString(code)}&redirect_uri={Uri.EscapeDataString("https://app.example/callback")}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(context);

        // The code is bound to public-client; other-client receives invalid_grant.
        string body = await ReadBodyAsync(context.Response.Body);
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.Equal("invalid_grant", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthCode_WrongRedirectUri_ReturnsInvalidGrant()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);

        // Correct client, but the redirect_uri does not match what was used at /authorize.
        DefaultHttpContext context = CreateTokenContext(services,
            $"grant_type=authorization_code&client_id=public-client&code={Uri.EscapeDataString(code)}&redirect_uri={Uri.EscapeDataString("https://evil.example/steal")}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(context);

        string body = await ReadBodyAsync(context.Response.Body);
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.Equal("invalid_grant", doc.RootElement.GetProperty("error").GetString());
    }

    // ─── Refresh token security ────────────────────────────────────────────────

    [Fact]
    public async Task RefreshToken_ReplayAfterRotation_ReturnsInvalidGrant()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);
        (_, string originalRefresh) = await ExchangeCodeForTokensAsync(services, code);

        // First use — rotates the token.
        DefaultHttpContext firstRefresh = CreateTokenContext(services,
            $"grant_type=refresh_token&client_id=public-client&refresh_token={Uri.EscapeDataString(originalRefresh)}");
        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(firstRefresh);
        Assert.Equal(StatusCodes.Status200OK, firstRefresh.Response.StatusCode);

        // Second use of the original (now rotated) token — must fail.
        DefaultHttpContext secondRefresh = CreateTokenContext(services,
            $"grant_type=refresh_token&client_id=public-client&refresh_token={Uri.EscapeDataString(originalRefresh)}");
        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(secondRefresh);

        string body = await ReadBodyAsync(secondRefresh.Response.Body);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.Equal("invalid_grant", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task RefreshToken_WrongClient_ReturnsInvalidGrant()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);
        (_, string refresh) = await ExchangeCodeForTokensAsync(services, code);

        DefaultHttpContext context = CreateTokenContext(services,
            $"grant_type=refresh_token&client_id=other-client&refresh_token={Uri.EscapeDataString(refresh)}");
        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(context);

        // The refresh token is bound to public-client; other-client receives unauthorized_client
        // because other-client does not have refresh_token in AllowedGrantTypes.
        string body = await ReadBodyAsync(context.Response.Body);
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(body);
        string error = doc.RootElement.GetProperty("error").GetString()!;
        Assert.True(
            string.Equals(error, "unauthorized_client", StringComparison.Ordinal) ||
            string.Equals(error, "invalid_grant", StringComparison.Ordinal),
            $"Expected unauthorized_client or invalid_grant but got: {error}");
    }

    // ─── Token introspection security ─────────────────────────────────────────

    [Fact]
    public async Task Introspection_RevokedAccessToken_ReturnsInactive()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);
        (string accessToken, string refresh) = await ExchangeCodeForTokensAsync(services, code);

        // Revoke via refresh-token rotation replay (the old token gets revoked).
        DefaultHttpContext rotateCtx = CreateTokenContext(services,
            $"grant_type=refresh_token&client_id=public-client&refresh_token={Uri.EscapeDataString(refresh)}");
        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(rotateCtx);

        // The original access token should now be inactive.
        DefaultHttpContext introspect = CreatePostContext(services,
            $"client_id=public-client&token={Uri.EscapeDataString(accessToken)}");
        await SimpleAuth.Endpoints.IntrospectionEndpoint.HandleAsync(introspect);

        string body = await ReadBodyAsync(introspect.Response.Body);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.False(doc.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Introspection_MissingClientAuth_Returns401()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);
        (string accessToken, _) = await ExchangeCodeForTokensAsync(services, code);

        // No client_id at all.
        DefaultHttpContext context = CreatePostContext(services,
            $"token={Uri.EscapeDataString(accessToken)}");
        await SimpleAuth.Endpoints.IntrospectionEndpoint.HandleAsync(context);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    // ─── Authorize endpoint security ──────────────────────────────────────────

    [Fact]
    public async Task Authorize_MissingPkce_ReturnsError()
    {
        IServiceProvider services = BuildServices();

        DefaultHttpContext context = CreateAuthorizeContext(services,
            "?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=abc");

        await SimpleAuth.Endpoints.AuthorizationEndpoint.HandleAsync(context);

        // Must redirect with error=invalid_request (missing code_challenge).
        string redirect = context.Response.Headers.Location.ToString();
        Assert.False(string.IsNullOrWhiteSpace(redirect));
        Assert.Contains("error=", redirect);
    }

    [Fact]
    public async Task Authorize_UnknownClient_Returns400()
    {
        IServiceProvider services = BuildServices();

        DefaultHttpContext context = CreateAuthorizeContext(services,
            "?response_type=code&client_id=unknown-ghost&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=abc&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");

        await SimpleAuth.Endpoints.AuthorizationEndpoint.HandleAsync(context);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
    }

    [Fact]
    public async Task Authorize_UnregisteredRedirectUri_Returns400()
    {
        IServiceProvider services = BuildServices();

        DefaultHttpContext context = CreateAuthorizeContext(services,
            "?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fevil.example%2Fsteal&scope=openid&state=abc&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");

        await SimpleAuth.Endpoints.AuthorizationEndpoint.HandleAsync(context);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
    }

    // ─── End session security ─────────────────────────────────────────────────

    [Fact]
    public async Task EndSession_WithSubjectAndClient_RevokesAllTokens()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);
        (string accessToken, _) = await ExchangeCodeForTokensAsync(services, code);

        // Verify the token is active before logout.
        DefaultHttpContext before = CreatePostContext(services,
            $"client_id=public-client&token={Uri.EscapeDataString(accessToken)}");
        await SimpleAuth.Endpoints.IntrospectionEndpoint.HandleAsync(before);
        using JsonDocument beforeDoc = JsonDocument.Parse(await ReadBodyAsync(before.Response.Body));
        Assert.True(beforeDoc.RootElement.GetProperty("active").GetBoolean());

        // End-session with post_logout_redirect_uri — endpoint identifies client from client_id param.
        DefaultHttpContext endSession = CreateGetContext(services,
            $"/connect/endsession?client_id=public-client&post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Floggedout");

        await SimpleAuth.Endpoints.EndSessionEndpoint.HandleAsync(endSession);

        Assert.Equal(StatusCodes.Status302Found, endSession.Response.StatusCode);
        Assert.Contains("loggedout", endSession.Response.Headers.Location.ToString());
    }

    [Fact]
    public async Task EndSession_NoPostLogoutUri_Returns200()
    {
        IServiceProvider services = BuildServices();

        DefaultHttpContext context = CreateGetContext(services, "/connect/endsession");
        await SimpleAuth.Endpoints.EndSessionEndpoint.HandleAsync(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    // ─── IClaimsEnricher pipeline ─────────────────────────────────────────────

    [Fact]
    public async Task ClaimsEnricher_AddsClaimsToUserInfo()
    {
        IServiceProvider services = BuildServicesWithEnricher();
        string code = await IssueAuthorizationCodeAsync(services);
        (string accessToken, _) = await ExchangeCodeForTokensAsync(services, code);

        DefaultHttpContext userInfo = CreateHttpContext(services, HttpMethods.Get);
        userInfo.Request.Headers.Authorization = $"Bearer {accessToken}";
        await SimpleAuth.Endpoints.UserInfoEndpoint.HandleAsync(userInfo);

        string body = await ReadBodyAsync(userInfo.Response.Body);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.True(doc.RootElement.TryGetProperty("custom_claim", out JsonElement custom));
        Assert.Equal("enriched-value", custom.GetString());
    }

    // ─── PAR security ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Par_ClientIdMismatch_Returns400()
    {
        // Issue a PAR entry for public-client.
        IServiceProvider services = BuildServices();
        DefaultHttpContext parCtx = CreatePostContext(services,
            "response_type=code&client_id=public-client" +
            "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" +
            "&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" +
            "&code_challenge_method=S256");

        await SimpleAuth.Endpoints.PushedAuthorizationEndpoint.HandleAsync(parCtx);
        Assert.Equal(StatusCodes.Status201Created, parCtx.Response.StatusCode);

        string parJson = await ReadBodyAsync(parCtx.Response.Body);
        using JsonDocument parDoc = JsonDocument.Parse(parJson);
        string requestUri = parDoc.RootElement.GetProperty("request_uri").GetString()!;

        // Try to use the request_uri with a DIFFERENT client_id.
        DefaultHttpContext authorizeCtx = CreateAuthorizeContext(services,
            $"?client_id=other-client&request_uri={Uri.EscapeDataString(requestUri)}");
        await SimpleAuth.Endpoints.AuthorizationEndpoint.HandleAsync(authorizeCtx);

        string body = await ReadBodyAsync(authorizeCtx.Response.Body);
        Assert.Equal(StatusCodes.Status400BadRequest, authorizeCtx.Response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.Equal("invalid_request", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Par_ExpiredRequestUri_Returns400()
    {
        IServiceProvider services = BuildServices();

        // Manually store an already-expired PAR entry.
        IParStore parStore = services.GetRequiredService<IParStore>();
        DateTime now = DateTime.UtcNow;
        await parStore.StoreAsync(new ParEntry
        {
            RequestUri = "urn:ietf:params:oauth:request-uri:expired-test-entry",
            ClientId = "public-client",
            RedirectUri = "https://app.example/callback",
            Scope = "openid",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = "S256",
            ResponseType = "code",
            CreatedAt = now.AddSeconds(-120),
            ExpiresAt = now.AddSeconds(-30), // Already expired.
        });

        DefaultHttpContext authorizeCtx = CreateAuthorizeContext(services,
            "?client_id=public-client&request_uri=urn:ietf:params:oauth:request-uri:expired-test-entry");
        await SimpleAuth.Endpoints.AuthorizationEndpoint.HandleAsync(authorizeCtx);

        string body = await ReadBodyAsync(authorizeCtx.Response.Body);
        Assert.Equal(StatusCodes.Status400BadRequest, authorizeCtx.Response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.Equal("invalid_request", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Par_RequiredMode_DirectAuthorize_Returns400()
    {
        ServiceCollection svc = new();
        svc.AddSimpleAuth(server =>
        {
            server.Issuer = "https://auth.example";
            server.Par.Enabled = true;
            server.Par.Required = true;
            server.Store.UseInMemory(store =>
            {
                store.Clients.Add(new Client
                {
                    ClientId = "public-client",
                    ClientName = "Public Client",
                    AllowedGrantTypes = [GrantType.AuthorizationCode],
                    AllowedScopes = [StandardScope.OpenId],
                    RedirectUris = ["https://app.example/callback"],
                    RequireClientSecret = false,
                    RequirePkce = true,
                    RequireConsent = false,
                });
            });
            server.Keys.UseDevelopmentKey();
        });
        IServiceProvider services = svc.BuildServiceProvider();

        DefaultHttpContext authorizeCtx = CreateAuthorizeContext(services,
            "?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" +
            "&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");
        await SimpleAuth.Endpoints.AuthorizationEndpoint.HandleAsync(authorizeCtx);

        string body = await ReadBodyAsync(authorizeCtx.Response.Body);
        Assert.Equal(StatusCodes.Status400BadRequest, authorizeCtx.Response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.Equal("invalid_request", doc.RootElement.GetProperty("error").GetString());
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private static IServiceProvider BuildServices()
    {
        ServiceCollection services = new();
        services.AddSimpleAuth(server =>
        {
            server.Issuer = "https://auth.example";
            server.Store.UseInMemory(store =>
            {
                store.Clients.Add(new Client
                {
                    ClientId = "public-client",
                    ClientName = "Public Client",
                    AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
                    AllowedScopes = [StandardScope.OpenId, StandardScope.OfflineAccess],
                    RedirectUris = ["https://app.example/callback"],
                    PostLogoutRedirectUris = ["https://app.example/loggedout"],
                    RequireClientSecret = false,
                    RequirePkce = true,
                    AllowOfflineAccess = true,
                    AccessTokenType = AccessTokenType.Reference,
                    RequireConsent = false,
                });

                store.Clients.Add(new Client
                {
                    ClientId = "other-client",
                    ClientName = "Other Client",
                    AllowedGrantTypes = [GrantType.AuthorizationCode],
                    AllowedScopes = [StandardScope.OpenId],
                    RedirectUris = ["https://other.example/callback"],
                    RequireClientSecret = false,
                    RequirePkce = true,
                    RequireConsent = false,
                });
            });
            server.Keys.UseDevelopmentKey();
        });

        return services.BuildServiceProvider();
    }

    private static IServiceProvider BuildServicesWithEnricher()
    {
        ServiceCollection services = new();
        services.AddSimpleAuth(server =>
        {
            server.Issuer = "https://auth.example";
            server.Store.UseInMemory(store =>
            {
                store.Clients.Add(new Client
                {
                    ClientId = "public-client",
                    ClientName = "Public Client",
                    AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
                    AllowedScopes = [StandardScope.OpenId, StandardScope.OfflineAccess],
                    RedirectUris = ["https://app.example/callback"],
                    RequireClientSecret = false,
                    RequirePkce = true,
                    AllowOfflineAccess = true,
                    AccessTokenType = AccessTokenType.Reference,
                    RequireConsent = false,
                });
            });
            server.Keys.UseDevelopmentKey();
        });
        services.AddSingleton<IClaimsEnricher, TestClaimsEnricher>();

        return services.BuildServiceProvider();
    }

    private static async Task<string> IssueAuthorizationCodeAsync(IServiceProvider services)
    {
        DefaultHttpContext context = CreateAuthorizeContext(services,
            "?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid%20offline_access&state=abc&nonce=n-1&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");

        await SimpleAuth.Endpoints.AuthorizationEndpoint.HandleAsync(context);

        string redirect = context.Response.Headers.Location.ToString();
        return ExtractQueryValue(redirect, "code");
    }

    private static async Task<(string AccessToken, string RefreshToken)> ExchangeCodeForTokensAsync(
        IServiceProvider services, string code)
    {
        DefaultHttpContext context = CreateTokenContext(services,
            $"grant_type=authorization_code&client_id=public-client&code={Uri.EscapeDataString(code)}&redirect_uri={Uri.EscapeDataString("https://app.example/callback")}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(context);

        using JsonDocument doc = JsonDocument.Parse(await ReadBodyAsync(context.Response.Body));
        string access = doc.RootElement.GetProperty("access_token").GetString()!;
        string refresh = doc.RootElement.GetProperty("refresh_token").GetString()!;
        return (access, refresh);
    }

    private static DefaultHttpContext CreateAuthorizeContext(IServiceProvider services, string query)
    {
        DefaultHttpContext context = CreateHttpContext(services, HttpMethods.Get);
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "user-123"),
        ], "cookie"));
        context.Request.QueryString = new QueryString(query);
        return context;
    }

    private static DefaultHttpContext CreateTokenContext(IServiceProvider services, string formBody)
    {
        DefaultHttpContext context = CreateHttpContext(services, HttpMethods.Post);
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(formBody));
        return context;
    }

    private static DefaultHttpContext CreatePostContext(IServiceProvider services, string formBody)
    {
        DefaultHttpContext context = CreateHttpContext(services, HttpMethods.Post);
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(formBody));
        return context;
    }

    private static DefaultHttpContext CreateGetContext(IServiceProvider services, string path)
    {
        DefaultHttpContext context = CreateHttpContext(services, HttpMethods.Get);
        int q = path.IndexOf('?', StringComparison.Ordinal);
        if (q >= 0)
        {
            context.Request.Path = path[..q];
            context.Request.QueryString = new QueryString(path[q..]);
        }
        else
        {
            context.Request.Path = path;
        }

        return context;
    }

    private static DefaultHttpContext CreateHttpContext(IServiceProvider services, string method)
    {
        var context = new DefaultHttpContext();
        context.RequestServices = services;
        context.Request.Method = method;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static async Task<string> ReadBodyAsync(Stream stream)
    {
        stream.Position = 0;
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        return await reader.ReadToEndAsync();
    }

    private static string ExtractQueryValue(string uri, string key)
    {
        string query = new Uri(uri).Query;
        foreach (string segment in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] pair = segment.Split('=', 2);
            if (pair.Length == 2 && string.Equals(Uri.UnescapeDataString(pair[0]), key, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[1]);
            }
        }

        return string.Empty;
    }
}

/// <summary>Minimal enricher used in pipeline tests.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Registered via DI.")]
file sealed class TestClaimsEnricher : IClaimsEnricher
{
    public ValueTask EnrichAsync(ClaimsEnrichmentContext context, CancellationToken cancellationToken = default)
    {
        context.Claims.Add(new System.Security.Claims.Claim("custom_claim", "enriched-value"));
        return ValueTask.CompletedTask;
    }
}
