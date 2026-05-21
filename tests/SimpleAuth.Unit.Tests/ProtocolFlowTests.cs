using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SimpleAuth;

public sealed class ProtocolFlowTests
{
    [Fact]
    public async Task AuthorizationCodeFlow_IssuesTokensAndUserInfo()
    {
        IServiceProvider services = BuildServices();

        string expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        await IssueAndInspectAuthorizationCodeAsync(services, expectedChallenge);
        string code = await IssueAuthorizationCodeAsync(services);

        DefaultHttpContext tokenContext = CreateHttpContext(services, HttpMethods.Post);
        tokenContext.Request.ContentType = "application/x-www-form-urlencoded";
        tokenContext.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(
            $"grant_type=authorization_code&client_id=public-client&code={Uri.EscapeDataString(code)}&redirect_uri={Uri.EscapeDataString("https://app.example/callback")}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(tokenContext);

        string tokenJson = await ReadBodyAsync(tokenContext.Response.Body);
        Assert.True(tokenContext.Response.StatusCode is StatusCodes.Status200OK, tokenJson);
        Assert.False(string.IsNullOrWhiteSpace(tokenJson));
        using JsonDocument tokenDocument = JsonDocument.Parse(tokenJson);
        JsonElement tokenRoot = tokenDocument.RootElement;

        string accessToken = tokenRoot.GetProperty("access_token").GetString()!;
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
        Assert.True(tokenRoot.TryGetProperty("refresh_token", out JsonElement refreshToken));
        Assert.False(string.IsNullOrWhiteSpace(refreshToken.GetString()));
        Assert.True(tokenRoot.TryGetProperty("id_token", out JsonElement idToken));
        Assert.False(string.IsNullOrWhiteSpace(idToken.GetString()));

        DefaultHttpContext userInfoContext = CreateHttpContext(services, HttpMethods.Get);
        userInfoContext.Request.Headers.Authorization = $"Bearer {accessToken}";
        await SimpleAuth.Endpoints.UserInfoEndpoint.HandleAsync(userInfoContext);

        string userInfoJson = await ReadBodyAsync(userInfoContext.Response.Body);
        using JsonDocument userInfoDocument = JsonDocument.Parse(userInfoJson);
        Assert.Equal("user-123", userInfoDocument.RootElement.GetProperty("sub").GetString());

        DefaultHttpContext introspectionContext = CreateHttpContext(services, HttpMethods.Post);
        introspectionContext.Request.ContentType = "application/x-www-form-urlencoded";
        introspectionContext.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes($"client_id=public-client&token={Uri.EscapeDataString(accessToken)}"));
        await SimpleAuth.Endpoints.IntrospectionEndpoint.HandleAsync(introspectionContext);

        string introspectionJson = await ReadBodyAsync(introspectionContext.Response.Body);
        using JsonDocument introspectionDocument = JsonDocument.Parse(introspectionJson);
        Assert.True(introspectionDocument.RootElement.GetProperty("active").GetBoolean());
        Assert.Equal("public-client", introspectionDocument.RootElement.GetProperty("client_id").GetString());
    }

    [Fact]
    public async Task RefreshTokenFlow_RotatesAndRevokesOldFamily()
    {
        IServiceProvider services = BuildServices();
        string code = await IssueAuthorizationCodeAsync(services);
        (string accessToken, string refreshToken) = await ExchangeCodeForTokensAsync(services, code);

        DefaultHttpContext firstIntrospection = CreateHttpContext(services, HttpMethods.Post);
        firstIntrospection.Request.ContentType = "application/x-www-form-urlencoded";
        firstIntrospection.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes($"client_id=public-client&token={Uri.EscapeDataString(accessToken)}"));
        await SimpleAuth.Endpoints.IntrospectionEndpoint.HandleAsync(firstIntrospection);
        using JsonDocument firstIntrospectionDocument = JsonDocument.Parse(await ReadBodyAsync(firstIntrospection.Response.Body));
        Assert.True(firstIntrospectionDocument.RootElement.GetProperty("active").GetBoolean());

        DefaultHttpContext refreshContext = CreateHttpContext(services, HttpMethods.Post);
        refreshContext.Request.ContentType = "application/x-www-form-urlencoded";
        refreshContext.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(
            $"grant_type=refresh_token&client_id=public-client&refresh_token={Uri.EscapeDataString(refreshToken)}"));

        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(refreshContext);
        using JsonDocument refreshDocument = JsonDocument.Parse(await ReadBodyAsync(refreshContext.Response.Body));
        string nextRefreshToken = refreshDocument.RootElement.GetProperty("refresh_token").GetString()!;
        string nextAccessToken = refreshDocument.RootElement.GetProperty("access_token").GetString()!;

        Assert.False(string.IsNullOrWhiteSpace(nextRefreshToken));
        Assert.False(string.IsNullOrWhiteSpace(nextAccessToken));
        Assert.NotEqual(refreshToken, nextRefreshToken);

        DefaultHttpContext secondUse = CreateHttpContext(services, HttpMethods.Post);
        secondUse.Request.ContentType = "application/x-www-form-urlencoded";
        secondUse.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(
            $"grant_type=refresh_token&client_id=public-client&refresh_token={Uri.EscapeDataString(refreshToken)}"));
        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(secondUse);
        using JsonDocument secondUseDocument = JsonDocument.Parse(await ReadBodyAsync(secondUse.Response.Body));
        Assert.Equal("invalid_grant", secondUseDocument.RootElement.GetProperty("error").GetString());

        DefaultHttpContext revokedIntrospection = CreateHttpContext(services, HttpMethods.Post);
        revokedIntrospection.Request.ContentType = "application/x-www-form-urlencoded";
        revokedIntrospection.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes($"client_id=public-client&token={Uri.EscapeDataString(accessToken)}"));
        await SimpleAuth.Endpoints.IntrospectionEndpoint.HandleAsync(revokedIntrospection);
        using JsonDocument revokedIntrospectionDocument = JsonDocument.Parse(await ReadBodyAsync(revokedIntrospection.Response.Body));
        Assert.False(revokedIntrospectionDocument.RootElement.GetProperty("active").GetBoolean());
    }

    private static async Task IssueAndInspectAuthorizationCodeAsync(IServiceProvider services, string expectedChallenge)
    {
        DefaultHttpContext authorizeContext = CreateHttpContext(services, HttpMethods.Get);
        authorizeContext.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "user-123"),
        ], "cookie"));
        authorizeContext.Request.QueryString = new QueryString(
            $"?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid%20offline_access&state=abc&nonce=n-1&code_challenge={expectedChallenge}&code_challenge_method=S256");

        await SimpleAuth.Endpoints.AuthorizationEndpoint.HandleAsync(authorizeContext);

        Assert.Equal(StatusCodes.Status302Found, authorizeContext.Response.StatusCode);
        string redirect = authorizeContext.Response.Headers.Location.ToString();
        string code = ExtractQueryValue(redirect, "code");
        Assert.False(string.IsNullOrWhiteSpace(code));

        IAuthorizationCodeStore authorizationCodeStore = services.GetRequiredService<IAuthorizationCodeStore>();
        AuthorizationCode? stored = await authorizationCodeStore.ConsumeAsync(code);
        Assert.NotNull(stored);
        Assert.Equal(expectedChallenge, stored!.CodeChallenge);
    }

    private static async Task<string> IssueAuthorizationCodeAsync(IServiceProvider services)
    {
        DefaultHttpContext authorizeContext = CreateHttpContext(services, HttpMethods.Get);
        authorizeContext.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "user-123"),
        ], "cookie"));
        authorizeContext.Request.QueryString = new QueryString(
            "?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid%20offline_access&state=abc&nonce=n-1&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");

        await SimpleAuth.Endpoints.AuthorizationEndpoint.HandleAsync(authorizeContext);

        Assert.Equal(StatusCodes.Status302Found, authorizeContext.Response.StatusCode);
        string redirect = authorizeContext.Response.Headers.Location.ToString();
        string code = ExtractQueryValue(redirect, "code");
        Assert.False(string.IsNullOrWhiteSpace(code));
        return code;
    }

    private static async Task<(string AccessToken, string RefreshToken)> ExchangeCodeForTokensAsync(IServiceProvider services, string code)
    {
        DefaultHttpContext tokenContext = CreateHttpContext(services, HttpMethods.Post);
        tokenContext.Request.ContentType = "application/x-www-form-urlencoded";
        tokenContext.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(
            $"grant_type=authorization_code&client_id=public-client&code={Uri.EscapeDataString(code)}&redirect_uri={Uri.EscapeDataString("https://app.example/callback")}&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

        await SimpleAuth.Endpoints.TokenEndpoint.HandleAsync(tokenContext);

        using JsonDocument tokenDocument = JsonDocument.Parse(await ReadBodyAsync(tokenContext.Response.Body));
        string accessToken = tokenDocument.RootElement.GetProperty("access_token").GetString()!;
        string refreshToken = tokenDocument.RootElement.GetProperty("refresh_token").GetString()!;
        return (accessToken, refreshToken);
    }

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
                    RequireClientSecret = false,
                    RequirePkce = true,
                    AllowOfflineAccess = true,
                    AccessTokenType = AccessTokenType.Reference,
                    RequireConsent = false,
                });
            });
            server.Keys.UseDevelopmentKey();
        });

        return services.BuildServiceProvider();
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
