using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// OIDC Conformance: UserInfo Endpoint (OIDC Core §5.3)
/// Tests bearer token validation, claim responses, and error handling.
/// </summary>
[Collection("Conformance")]
public sealed class UserInfoConformanceTests(ConformanceFixture fixture) : IClassFixture<ConformanceFixture>
{
    private HttpClient Client => fixture.Client;

    [Fact]
    public async Task UserInfo_WithValidToken_ReturnsSubClaim()
    {
        string accessToken = await GetAccessTokenAsync("openid profile email");

        using HttpRequestMessage req = new(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        HttpResponseMessage resp = await Client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(doc.RootElement.TryGetProperty("sub", out JsonElement sub));
        Assert.False(string.IsNullOrWhiteSpace(sub.GetString()));
    }

    [Fact]
    public async Task UserInfo_SubMatchesIdToken()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback", "openid profile", "alice");

        string idToken = tokens.RootElement.GetProperty("id_token").GetString()!;
        string accessToken = tokens.RootElement.GetProperty("access_token").GetString()!;

        using JsonDocument idPayload = TestHelpers.DecodeJwtPayload(idToken);
        string? idSub = idPayload.RootElement.GetProperty("sub").GetString();

        using HttpRequestMessage req = new(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        HttpResponseMessage resp = await Client.SendAsync(req);

        using JsonDocument userInfo = await TestHelpers.ParseJsonAsync(resp);
        string? uiSub = userInfo.RootElement.GetProperty("sub").GetString();

        Assert.Equal(idSub, uiSub);
    }

    [Fact]
    public async Task UserInfo_ProfileScopeReturnsClaims()
    {
        string accessToken = await GetAccessTokenAsync("openid profile");

        using HttpRequestMessage req = new(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        HttpResponseMessage resp = await Client.SendAsync(req);

        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        // Profile scope should return name/preferred_username (from our test enricher)
        Assert.True(doc.RootElement.TryGetProperty("name", out _) ||
                    doc.RootElement.TryGetProperty("preferred_username", out _),
            "Profile scope should return profile claims");
    }

    [Fact]
    public async Task UserInfo_EmailScopeReturnsClaims()
    {
        string accessToken = await GetAccessTokenAsync("openid email");

        using HttpRequestMessage req = new(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        HttpResponseMessage resp = await Client.SendAsync(req);

        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(doc.RootElement.TryGetProperty("email", out _), "Email scope should return email claim");
    }

    [Fact]
    public async Task UserInfo_WithoutToken_Returns401()
    {
        HttpResponseMessage resp = await Client.GetAsync("/connect/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task UserInfo_WithInvalidToken_Returns401()
    {
        using HttpRequestMessage req = new(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid.token.value");
        HttpResponseMessage resp = await Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task UserInfo_PostMethod_Works()
    {
        // OIDC Core §5.3.1: UserInfo SHOULD support POST
        string accessToken = await GetAccessTokenAsync("openid");

        using HttpRequestMessage req = new(HttpMethod.Post, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        req.Content = new StringContent(string.Empty);
        HttpResponseMessage resp = await Client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(doc.RootElement.TryGetProperty("sub", out _));
    }

    [Fact]
    public async Task UserInfo_ContentTypeIsJson()
    {
        string accessToken = await GetAccessTokenAsync("openid");

        using HttpRequestMessage req = new(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        HttpResponseMessage resp = await Client.SendAsync(req);

        Assert.Equal("application/json", resp.Content.Headers.ContentType?.MediaType);
    }

    private async Task<string> GetAccessTokenAsync(string scope)
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback", scope, "userinfo-test-user");

        return tokens.RootElement.GetProperty("access_token").GetString()!;
    }
}
