using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// OIDC Conformance: Token Revocation (RFC 7009) and Introspection (RFC 7662)
/// Tests revocation behavior and introspection responses for active/revoked tokens.
/// </summary>
[Collection("Conformance")]
public sealed class RevocationIntrospectionConformanceTests(ConformanceFixture fixture) : IClassFixture<ConformanceFixture>
{
    private HttpClient Client => fixture.Client;

    // ── Revocation (RFC 7009) ─────────────────────────────────────────────────

    [Fact]
    public async Task Revocation_ValidAccessToken_Returns200()
    {
        string accessToken = await GetAccessTokenM2MAsync();

        HttpResponseMessage resp = await Client.PostAsync("/connect/revocation",
            TestHelpers.Form($"token={Uri.EscapeDataString(accessToken)}" +
                            $"&client_id=m2m-service&client_secret=m2m-secret"));

        // RFC 7009 §2.1: The server responds with HTTP 200 for both valid and invalid tokens
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Revocation_InvalidToken_Returns200()
    {
        // RFC 7009 §2.1: Server MUST respond 200 even for invalid tokens
        HttpResponseMessage resp = await Client.PostAsync("/connect/revocation",
            TestHelpers.Form("token=totally-invalid-token&client_id=m2m-service&client_secret=m2m-secret"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Revocation_RevokedToken_NotUsableAtUserInfo()
    {
        // Get an access token via auth code flow
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid profile", "revoke-user-1");

        string accessToken = tokens.RootElement.GetProperty("access_token").GetString()!;

        // Revoke it
        await Client.PostAsync("/connect/revocation",
            TestHelpers.Form($"token={Uri.EscapeDataString(accessToken)}&client_id=public-spa"));

        // Try to use it at userinfo
        using HttpRequestMessage req = new(HttpMethod.Get, "/connect/userinfo");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        HttpResponseMessage resp = await Client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Revocation_RefreshToken_Invalidates()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid offline_access", "revoke-user-2");

        string refreshToken = tokens.RootElement.GetProperty("refresh_token").GetString()!;

        // Revoke the refresh token (with hint per RFC 7009 §2.1)
        await Client.PostAsync("/connect/revocation",
            TestHelpers.Form($"token={Uri.EscapeDataString(refreshToken)}&token_type_hint=refresh_token&client_id=public-spa"));

        // Try to use it
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=refresh_token&client_id=public-spa&refresh_token={Uri.EscapeDataString(refreshToken)}"));

        Assert.True((int)resp.StatusCode >= 400, "Revoked refresh token must be rejected");
    }

    [Fact]
    public async Task Revocation_WithoutClientAuth_Returns401()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/revocation",
            TestHelpers.Form("token=some-token"));

        // Without client_id, server can't identify caller
        Assert.True((int)resp.StatusCode is 400 or 401);
    }

    // ── Introspection (RFC 7662) ──────────────────────────────────────────────

    [Fact]
    public async Task Introspection_ActiveToken_ReturnsActiveTrue()
    {
        string accessToken = await GetAccessTokenM2MAsync();

        HttpResponseMessage resp = await Client.PostAsync("/connect/introspect",
            TestHelpers.Form($"token={Uri.EscapeDataString(accessToken)}" +
                            $"&client_id=m2m-service&client_secret=m2m-secret"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(doc.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Introspection_ActiveToken_ContainsExpectedClaims()
    {
        string accessToken = await GetAccessTokenM2MAsync();

        HttpResponseMessage resp = await Client.PostAsync("/connect/introspect",
            TestHelpers.Form($"token={Uri.EscapeDataString(accessToken)}" +
                            $"&client_id=m2m-service&client_secret=m2m-secret"));

        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        JsonElement root = doc.RootElement;

        // RFC 7662 §2.2: SHOULD include these for active tokens
        Assert.True(root.TryGetProperty("client_id", out _), "Active token introspection should have client_id");
    }

    [Fact]
    public async Task Introspection_InvalidToken_ReturnsActiveFalse()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/introspect",
            TestHelpers.Form("token=invalid-token-xyz&client_id=m2m-service&client_secret=m2m-secret"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.False(doc.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Introspection_RevokedToken_ReturnsActiveFalse()
    {
        // Use a reference token (via auth code flow) so revocation is effective
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid", "introspect-revoke-user");

        string accessToken = tokens.RootElement.GetProperty("access_token").GetString()!;

        // Revoke first
        await Client.PostAsync("/connect/revocation",
            TestHelpers.Form($"token={Uri.EscapeDataString(accessToken)}&client_id=public-spa"));

        // Introspect — public-spa uses Reference tokens, so the m2m client can introspect
        HttpResponseMessage resp = await Client.PostAsync("/connect/introspect",
            TestHelpers.Form($"token={Uri.EscapeDataString(accessToken)}" +
                            $"&client_id=m2m-service&client_secret=m2m-secret"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.False(doc.RootElement.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Introspection_WithoutClientAuth_Returns401()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/introspect",
            TestHelpers.Form("token=some-token"));

        Assert.True((int)resp.StatusCode is 400 or 401);
    }

    [Fact]
    public async Task Introspection_ContentTypeIsJson()
    {
        string accessToken = await GetAccessTokenM2MAsync();

        HttpResponseMessage resp = await Client.PostAsync("/connect/introspect",
            TestHelpers.Form($"token={Uri.EscapeDataString(accessToken)}" +
                            $"&client_id=m2m-service&client_secret=m2m-secret"));

        Assert.Equal("application/json", resp.Content.Headers.ContentType?.MediaType);
    }

    private async Task<string> GetAccessTokenM2MAsync()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"));
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        return doc.RootElement.GetProperty("access_token").GetString()!;
    }
}
