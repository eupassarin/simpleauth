using System.Net;
using System.Text.Json;
using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// OIDC Conformance: Refresh Token (OAuth 2.1 §6, RFC 6749 §6)
/// Tests refresh token issuance, rotation, revocation, and error handling.
/// </summary>
[Collection("Conformance")]
public sealed class RefreshTokenConformanceTests(ConformanceFixture fixture) : IClassFixture<ConformanceFixture>
{
    private HttpClient Client => fixture.Client;

    [Fact]
    public async Task RefreshToken_IssuedWhenOfflineAccessRequested()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid offline_access", "refresh-user-1");

        Assert.True(tokens.RootElement.TryGetProperty("refresh_token", out _),
            "offline_access scope must result in refresh_token");
    }

    [Fact]
    public async Task RefreshToken_NotIssuedWithoutOfflineAccess()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid", "refresh-user-2");

        Assert.False(tokens.RootElement.TryGetProperty("refresh_token", out JsonElement rt) &&
                     rt.ValueKind == JsonValueKind.String &&
                     !string.IsNullOrEmpty(rt.GetString()),
            "Without offline_access, refresh_token should not be issued");
    }

    [Fact]
    public async Task RefreshToken_Exchange_ReturnsNewAccessToken()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid offline_access", "refresh-user-3");

        string refreshToken = tokens.RootElement.GetProperty("refresh_token").GetString()!;

        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=refresh_token&client_id=public-spa&refresh_token={Uri.EscapeDataString(refreshToken)}"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument newTokens = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(newTokens.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal("Bearer", newTokens.RootElement.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task RefreshToken_Rotation_NewRefreshTokenIssued()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid offline_access", "refresh-user-4");

        string originalRt = tokens.RootElement.GetProperty("refresh_token").GetString()!;

        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=refresh_token&client_id=public-spa&refresh_token={Uri.EscapeDataString(originalRt)}"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument newTokens = await TestHelpers.ParseJsonAsync(resp);

        if (newTokens.RootElement.TryGetProperty("refresh_token", out JsonElement newRt))
        {
            // If rotation is implemented, old RT should differ from new RT
            Assert.NotEqual(originalRt, newRt.GetString());
        }
    }

    [Fact]
    public async Task RefreshToken_OldTokenInvalid_AfterRotation()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid offline_access", "refresh-user-5");

        string originalRt = tokens.RootElement.GetProperty("refresh_token").GetString()!;

        // First refresh succeeds
        HttpResponseMessage first = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=refresh_token&client_id=public-spa&refresh_token={Uri.EscapeDataString(originalRt)}"));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        // Using the old RT again should fail (replay detection)
        HttpResponseMessage second = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=refresh_token&client_id=public-spa&refresh_token={Uri.EscapeDataString(originalRt)}"));
        Assert.True((int)second.StatusCode >= 400, "Old refresh token must be invalid after rotation");
    }

    [Fact]
    public async Task RefreshToken_InvalidToken_ReturnsError()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=refresh_token&client_id=public-spa&refresh_token=invalid-rt-handle"));

        Assert.True((int)resp.StatusCode >= 400);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.Equal("invalid_grant", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task RefreshToken_WrongClient_ReturnsError()
    {
        // Get a refresh token for public-spa
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid offline_access", "refresh-user-6");

        string refreshToken = tokens.RootElement.GetProperty("refresh_token").GetString()!;

        // Try to use it with a different client
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=refresh_token&client_id=confidential-code&client_secret=secret123" +
                            $"&refresh_token={Uri.EscapeDataString(refreshToken)}"));

        Assert.True((int)resp.StatusCode >= 400, "Refresh token must be bound to original client");
    }

    [Fact]
    public async Task RefreshToken_IdTokenReissued_OnRefresh()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback",
            "openid offline_access", "refresh-user-7");

        string refreshToken = tokens.RootElement.GetProperty("refresh_token").GetString()!;

        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=refresh_token&client_id=public-spa&refresh_token={Uri.EscapeDataString(refreshToken)}"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument newTokens = await TestHelpers.ParseJsonAsync(resp);

        // ID token may or may not be reissued on refresh — if present, verify it's valid
        if (newTokens.RootElement.TryGetProperty("id_token", out JsonElement idToken) &&
            idToken.ValueKind == JsonValueKind.String)
        {
            using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken.GetString()!);
            Assert.True(payload.RootElement.TryGetProperty("sub", out _));
        }
    }
}
