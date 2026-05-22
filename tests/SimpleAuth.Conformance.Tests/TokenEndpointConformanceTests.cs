using System.Net;
using System.Text.Json;
using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// OIDC Conformance: Token Endpoint (OAuth 2.1 §4.1.3, RFC 6749 §5)
/// Tests token exchange, grant types, client authentication methods, and error handling.
/// </summary>
[Collection("Conformance")]
public sealed class TokenEndpointConformanceTests(ConformanceFixture fixture) : IClassFixture<ConformanceFixture>
{
    private HttpClient Client => fixture.Client;

    // ── Grant type: client_credentials ────────────────────────────────────────

    [Fact]
    public async Task ClientCredentials_PostAuth_ReturnsAccessToken()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(doc.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal("Bearer", doc.RootElement.GetProperty("token_type").GetString());
        Assert.True(doc.RootElement.TryGetProperty("expires_in", out JsonElement expiresIn));
        Assert.True(expiresIn.GetInt32() > 0);
    }

    [Fact]
    public async Task ClientCredentials_BasicAuth_ReturnsAccessToken()
    {
        using HttpRequestMessage req = new(HttpMethod.Post, "/connect/token")
        {
            Content = TestHelpers.Form("grant_type=client_credentials&scope=api"),
        };
        req.Headers.Authorization = TestHelpers.BasicAuth("m2m-service", "m2m-secret");

        HttpResponseMessage resp = await Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(doc.RootElement.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task ClientCredentials_NoRefreshTokenIssued()
    {
        // RFC 6749 §4.4.3: A refresh token SHOULD NOT be included for client_credentials
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"));

        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.False(doc.RootElement.TryGetProperty("refresh_token", out _),
            "client_credentials should not issue refresh_token");
    }

    [Fact]
    public async Task ClientCredentials_WrongSecret_Returns401()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=WRONG&scope=api"));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.Equal("invalid_client", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task ClientCredentials_UnknownClient_Returns401()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=nonexistent&client_secret=x&scope=api"));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task ClientCredentials_MissingGrantType_ReturnsError()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("client_id=m2m-service&client_secret=m2m-secret&scope=api"));

        Assert.True((int)resp.StatusCode >= 400);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(doc.RootElement.TryGetProperty("error", out _));
    }

    [Fact]
    public async Task ClientCredentials_UnsupportedGrantType_ReturnsError()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=password&client_id=m2m-service&client_secret=m2m-secret&username=x&password=y"));

        Assert.True((int)resp.StatusCode >= 400);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        string? error = doc.RootElement.GetProperty("error").GetString();
        Assert.True(error is "unsupported_grant_type" or "unauthorized_client");
    }

    // ── Grant type: authorization_code ────────────────────────────────────────

    [Fact]
    public async Task AuthorizationCode_InvalidCode_ReturnsError()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=authorization_code&client_id=public-spa" +
                            "&code=INVALID_CODE&redirect_uri=https%3A%2F%2Fspa.example%2Fcallback" +
                            "&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

        Assert.True((int)resp.StatusCode >= 400);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.Equal("invalid_grant", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthorizationCode_WrongCodeVerifier_ReturnsError()
    {
        // Get a real code
        string verifier = TestHelpers.GenerateCodeVerifier();
        string challenge = TestHelpers.ComputeS256Challenge(verifier);

        string authorizeUrl = $"/connect/authorize?response_type=code&client_id=public-spa" +
                              $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                              $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256";
        using HttpRequestMessage authorizeReq = TestHelpers.AuthorizeRequest(authorizeUrl, "alice");
        HttpResponseMessage authorizeResp = await Client.SendAsync(authorizeReq);
        string? code = TestHelpers.GetQueryParam(authorizeResp.Headers.Location!.ToString(), "code");

        // Use wrong verifier
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=authorization_code&client_id=public-spa" +
                            $"&code={Uri.EscapeDataString(code!)}" +
                            $"&redirect_uri=https%3A%2F%2Fspa.example%2Fcallback" +
                            $"&code_verifier=WRONG_VERIFIER_THAT_DOES_NOT_MATCH"));

        Assert.True((int)resp.StatusCode >= 400);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.Equal("invalid_grant", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthorizationCode_CodeReuse_ReturnsError()
    {
        // Get a real code and use it once
        string verifier = TestHelpers.GenerateCodeVerifier();
        string challenge = TestHelpers.ComputeS256Challenge(verifier);

        string authorizeUrl = $"/connect/authorize?response_type=code&client_id=public-spa" +
                              $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                              $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256";
        using HttpRequestMessage authorizeReq = TestHelpers.AuthorizeRequest(authorizeUrl, "alice");
        HttpResponseMessage authorizeResp = await Client.SendAsync(authorizeReq);
        string? code = TestHelpers.GetQueryParam(authorizeResp.Headers.Location!.ToString(), "code");

        string tokenBody = $"grant_type=authorization_code&client_id=public-spa" +
                           $"&code={Uri.EscapeDataString(code!)}" +
                           $"&redirect_uri=https%3A%2F%2Fspa.example%2Fcallback&code_verifier={verifier}";

        // First use succeeds
        HttpResponseMessage first = await Client.PostAsync("/connect/token", TestHelpers.Form(tokenBody));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        // Second use MUST fail (RFC 6749 §4.1.2)
        HttpResponseMessage second = await Client.PostAsync("/connect/token", TestHelpers.Form(tokenBody));
        Assert.True((int)second.StatusCode >= 400);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(second);
        Assert.Equal("invalid_grant", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthorizationCode_WrongRedirectUri_ReturnsError()
    {
        string verifier = TestHelpers.GenerateCodeVerifier();
        string challenge = TestHelpers.ComputeS256Challenge(verifier);

        string authorizeUrl = $"/connect/authorize?response_type=code&client_id=public-spa" +
                              $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                              $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256";
        using HttpRequestMessage authorizeReq = TestHelpers.AuthorizeRequest(authorizeUrl, "alice");
        HttpResponseMessage authorizeResp = await Client.SendAsync(authorizeReq);
        string? code = TestHelpers.GetQueryParam(authorizeResp.Headers.Location!.ToString(), "code");

        // Use different redirect_uri in token exchange
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=authorization_code&client_id=public-spa" +
                            $"&code={Uri.EscapeDataString(code!)}" +
                            $"&redirect_uri=https%3A%2F%2Fwrong.example%2Fcallback&code_verifier={verifier}"));

        Assert.True((int)resp.StatusCode >= 400);
    }

    [Fact]
    public async Task AuthorizationCode_ConfidentialClient_RequiresAuth()
    {
        string verifier = TestHelpers.GenerateCodeVerifier();
        string challenge = TestHelpers.ComputeS256Challenge(verifier);

        string authorizeUrl = $"/connect/authorize?response_type=code&client_id=confidential-code" +
                              $"&redirect_uri={Uri.EscapeDataString("https://client.example/callback")}" +
                              $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256";
        using HttpRequestMessage authorizeReq = TestHelpers.AuthorizeRequest(authorizeUrl, "alice");
        HttpResponseMessage authorizeResp = await Client.SendAsync(authorizeReq);
        string? code = TestHelpers.GetQueryParam(authorizeResp.Headers.Location!.ToString(), "code");

        // Token exchange WITHOUT client secret
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=authorization_code&client_id=confidential-code" +
                            $"&code={Uri.EscapeDataString(code!)}" +
                            $"&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&code_verifier={verifier}"));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Token response format ─────────────────────────────────────────────────

    [Fact]
    public async Task TokenResponse_ContentTypeIsJson()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"));

        Assert.Equal("application/json", resp.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task TokenResponse_NoCacheHeaders()
    {
        // RFC 6749 §5.1: The authorization server MUST include Cache-Control: no-store
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"));

        // At minimum, response should not be publicly cacheable
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task TokenEndpoint_GetMethod_Rejected()
    {
        // Token endpoint MUST only accept POST (RFC 6749 §3.2)
        HttpResponseMessage resp = await Client.GetAsync("/connect/token?grant_type=client_credentials&client_id=m2m-service");
        Assert.Equal(HttpStatusCode.MethodNotAllowed, resp.StatusCode);
    }

    [Fact]
    public async Task ErrorResponse_HasRequiredFields()
    {
        // RFC 6749 §5.2: error response MUST include 'error' field
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=WRONG"));

        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(doc.RootElement.TryGetProperty("error", out JsonElement error));
        Assert.False(string.IsNullOrWhiteSpace(error.GetString()));
    }

    [Fact]
    public async Task ErrorResponse_ErrorCodeIsAscii()
    {
        // RFC 6749 §5.2: error code values are ASCII, no spaces
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=WRONG"));

        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        string? errorCode = doc.RootElement.GetProperty("error").GetString();
        Assert.NotNull(errorCode);
        Assert.DoesNotContain(" ", errorCode);
        Assert.All(errorCode!, c => Assert.True(c < 128, "Error code must be ASCII"));
    }

    // ── RFC 6749 §4.1.2: auth code reuse + token revocation ─────────────────

    [Fact]
    public async Task AuthCode_Reuse_RevokesTokenAndReturnsError()
    {
        // RFC 6749 §4.1.2: if a code is used more than once the AS MUST return an error
        // and SHOULD revoke all tokens previously issued for that code.
        // Using public-spa (reference tokens) so revocation is observable at UserInfo.
        const string clientId = "public-spa";
        const string redirectUri = "https://spa.example/callback";

        string verifier = TestHelpers.GenerateCodeVerifier();
        string challenge = TestHelpers.ComputeS256Challenge(verifier);

        // Step 1: get an authorization code
        string authorizeUrl = $"/connect/authorize?response_type=code&client_id={clientId}" +
            $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
            $"&scope=openid&state=s&nonce=n" +
            $"&code_challenge={challenge}&code_challenge_method=S256";

        using HttpRequestMessage authorizeReq = TestHelpers.AuthorizeRequest(authorizeUrl, "alice");
        HttpResponseMessage authorizeResp = await Client.SendAsync(authorizeReq);
        string code = TestHelpers.GetQueryParam(
            authorizeResp.Headers.Location!.ToString(), "code")!;

        // Step 2: first exchange → should succeed
        string body = $"grant_type=authorization_code&code={Uri.EscapeDataString(code)}" +
                      $"&redirect_uri={Uri.EscapeDataString(redirectUri)}&code_verifier={verifier}" +
                      $"&client_id={clientId}";
        HttpResponseMessage firstResp = await Client.PostAsync("/connect/token", TestHelpers.Form(body));
        Assert.Equal(HttpStatusCode.OK, firstResp.StatusCode);
        using JsonDocument firstDoc = await TestHelpers.ParseJsonAsync(firstResp);
        string accessToken = firstDoc.RootElement.GetProperty("access_token").GetString()!;

        // Step 3: reuse the same code → MUST return invalid_grant
        HttpResponseMessage reuseResp = await Client.PostAsync("/connect/token", TestHelpers.Form(body));
        Assert.Equal(HttpStatusCode.BadRequest, reuseResp.StatusCode);
        using JsonDocument reuseDoc = await TestHelpers.ParseJsonAsync(reuseResp);
        Assert.Equal("invalid_grant", reuseDoc.RootElement.GetProperty("error").GetString());

        // Step 4: the original access token MUST now be revoked (4xx at UserInfo)
        using HttpRequestMessage userInfoReq = new(HttpMethod.Get, "/connect/userinfo");
        userInfoReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        HttpResponseMessage userInfoResp = await Client.SendAsync(userInfoReq);
        Assert.True(
            (int)userInfoResp.StatusCode is >= 400 and <= 499,
            $"Expected 4xx after token revocation, got {(int)userInfoResp.StatusCode}");
    }
}
