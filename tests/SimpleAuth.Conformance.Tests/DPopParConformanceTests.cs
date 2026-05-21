using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// OIDC Conformance: DPoP (RFC 9449) and PAR (RFC 9126)
/// Tests Demonstrating Proof of Possession and Pushed Authorization Requests.
/// </summary>
[Collection("Conformance")]
public sealed class DPopParConformanceTests(ConformanceFixture fixture) : IClassFixture<ConformanceFixture>
{
    private HttpClient Client => fixture.Client;

    // ── DPoP (RFC 9449) ───────────────────────────────────────────────────────

    [Fact]
    public async Task DPoP_ValidProof_TokenTypeIsDPoP()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string proof = TestHelpers.CreateDPopProof(key, HttpMethod.Post, "http://localhost/connect/token");

        using HttpRequestMessage req = new(HttpMethod.Post, "/connect/token")
        {
            Content = TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"),
        };
        req.Headers.Add("DPoP", proof);

        HttpResponseMessage resp = await Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.Equal("DPoP", doc.RootElement.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task DPoP_AccessTokenContainsCnfJkt()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string proof = TestHelpers.CreateDPopProof(key, HttpMethod.Post, "http://localhost/connect/token");

        using HttpRequestMessage req = new(HttpMethod.Post, "/connect/token")
        {
            Content = TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"),
        };
        req.Headers.Add("DPoP", proof);

        HttpResponseMessage resp = await Client.SendAsync(req);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        string accessToken = doc.RootElement.GetProperty("access_token").GetString()!;

        // JWT access tokens should contain cnf.jkt
        if (accessToken.Count(c => c == '.') == 2)
        {
            using JsonDocument payload = TestHelpers.DecodeJwtPayload(accessToken);
            Assert.True(payload.RootElement.TryGetProperty("cnf", out JsonElement cnf));
            Assert.True(cnf.TryGetProperty("jkt", out JsonElement jkt));
            Assert.False(string.IsNullOrWhiteSpace(jkt.GetString()));
        }
    }

    [Fact]
    public async Task DPoP_WithoutProof_TokenTypeIsBearer()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/token",
            TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"));

        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.Equal("Bearer", doc.RootElement.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task DPoP_InvalidProofFormat_Returns400()
    {
        using HttpRequestMessage req = new(HttpMethod.Post, "/connect/token")
        {
            Content = TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"),
        };
        req.Headers.Add("DPoP", "not-a-valid-jwt");

        HttpResponseMessage resp = await Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.Equal("invalid_dpop_proof", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task DPoP_WrongHttpMethod_Returns400()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // htm = GET but actual request is POST
        string proof = TestHelpers.CreateDPopProof(key, HttpMethod.Get, "http://localhost/connect/token");

        using HttpRequestMessage req = new(HttpMethod.Post, "/connect/token")
        {
            Content = TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"),
        };
        req.Headers.Add("DPoP", proof);

        HttpResponseMessage resp = await Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task DPoP_WrongHtu_Returns400()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // htu points to wrong endpoint
        string proof = TestHelpers.CreateDPopProof(key, HttpMethod.Post, "http://localhost/connect/userinfo");

        using HttpRequestMessage req = new(HttpMethod.Post, "/connect/token")
        {
            Content = TestHelpers.Form("grant_type=client_credentials&client_id=m2m-service&client_secret=m2m-secret&scope=api"),
        };
        req.Headers.Add("DPoP", proof);

        HttpResponseMessage resp = await Client.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // ── PAR (RFC 9126) ────────────────────────────────────────────────────────

    [Fact]
    public async Task Par_Returns201WithRequestUri()
    {
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());

        HttpResponseMessage resp = await Client.PostAsync("/connect/par",
            TestHelpers.Form($"response_type=code&client_id=public-spa" +
                            $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                            $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256"));

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        string? requestUri = doc.RootElement.GetProperty("request_uri").GetString();
        Assert.StartsWith("urn:ietf:params:oauth:request-uri:", requestUri);
    }

    [Fact]
    public async Task Par_ExpiresInIsPositive()
    {
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());

        HttpResponseMessage resp = await Client.PostAsync("/connect/par",
            TestHelpers.Form($"response_type=code&client_id=public-spa" +
                            $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                            $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256"));

        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.True(doc.RootElement.GetProperty("expires_in").GetInt32() > 0);
    }

    [Fact]
    public async Task Par_RequestUriIsOneTimeUse()
    {
        string verifier = TestHelpers.GenerateCodeVerifier();
        string challenge = TestHelpers.ComputeS256Challenge(verifier);

        HttpResponseMessage parResp = await Client.PostAsync("/connect/par",
            TestHelpers.Form($"response_type=code&client_id=public-spa" +
                            $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                            $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256"));

        using JsonDocument parDoc = await TestHelpers.ParseJsonAsync(parResp);
        string requestUri = parDoc.RootElement.GetProperty("request_uri").GetString()!;

        // First use
        string authorizeUrl = $"/connect/authorize?client_id=public-spa&request_uri={Uri.EscapeDataString(requestUri)}";
        using HttpRequestMessage first = TestHelpers.AuthorizeRequest(authorizeUrl, "alice");
        HttpResponseMessage firstResp = await Client.SendAsync(first);
        Assert.Equal(HttpStatusCode.Redirect, firstResp.StatusCode);

        // Second use — must fail
        using HttpRequestMessage second = TestHelpers.AuthorizeRequest(authorizeUrl, "alice");
        HttpResponseMessage secondResp = await Client.SendAsync(second);
        Assert.Equal(HttpStatusCode.BadRequest, secondResp.StatusCode);
    }

    [Fact]
    public async Task Par_InvalidRequestUri_Returns400()
    {
        string url = "/connect/authorize?client_id=public-spa&request_uri=urn:ietf:params:oauth:request-uri:fake";
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        using JsonDocument doc = await TestHelpers.ParseJsonAsync(resp);
        Assert.Equal("invalid_request", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Par_FullFlow_CompletesTokenExchange()
    {
        string verifier = TestHelpers.GenerateCodeVerifier();
        string challenge = TestHelpers.ComputeS256Challenge(verifier);

        // Step 1: PAR
        HttpResponseMessage parResp = await Client.PostAsync("/connect/par",
            TestHelpers.Form($"response_type=code&client_id=public-spa" +
                            $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                            $"&scope=openid&state=par-state&nonce=par-nonce" +
                            $"&code_challenge={challenge}&code_challenge_method=S256"));

        using JsonDocument parDoc = await TestHelpers.ParseJsonAsync(parResp);
        string requestUri = parDoc.RootElement.GetProperty("request_uri").GetString()!;

        // Step 2: Authorize with request_uri
        string authorizeUrl = $"/connect/authorize?client_id=public-spa&request_uri={Uri.EscapeDataString(requestUri)}";
        using HttpRequestMessage authorizeReq = TestHelpers.AuthorizeRequest(authorizeUrl, "par-user");
        HttpResponseMessage authorizeResp = await Client.SendAsync(authorizeReq);

        Assert.Equal(HttpStatusCode.Redirect, authorizeResp.StatusCode);
        string? code = TestHelpers.GetQueryParam(authorizeResp.Headers.Location!.ToString(), "code");
        Assert.NotNull(code);

        // Step 3: Token exchange
        HttpResponseMessage tokenResp = await Client.PostAsync("/connect/token",
            TestHelpers.Form($"grant_type=authorization_code&client_id=public-spa" +
                            $"&code={Uri.EscapeDataString(code!)}" +
                            $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                            $"&code_verifier={verifier}"));

        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        using JsonDocument tokenDoc = await TestHelpers.ParseJsonAsync(tokenResp);
        Assert.True(tokenDoc.RootElement.TryGetProperty("access_token", out _));
        Assert.True(tokenDoc.RootElement.TryGetProperty("id_token", out _));
    }

    [Fact]
    public async Task Par_MissingPkce_ReturnsError()
    {
        HttpResponseMessage resp = await Client.PostAsync("/connect/par",
            TestHelpers.Form($"response_type=code&client_id=public-spa" +
                            $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                            $"&scope=openid"));

        // PKCE is required — PAR without it should fail
        Assert.True((int)resp.StatusCode >= 400);
    }

    [Fact]
    public async Task Par_UnknownClient_ReturnsError()
    {
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());

        HttpResponseMessage resp = await Client.PostAsync("/connect/par",
            TestHelpers.Form($"response_type=code&client_id=nonexistent" +
                            $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                            $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256"));

        Assert.True((int)resp.StatusCode >= 400);
    }
}
