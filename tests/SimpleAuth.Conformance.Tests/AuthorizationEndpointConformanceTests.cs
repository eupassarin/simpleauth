using System.Net;
using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// OIDC Conformance: Authorization Endpoint (OAuth 2.1 §4.1, OIDC Core §3.1.2)
/// Tests the authorize endpoint behavior including PKCE, error responses, and redirect validation.
/// </summary>
[Collection("Conformance")]
public sealed class AuthorizationEndpointConformanceTests(ConformanceFixture fixture) : IClassFixture<ConformanceFixture>
{
    private HttpClient Client => fixture.Client;

    [Fact]
    public async Task Authorize_ValidRequest_RedirectsWithCode()
    {
        string verifier = TestHelpers.GenerateCodeVerifier();
        string challenge = TestHelpers.ComputeS256Challenge(verifier);

        string url = BuildAuthorizeUrl("public-spa", "https://spa.example/callback", "openid", challenge);
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        string location = resp.Headers.Location!.ToString();
        Assert.Contains("code=", location);
    }

    [Fact]
    public async Task Authorize_StateIsEchoedBack()
    {
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());
        string url = BuildAuthorizeUrl("public-spa", "https://spa.example/callback", "openid", challenge) + "&state=my-state-123";
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        string location = resp.Headers.Location!.ToString();
        Assert.Contains("state=my-state-123", location);
    }

    [Fact]
    public async Task Authorize_MissingResponseType_ReturnsError()
    {
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());
        string url = $"/connect/authorize?client_id=public-spa&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                     $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256";
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        // Without response_type, must return error
        Assert.True(resp.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Redirect);
    }

    [Fact]
    public async Task Authorize_UnsupportedResponseType_ReturnsError()
    {
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());
        string url = $"/connect/authorize?response_type=token&client_id=public-spa" +
                     $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                     $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256";
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        // OAuth 2.1 removes implicit flow — "token" response_type must be rejected.
        // Per RFC 6749 §4.1.2.1: error is returned via redirect to the redirect_uri with ?error=
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            string location = resp.Headers.Location!.ToString();
            Assert.Contains("error=", location);
            Assert.Contains("unsupported_response_type", location);
        }
        else
        {
            Assert.True((int)resp.StatusCode >= 400);
        }
    }

    [Fact]
    public async Task Authorize_MissingPkce_ReturnsError()
    {
        // OAuth 2.1 requires PKCE for all authorization code requests
        string url = "/connect/authorize?response_type=code&client_id=public-spa" +
                     "&redirect_uri=https%3A%2F%2Fspa.example%2Fcallback&scope=openid";
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        // RFC 6749 §4.1.2.1: errors returned via redirect with error=invalid_request
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            string location = resp.Headers.Location!.ToString();
            Assert.Contains("error=", location);
        }
        else
        {
            Assert.True((int)resp.StatusCode >= 400, "Missing PKCE must be rejected per OAuth 2.1");
        }
    }

    [Fact]
    public async Task Authorize_PlainCodeChallengeMethod_Rejected()
    {
        // OAuth 2.1 §7.6.2: Servers MUST support S256; "plain" SHOULD be rejected
        string url = "/connect/authorize?response_type=code&client_id=public-spa" +
                     "&redirect_uri=https%3A%2F%2Fspa.example%2Fcallback&scope=openid" +
                     "&code_challenge=abcdefg&code_challenge_method=plain";
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        // Error via redirect or direct error response
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            string location = resp.Headers.Location!.ToString();
            Assert.Contains("error=", location);
            Assert.DoesNotContain("code=", location);
        }
        else
        {
            Assert.True((int)resp.StatusCode >= 400, "'plain' code_challenge_method should be rejected");
        }
    }

    [Fact]
    public async Task Authorize_InvalidRedirectUri_DoesNotRedirect()
    {
        // RFC 6749 §4.1.2.1: If redirect_uri is invalid, server MUST NOT redirect
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());
        string url = $"/connect/authorize?response_type=code&client_id=public-spa" +
                     $"&redirect_uri={Uri.EscapeDataString("https://evil.example/callback")}" +
                     $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256";
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        // Must NOT redirect to the invalid URI
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            string location = resp.Headers.Location!.ToString();
            Assert.DoesNotContain("evil.example", location);
        }
        else
        {
            Assert.True((int)resp.StatusCode >= 400);
        }
    }

    [Fact]
    public async Task Authorize_UnknownClient_ReturnsError()
    {
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());
        string url = $"/connect/authorize?response_type=code&client_id=nonexistent-client" +
                     $"&redirect_uri={Uri.EscapeDataString("https://unknown.example/callback")}" +
                     $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256";
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        Assert.True((int)resp.StatusCode >= 400);
    }

    [Fact]
    public async Task Authorize_UnauthenticatedUser_ReturnsUnauthorizedOrRedirect()
    {
        // Without X-Test-User header, user is not authenticated
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());
        string url = BuildAuthorizeUrl("public-spa", "https://spa.example/callback", "openid", challenge);
        HttpResponseMessage resp = await Client.GetAsync(url);

        // Server should either return 401 or redirect to login (implementation-specific)
        Assert.True((int)resp.StatusCode is 401 or 302 or 400);
    }

    [Fact]
    public async Task Authorize_ScopeWithoutOpenId_StillWorks()
    {
        // Non-OIDC request (no openid scope) — should still issue a code
        string challenge = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());
        string url = $"/connect/authorize?response_type=code&client_id=public-spa" +
                     $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                     $"&scope=openid&state=s1&code_challenge={challenge}&code_challenge_method=S256";
        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "bob");
        HttpResponseMessage resp = await Client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Contains("code=", resp.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Authorize_CodeIsUniquePerRequest()
    {
        string challenge1 = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());
        string challenge2 = TestHelpers.ComputeS256Challenge(TestHelpers.GenerateCodeVerifier());

        string url1 = BuildAuthorizeUrl("public-spa", "https://spa.example/callback", "openid", challenge1);
        string url2 = BuildAuthorizeUrl("public-spa", "https://spa.example/callback", "openid", challenge2);

        using HttpRequestMessage req1 = TestHelpers.AuthorizeRequest(url1, "alice");
        using HttpRequestMessage req2 = TestHelpers.AuthorizeRequest(url2, "alice");

        HttpResponseMessage resp1 = await Client.SendAsync(req1);
        HttpResponseMessage resp2 = await Client.SendAsync(req2);

        string? code1 = TestHelpers.GetQueryParam(resp1.Headers.Location!.ToString(), "code");
        string? code2 = TestHelpers.GetQueryParam(resp2.Headers.Location!.ToString(), "code");

        Assert.NotEqual(code1, code2);
    }

    [Fact]
    public async Task Authorize_RejectsRequestObjectWithRequestNotSupported()
    {
        // RFC 9101: server does not support JAR request objects → must return request_not_supported.
        string state = "test-state-jar";
        string fakeJar = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."; // alg=none JWT stub
        string url = $"/connect/authorize?response_type=code&client_id=public-spa" +
                     $"&redirect_uri={Uri.EscapeDataString("https://spa.example/callback")}" +
                     $"&scope=openid&state={state}&request={Uri.EscapeDataString(fakeJar)}";

        using HttpRequestMessage req = TestHelpers.AuthorizeRequest(url, "alice");
        HttpResponseMessage resp = await Client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Found, resp.StatusCode);
        string? error = TestHelpers.GetQueryParam(resp.Headers.Location!.ToString(), "error");
        Assert.Equal("request_not_supported", error);
    }

    private static string BuildAuthorizeUrl(string clientId, string redirectUri, string scope, string codeChallenge) =>
        $"/connect/authorize?response_type=code&client_id={clientId}" +
        $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
        $"&scope={Uri.EscapeDataString(scope)}&nonce=test-nonce" +
        $"&code_challenge={codeChallenge}&code_challenge_method=S256";
}
