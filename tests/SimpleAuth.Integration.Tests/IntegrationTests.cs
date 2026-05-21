using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.TestHost;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SimpleAuth.Crypto;
using Xunit;

namespace SimpleAuth.Integration.Tests;

/// <summary>
/// Full-pipeline integration tests. Each test runs against a real <see cref="TestServer"/>
/// so the complete ASP.NET Core middleware stack is exercised (routing, rate limiting, etc.).
/// </summary>
public sealed class IntegrationTests : IAsyncLifetime
{
    private WebApplication? _app;
    private HttpClient? _client;

    public async Task InitializeAsync() =>
        (_app, _client) = await BuildTestServerAsync();

    public async Task DisposeAsync()
    {
        _client?.Dispose();
        if (_app is not null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    private HttpClient Client => _client!;

    // ─── Discovery ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Discovery_ReturnsValidDocument()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json; charset=utf-8", response.Content.Headers.ContentType?.ToString());

        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);

        Assert.Equal("https://auth.example.test", doc.RootElement.GetProperty("issuer").GetString());
        Assert.True(doc.RootElement.TryGetProperty("token_endpoint", out _));
        Assert.True(doc.RootElement.TryGetProperty("authorization_endpoint", out _));
        Assert.True(doc.RootElement.TryGetProperty("jwks_uri", out _));
    }

    [Fact]
    public async Task Jwks_ReturnsValidDocument()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/jwks.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("keys", out JsonElement keys));
        Assert.True(keys.GetArrayLength() > 0);
    }

    // ─── Client credentials ───────────────────────────────────────────────────

    [Fact]
    public async Task ClientCredentials_ValidRequest_ReturnsAccessToken()
    {
        HttpResponseMessage response = await Client.PostAsync("/connect/token",
            TokenForm("grant_type=client_credentials&client_id=m2m&client_secret=m2m-secret&scope=api"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal("Bearer", doc.RootElement.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task ClientCredentials_WrongSecret_ReturnsInvalidClient()
    {
        HttpResponseMessage response = await Client.PostAsync("/connect/token",
            TokenForm("grant_type=client_credentials&client_id=m2m&client_secret=WRONG&scope=api"));

        // RFC 6749 §5.2: invalid_client with 401 when credentials are sent in request body.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("invalid_client", doc.RootElement.GetProperty("error").GetString());
    }

    // ─── Authorization code + PKCE flow ──────────────────────────────────────

    [Fact]
    public async Task AuthorizationCode_FullFlow_ReturnsTokens()
    {
        const string codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; // S256 of verifier

        string authorizeUrl =
            "/connect/authorize?response_type=code&client_id=webapp" +
            "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" +
            "&scope=openid%20offline_access&state=xyz&nonce=abc" +
            $"&code_challenge={codeChallenge}&code_challenge_method=S256";

        // Simulate a logged-in user via the X-Test-User header (test middleware injects ClaimsPrincipal).
        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add("X-Test-User", "alice");
        HttpResponseMessage authorizeResponse = await Client.SendAsync(authorizeRequest);

        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);
        string location = authorizeResponse.Headers.Location?.ToString() ?? string.Empty;
        Assert.Contains("code=", location);
        Assert.Contains("state=xyz", location);

        string? code = HttpUtility.ParseQueryString(new Uri(location).Query)["code"];
        Assert.NotNull(code);

        HttpResponseMessage tokenResponse = await Client.PostAsync("/connect/token",
            TokenForm($"grant_type=authorization_code&client_id=webapp&code={Uri.EscapeDataString(code!)}" +
                      $"&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_verifier={codeVerifier}"));

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        using JsonDocument tokenDoc = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
        Assert.True(tokenDoc.RootElement.TryGetProperty("access_token", out _));
        Assert.True(tokenDoc.RootElement.TryGetProperty("id_token", out _));
        Assert.True(tokenDoc.RootElement.TryGetProperty("refresh_token", out _));
    }

    // ─── Rate limiting ────────────────────────────────────────────────────────

    [Fact]
    public async Task TokenEndpoint_ExceedsRateLimit_Returns429()
    {
        // Build a separate server with a very tight rate limit (3 requests).
        (WebApplication app, HttpClient client) = await BuildTestServerAsync(tokenPermitLimit: 3);

        try
        {
            HttpStatusCode? tooManyStatus = null;

            for (int i = 0; i < 10; i++)
            {
                HttpResponseMessage resp = await client.PostAsync("/connect/token",
                    TokenForm("grant_type=client_credentials&client_id=m2m&client_secret=WRONG"));

                if (resp.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    tooManyStatus = resp.StatusCode;
                    break;
                }
            }

            Assert.Equal(HttpStatusCode.TooManyRequests, tooManyStatus);
        }
        finally
        {
            client.Dispose();
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    // ─── UserInfo ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task UserInfo_WithoutToken_Returns401()
    {
        HttpResponseMessage response = await Client.GetAsync("/connect/userinfo");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task UserInfo_WithInvalidToken_Returns401()
    {
        using HttpRequestMessage request = new(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-valid-token");
        HttpResponseMessage response = await Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static async Task<(WebApplication App, HttpClient Client)> BuildTestServerAsync(int tokenPermitLimit = 100)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();

        builder.Services.AddSimpleAuth(server =>
        {
            server.Issuer = "https://auth.example.test";
            server.Keys.UseDevelopmentKey();
            server.Discovery.IncludeIntrospectionEndpoint = true;
            server.Discovery.IncludeRevocationEndpoint = true;

            server.RateLimit.Enabled = true;
            server.RateLimit.TokenPermitLimit = tokenPermitLimit;
            server.RateLimit.AuthorizePermitLimit = tokenPermitLimit;
            // Wide window so individual test requests don't expire mid-test.
            server.RateLimit.TokenWindow = TimeSpan.FromHours(1);
            server.RateLimit.AuthorizeWindow = TimeSpan.FromHours(1);

            server.Store.UseInMemory(store =>
            {
                store.Clients.Add(new Client
                {
                    ClientId = "m2m",
                    ClientName = "M2M Client",
                    AllowedGrantTypes = [GrantType.ClientCredentials],
                    AllowedScopes = ["api"],
                    RequireClientSecret = true,
                    ClientCredentials =
                    [
                        new ClientCredential
                        {
                            Type = "SharedSecret",
                            Value = SecretHasher.Hash("m2m-secret"),
                        },
                    ],
                });

                store.Clients.Add(new Client
                {
                    ClientId = "webapp",
                    ClientName = "Web App",
                    AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
                    AllowedScopes = [StandardScope.OpenId, StandardScope.OfflineAccess],
                    RedirectUris = ["https://app.example/callback"],
                    RequireClientSecret = false,
                    RequirePkce = true,
                    AllowOfflineAccess = true,
                    RequireConsent = false,
                });
            });
        });

        WebApplication app = builder.Build();

        // Inject a test user for authorize requests that carry the X-Test-User header.
        // This simulates a logged-in session without a real cookie/auth middleware.
        app.Use(async (ctx, next) =>
        {
            if (ctx.Request.Headers.TryGetValue("X-Test-User", out Microsoft.Extensions.Primitives.StringValues sub) &&
                !Microsoft.Extensions.Primitives.StringValues.IsNullOrEmpty(sub))
            {
                ctx.User = new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity(
                    [
                        new System.Security.Claims.Claim("sub", sub.ToString()),
                        new System.Security.Claims.Claim("name", "Test User"),
                    ], "test"));
            }

            await next(ctx);
        });

        app.MapSimpleAuth();

        await app.StartAsync();

        HttpClient client = app.GetTestClient();
        client.BaseAddress = new Uri("http://localhost");

        return (app, client);
    }

    private static StringContent TokenForm(string body) =>
        new(body, System.Text.Encoding.UTF8, "application/x-www-form-urlencoded");

    // ─── PAR (Pushed Authorization Requests) ──────────────────────────────────

    [Fact]
    public async Task Par_ValidRequest_Returns201WithRequestUri()
    {
        const string codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        HttpResponseMessage response = await Client.PostAsync("/connect/par",
            TokenForm("response_type=code&client_id=webapp" +
                      "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" +
                      "&scope=openid&code_challenge=" + codeChallenge +
                      "&code_challenge_method=S256&state=xyz&nonce=abc"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);
        string? requestUri = doc.RootElement.GetProperty("request_uri").GetString();
        Assert.NotNull(requestUri);
        Assert.StartsWith("urn:ietf:params:oauth:request-uri:", requestUri);
        Assert.True(doc.RootElement.GetProperty("expires_in").GetInt32() > 0);
    }

    [Fact]
    public async Task Par_FullFlow_AuthorizeWithRequestUri_ReturnsTokens()
    {
        const string codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        // Step 1: POST to /connect/par
        HttpResponseMessage parResponse = await Client.PostAsync("/connect/par",
            TokenForm("response_type=code&client_id=webapp" +
                      "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" +
                      "&scope=openid%20offline_access&state=xyz&nonce=abc" +
                      $"&code_challenge={codeChallenge}&code_challenge_method=S256"));

        Assert.Equal(HttpStatusCode.Created, parResponse.StatusCode);
        using JsonDocument parDoc = JsonDocument.Parse(await parResponse.Content.ReadAsStringAsync());
        string? requestUri = parDoc.RootElement.GetProperty("request_uri").GetString();
        Assert.NotNull(requestUri);

        // Step 2: GET /connect/authorize with request_uri
        string authorizeUrl = "/connect/authorize?client_id=webapp" +
                              $"&request_uri={Uri.EscapeDataString(requestUri!)}";
        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add("X-Test-User", "alice");
        HttpResponseMessage authorizeResponse = await Client.SendAsync(authorizeRequest);

        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);
        string location = authorizeResponse.Headers.Location?.ToString() ?? string.Empty;
        Assert.Contains("code=", location);
        Assert.Contains("state=xyz", location);

        string? code = HttpUtility.ParseQueryString(new Uri(location).Query)["code"];
        Assert.NotNull(code);

        // Step 3: Exchange code for tokens
        HttpResponseMessage tokenResponse = await Client.PostAsync("/connect/token",
            TokenForm($"grant_type=authorization_code&client_id=webapp&code={Uri.EscapeDataString(code!)}" +
                      $"&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_verifier={codeVerifier}"));

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        using JsonDocument tokenDoc = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
        Assert.True(tokenDoc.RootElement.TryGetProperty("access_token", out _));
        Assert.True(tokenDoc.RootElement.TryGetProperty("id_token", out _));
    }

    [Fact]
    public async Task Par_UnknownRequestUri_Returns400()
    {
        string authorizeUrl = "/connect/authorize?client_id=webapp" +
                              "&request_uri=urn:ietf:params:oauth:request-uri:does-not-exist";
        using HttpRequestMessage request = new(HttpMethod.Get, authorizeUrl);
        request.Headers.Add("X-Test-User", "alice");
        HttpResponseMessage response = await Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Par_RequestUri_CannotBeUsedTwice()
    {
        const string codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        HttpResponseMessage parResponse = await Client.PostAsync("/connect/par",
            TokenForm("response_type=code&client_id=webapp" +
                      "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" +
                      $"&scope=openid&code_challenge={codeChallenge}&code_challenge_method=S256"));

        Assert.Equal(HttpStatusCode.Created, parResponse.StatusCode);
        using JsonDocument parDoc = JsonDocument.Parse(await parResponse.Content.ReadAsStringAsync());
        string? requestUri = parDoc.RootElement.GetProperty("request_uri").GetString();
        Assert.NotNull(requestUri);

        // First use — succeeds.
        string authorizeUrl = $"/connect/authorize?client_id=webapp&request_uri={Uri.EscapeDataString(requestUri!)}";
        using HttpRequestMessage first = new(HttpMethod.Get, authorizeUrl);
        first.Headers.Add("X-Test-User", "alice");
        HttpResponseMessage firstResp = await Client.SendAsync(first);
        Assert.Equal(HttpStatusCode.Redirect, firstResp.StatusCode);

        // Second use of the same request_uri — must be rejected.
        using HttpRequestMessage second = new(HttpMethod.Get, authorizeUrl);
        second.Headers.Add("X-Test-User", "alice");
        HttpResponseMessage secondResp = await Client.SendAsync(second);
        Assert.Equal(HttpStatusCode.BadRequest, secondResp.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(await secondResp.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Par_WrongClient_Returns401()
    {
        const string codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        // Use the m2m client credentials to POST to /connect/par (wrong auth method for auth code)
        HttpResponseMessage response = await Client.PostAsync("/connect/par",
            TokenForm("response_type=code&client_id=m2m&client_secret=m2m-secret" +
                      "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" +
                      $"&scope=openid&code_challenge={codeChallenge}&code_challenge_method=S256"));

        // m2m doesn't have authorization_code grant or redirect URIs — should get a 4xx error response
        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);
        string? error = doc.RootElement.GetProperty("error").GetString();
        Assert.True(error is "unauthorized_client" or "invalid_client" or "invalid_request");
        Assert.True((int)response.StatusCode is 400 or 401);
    }

    [Fact]
    public async Task Discovery_AdvertisesPAREndpoint()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/openid-configuration");
        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("pushed_authorization_request_endpoint", out JsonElement parEp));
        Assert.Contains("/connect/par", parEp.GetString() ?? string.Empty);
    }

    // ─── DPoP ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DPoP_ClientCredentials_IssuesTokenWithCnfClaim()
    {
        using ECDsa dpopKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string dpopProof = CreateDPopProof(dpopKey, HttpMethod.Post, "http://localhost/connect/token");

        using HttpRequestMessage request = new(HttpMethod.Post, "/connect/token");
        request.Content = TokenForm("grant_type=client_credentials&client_id=m2m&client_secret=m2m-secret&scope=api");
        request.Headers.Add("DPoP", dpopProof);
        HttpResponseMessage response = await Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);

        // token_type must be "DPoP" when DPoP is used (RFC 9449 §9.1)
        Assert.Equal("DPoP", doc.RootElement.GetProperty("token_type").GetString());

        string? accessToken = doc.RootElement.GetProperty("access_token").GetString();
        Assert.NotNull(accessToken);

        // Access token must contain cnf.jkt claim
        string[] parts = accessToken!.Split('.');
        Assert.Equal(3, parts.Length);

        string payloadJson = Encoding.UTF8.GetString(Base64UrlDecodeBytes(parts[1]));
        using JsonDocument tokenDoc = JsonDocument.Parse(payloadJson);
        Assert.True(tokenDoc.RootElement.TryGetProperty("cnf", out JsonElement cnf));
        Assert.True(cnf.TryGetProperty("jkt", out JsonElement jkt));
        Assert.NotNull(jkt.GetString());
    }

    [Fact]
    public async Task DPoP_InvalidProof_Returns400()
    {
        using HttpRequestMessage request = new(HttpMethod.Post, "/connect/token");
        request.Content = TokenForm("grant_type=client_credentials&client_id=m2m&client_secret=m2m-secret&scope=api");
        request.Headers.Add("DPoP", "not.a.valid.dpop.proof");
        HttpResponseMessage response = await Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.Equal("invalid_dpop_proof", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task DPoP_WrongHtm_Returns400()
    {
        using ECDsa dpopKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // Use wrong HTTP method (GET instead of POST)
        string dpopProof = CreateDPopProof(dpopKey, HttpMethod.Get, "http://localhost/connect/token");

        using HttpRequestMessage request = new(HttpMethod.Post, "/connect/token");
        request.Content = TokenForm("grant_type=client_credentials&client_id=m2m&client_secret=m2m-secret&scope=api");
        request.Headers.Add("DPoP", dpopProof);
        HttpResponseMessage response = await Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.Equal("invalid_dpop_proof", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Discovery_AdvertisesDPopAlgorithms()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/openid-configuration");
        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("dpop_signing_alg_values_supported", out JsonElement algs));
        Assert.True(algs.GetArrayLength() > 0);
    }

    // ─── DPoP helpers ─────────────────────────────────────────────────────────

    /// <summary>Creates a valid DPoP proof JWT signed with the provided key.</summary>
    private static string CreateDPopProof(ECDsa key, HttpMethod method, string htu, string? ath = null)
    {
        ECParameters ecParams = key.ExportParameters(includePrivateParameters: false);

        string x = Convert.ToBase64String(ecParams.Q.X!).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        string y = Convert.ToBase64String(ecParams.Q.Y!).Replace('+', '-').Replace('/', '_').TrimEnd('=');

        var jwk = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = x,
            ["y"] = y,
        };

        long nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method.Method,
            ["htu"] = htu,
            ["iat"] = nowUnix,
        };

        if (ath is not null)
        {
            claims["ath"] = ath;
        }

        var securityKey = new ECDsaSecurityKey(key);
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = jwk,
            },
            SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string ComputeAth(string accessToken)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.ASCII.GetBytes(accessToken), hash);
        return Convert.ToBase64String(hash).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static byte[] Base64UrlDecodeBytes(string input)
    {
        string padded = (input.Length % 4) switch
        {
            2 => input + "==",
            3 => input + "=",
            _ => input,
        };
        return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
    }
}
