using System.Net;
using System.Text.Json;
using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// OIDC Conformance: Discovery (RFC 8414 / OIDC Discovery 1.0)
/// Validates that the server metadata document is complete, correctly structured,
/// and contains all required fields per the specifications.
/// </summary>
[Collection("Conformance")]
public sealed class DiscoveryConformanceTests(ConformanceFixture fixture) : IClassFixture<ConformanceFixture>
{
    private HttpClient Client => fixture.Client;
    private string Issuer => fixture.Issuer;

    [Fact]
    public async Task Discovery_EndpointReturnsJson()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Discovery_IssuerMatchesConfiguration()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        Assert.Equal(Issuer, doc.RootElement.GetProperty("issuer").GetString());
    }

    [Fact]
    public async Task Discovery_IssuerIsHttpsUrl()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        string? issuer = doc.RootElement.GetProperty("issuer").GetString();
        Assert.NotNull(issuer);
        Assert.StartsWith("https://", issuer);
        Assert.DoesNotContain("#", issuer); // OIDC Discovery §4.1: no fragment
        Assert.DoesNotContain("?", issuer); // OIDC Discovery §4.1: no query
    }

    [Fact]
    public async Task Discovery_ContainsRequiredOidcFields()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        JsonElement root = doc.RootElement;

        // OIDC Discovery §3: REQUIRED fields
        Assert.True(root.TryGetProperty("issuer", out _));
        Assert.True(root.TryGetProperty("authorization_endpoint", out _));
        Assert.True(root.TryGetProperty("token_endpoint", out _));
        Assert.True(root.TryGetProperty("jwks_uri", out _));
        Assert.True(root.TryGetProperty("response_types_supported", out _));
        Assert.True(root.TryGetProperty("subject_types_supported", out _));
        Assert.True(root.TryGetProperty("id_token_signing_alg_values_supported", out _));
    }

    [Fact]
    public async Task Discovery_ResponseTypesSupported_ContainsCode()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        JsonElement responseTypes = doc.RootElement.GetProperty("response_types_supported");
        bool containsCode = false;
        foreach (JsonElement item in responseTypes.EnumerateArray())
        {
            if (item.GetString() == "code")
            {
                containsCode = true;
            }
        }

        Assert.True(containsCode, "response_types_supported must contain 'code'");
    }

    [Fact]
    public async Task Discovery_GrantTypesSupported_ContainsAuthorizationCode()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        JsonElement grantTypes = doc.RootElement.GetProperty("grant_types_supported");
        bool found = false;
        foreach (JsonElement item in grantTypes.EnumerateArray())
        {
            if (item.GetString() == GrantType.AuthorizationCode)
            {
                found = true;
            }
        }

        Assert.True(found, "grant_types_supported must contain 'authorization_code'");
    }

    [Fact]
    public async Task Discovery_CodeChallengeMethodsSupported_ContainsS256()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        Assert.True(doc.RootElement.TryGetProperty("code_challenge_methods_supported", out JsonElement methods));
        bool hasS256 = false;
        foreach (JsonElement item in methods.EnumerateArray())
        {
            if (item.GetString() == "S256")
            {
                hasS256 = true;
            }
        }

        Assert.True(hasS256, "PKCE S256 must be advertised");
    }

    [Fact]
    public async Task Discovery_TokenEndpointAuthMethods_ContainsExpected()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        Assert.True(doc.RootElement.TryGetProperty("token_endpoint_auth_methods_supported", out JsonElement methods));
        List<string?> authMethods = [];
        foreach (JsonElement item in methods.EnumerateArray())
        {
            authMethods.Add(item.GetString());
        }

        Assert.Contains("client_secret_basic", authMethods);
        Assert.Contains("client_secret_post", authMethods);
        Assert.Contains("private_key_jwt", authMethods);
    }

    [Fact]
    public async Task Discovery_ScopesSupported_ContainsOpenId()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        Assert.True(doc.RootElement.TryGetProperty("scopes_supported", out JsonElement scopes));
        bool hasOpenId = false;
        foreach (JsonElement item in scopes.EnumerateArray())
        {
            if (item.GetString() == "openid")
            {
                hasOpenId = true;
            }
        }

        Assert.True(hasOpenId);
    }

    [Fact]
    public async Task Discovery_SubjectTypesSupported_IsPresent()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        JsonElement subjectTypes = doc.RootElement.GetProperty("subject_types_supported");
        Assert.True(subjectTypes.GetArrayLength() > 0);
    }

    [Fact]
    public async Task Discovery_AllEndpointUrlsAreAbsolute()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        JsonElement root = doc.RootElement;

        string[] endpointFields =
        [
            "authorization_endpoint", "token_endpoint", "jwks_uri",
            "userinfo_endpoint", "revocation_endpoint", "introspection_endpoint",
        ];

        foreach (string field in endpointFields)
        {
            if (root.TryGetProperty(field, out JsonElement ep) && ep.ValueKind == JsonValueKind.String)
            {
                string? url = ep.GetString();
                Assert.True(Uri.IsWellFormedUriString(url, UriKind.Absolute), $"{field} must be absolute URL, got: {url}");
            }
        }
    }

    [Fact]
    public async Task Discovery_PushedAuthorizationRequestEndpoint_IsPresent()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        Assert.True(doc.RootElement.TryGetProperty("pushed_authorization_request_endpoint", out JsonElement parEp));
        Assert.Contains("/connect/par", parEp.GetString() ?? string.Empty);
    }

    [Fact]
    public async Task Discovery_DPopAlgorithmsSupported_IsPresent()
    {
        using JsonDocument doc = await GetDiscoveryAsync();
        Assert.True(doc.RootElement.TryGetProperty("dpop_signing_alg_values_supported", out JsonElement algs));
        Assert.True(algs.GetArrayLength() > 0);
    }

    // ── JWKS ──

    [Fact]
    public async Task Jwks_ContainsAtLeastOneKey()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/jwks.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement keys = doc.RootElement.GetProperty("keys");
        Assert.True(keys.GetArrayLength() >= 1);
    }

    [Fact]
    public async Task Jwks_KeyHasRequiredFields()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/jwks.json");
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement key = doc.RootElement.GetProperty("keys")[0];

        Assert.True(key.TryGetProperty("kty", out _), "JWK must have kty");
        Assert.True(key.TryGetProperty("kid", out _), "JWK must have kid");
        Assert.True(key.TryGetProperty("use", out _) || key.TryGetProperty("key_ops", out _), "JWK should have use or key_ops");
    }

    [Fact]
    public async Task Jwks_EcKeyHasCurveAndCoordinates()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/jwks.json");
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement key = doc.RootElement.GetProperty("keys")[0];

        if (key.GetProperty("kty").GetString() == "EC")
        {
            Assert.True(key.TryGetProperty("crv", out _), "EC key must have crv");
            Assert.True(key.TryGetProperty("x", out _), "EC key must have x");
            Assert.True(key.TryGetProperty("y", out _), "EC key must have y");
        }
    }

    [Fact]
    public async Task Jwks_DoesNotExposePrivateKeyMaterial()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/jwks.json");
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement key = doc.RootElement.GetProperty("keys")[0];

        Assert.False(key.TryGetProperty("d", out _), "JWKS must NOT expose private key 'd' parameter");
    }

    private async Task<JsonDocument> GetDiscoveryAsync()
    {
        HttpResponseMessage response = await Client.GetAsync("/.well-known/openid-configuration");
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }
}
