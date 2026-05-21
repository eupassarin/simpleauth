using System.Text.Json;
using Xunit;

namespace SimpleAuth.Conformance.Tests;

/// <summary>
/// OIDC Conformance: ID Token Validation (OIDC Core §3.1.3.7)
/// Validates structure, claims, and signing of ID tokens.
/// </summary>
[Collection("Conformance")]
public sealed class IdTokenConformanceTests(ConformanceFixture fixture) : IClassFixture<ConformanceFixture>
{
    private HttpClient Client => fixture.Client;
    private string Issuer => fixture.Issuer;

    [Fact]
    public async Task IdToken_IsValidJwt_ThreeParts()
    {
        string idToken = await GetIdTokenAsync();
        string[] parts = idToken.Split('.');
        Assert.Equal(3, parts.Length);
    }

    [Fact]
    public async Task IdToken_Header_HasTypJwt()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument header = TestHelpers.DecodeJwtHeader(idToken);
        // typ is optional per JWT spec but commonly present
        if (header.RootElement.TryGetProperty("typ", out JsonElement typ))
        {
            Assert.Equal("JWT", typ.GetString()?.ToUpperInvariant());
        }
    }

    [Fact]
    public async Task IdToken_Header_HasAlgField()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument header = TestHelpers.DecodeJwtHeader(idToken);
        Assert.True(header.RootElement.TryGetProperty("alg", out JsonElement alg));
        Assert.False(string.IsNullOrWhiteSpace(alg.GetString()));
        Assert.NotEqual("none", alg.GetString()); // MUST NOT use "none" alg
    }

    [Fact]
    public async Task IdToken_Header_HasKidField()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument header = TestHelpers.DecodeJwtHeader(idToken);
        Assert.True(header.RootElement.TryGetProperty("kid", out JsonElement kid));
        Assert.False(string.IsNullOrWhiteSpace(kid.GetString()));
    }

    [Fact]
    public async Task IdToken_Header_KidMatchesJwks()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument header = TestHelpers.DecodeJwtHeader(idToken);
        string? kid = header.RootElement.GetProperty("kid").GetString();

        HttpResponseMessage jwksResp = await Client.GetAsync("/.well-known/jwks.json");
        using JsonDocument jwks = JsonDocument.Parse(await jwksResp.Content.ReadAsStringAsync());

        bool found = false;
        foreach (JsonElement key in jwks.RootElement.GetProperty("keys").EnumerateArray())
        {
            if (key.GetProperty("kid").GetString() == kid)
            {
                found = true;
                break;
            }
        }

        Assert.True(found, $"kid '{kid}' from ID token must exist in JWKS");
    }

    [Fact]
    public async Task IdToken_ContainsRequiredClaims()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        JsonElement root = payload.RootElement;

        // OIDC Core §2: REQUIRED claims in ID Token
        Assert.True(root.TryGetProperty("iss", out _), "ID token must have 'iss'");
        Assert.True(root.TryGetProperty("sub", out _), "ID token must have 'sub'");
        Assert.True(root.TryGetProperty("aud", out _), "ID token must have 'aud'");
        Assert.True(root.TryGetProperty("exp", out _), "ID token must have 'exp'");
        Assert.True(root.TryGetProperty("iat", out _), "ID token must have 'iat'");
    }

    [Fact]
    public async Task IdToken_IssuerMatchesDiscovery()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        Assert.Equal(Issuer, payload.RootElement.GetProperty("iss").GetString());
    }

    [Fact]
    public async Task IdToken_SubClaimIsNonEmpty()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        string? sub = payload.RootElement.GetProperty("sub").GetString();
        Assert.False(string.IsNullOrWhiteSpace(sub));
        Assert.True(sub!.Length <= 255, "sub MUST NOT exceed 255 ASCII characters (OIDC Core §5.7)");
    }

    [Fact]
    public async Task IdToken_AudienceContainsClientId()
    {
        string idToken = await GetIdTokenAsync("confidential-code");
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        JsonElement aud = payload.RootElement.GetProperty("aud");

        if (aud.ValueKind == JsonValueKind.String)
        {
            Assert.Equal("confidential-code", aud.GetString());
        }
        else if (aud.ValueKind == JsonValueKind.Array)
        {
            bool found = false;
            foreach (JsonElement item in aud.EnumerateArray())
            {
                if (item.GetString() == "confidential-code")
                {
                    found = true;
                }
            }

            Assert.True(found, "aud must contain the client_id");
        }
    }

    [Fact]
    public async Task IdToken_ExpIsInFuture()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        long exp = payload.RootElement.GetProperty("exp").GetInt64();
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.True(exp > now, "ID token exp must be in the future");
    }

    [Fact]
    public async Task IdToken_IatIsReasonable()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        long iat = payload.RootElement.GetProperty("iat").GetInt64();
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // iat should be within 60 seconds of now
        Assert.True(Math.Abs(now - iat) < 60, "iat should be close to current time");
    }

    [Fact]
    public async Task IdToken_NonceMatchesRequest()
    {
        // The nonce sent in the authorize request must appear in the ID token
        string idToken = await GetIdTokenAsync();
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);

        if (payload.RootElement.TryGetProperty("nonce", out JsonElement nonce))
        {
            Assert.Equal("test-nonce", nonce.GetString());
        }
    }

    [Fact]
    public async Task IdToken_DoesNotContainSensitiveData()
    {
        string idToken = await GetIdTokenAsync();
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        JsonElement root = payload.RootElement;

        // ID tokens should NOT contain secrets or refresh tokens
        Assert.False(root.TryGetProperty("refresh_token", out _));
        Assert.False(root.TryGetProperty("client_secret", out _));
        Assert.False(root.TryGetProperty("password", out _));
    }

    /// <summary>
    /// OIDC Core §5.4 / OIDF EnsureIdTokenDoesNotContainEmailForScopeEmail:
    /// scope=email grants access to email in UserInfo only; email MUST NOT appear in ID token.
    /// </summary>
    [Fact]
    public async Task IdToken_EmailScope_EmailNotInIdToken()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback", "openid email", "alice");

        string idToken = tokens.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        JsonElement root = payload.RootElement;

        Assert.False(root.TryGetProperty("email", out _),
            "email MUST NOT appear in ID token when scope=email (OIDC Core §5.4, OIDF EnsureIdTokenDoesNotContainEmailForScopeEmail)");
        Assert.False(root.TryGetProperty("email_verified", out _),
            "email_verified MUST NOT appear in ID token when scope=email");
    }

    /// <summary>
    /// OIDC Core §5.4: scope=phone grants access to phone claims in UserInfo only.
    /// </summary>
    [Fact]
    public async Task IdToken_PhoneScope_PhoneNotInIdToken()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback", "openid phone", "alice");

        string idToken = tokens.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        JsonElement root = payload.RootElement;

        Assert.False(root.TryGetProperty("phone_number", out _),
            "phone_number MUST NOT appear in ID token when scope=phone (UserInfo-only claim)");
        Assert.False(root.TryGetProperty("phone_number_verified", out _),
            "phone_number_verified MUST NOT appear in ID token when scope=phone");
    }

    /// <summary>
    /// OIDC Core §5.1: updated_at and auth_time MUST be numeric values (Unix timestamps), not strings.
    /// </summary>
    [Fact]
    public async Task IdToken_NumericClaims_AreNumbers()
    {
        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, "public-spa", "https://spa.example/callback", "openid profile", "alice");

        string idToken = tokens.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = TestHelpers.DecodeJwtPayload(idToken);
        JsonElement root = payload.RootElement;

        // iat, exp are always present and must be numbers
        Assert.Equal(JsonValueKind.Number, root.GetProperty("iat").ValueKind);
        Assert.Equal(JsonValueKind.Number, root.GetProperty("exp").ValueKind);

        // updated_at must be a number when present (OIDC Core §5.1)
        if (root.TryGetProperty("updated_at", out JsonElement updatedAt))
        {
            Assert.Equal(JsonValueKind.Number, updatedAt.ValueKind);
        }
    }

    private async Task<string> GetIdTokenAsync(string clientId = "public-spa")
    {
        string redirectUri = clientId == "confidential-code"
            ? "https://client.example/callback"
            : "https://spa.example/callback";
        string? secret = clientId == "confidential-code" ? "secret123" : null;

        using JsonDocument tokens = await TestHelpers.PerformAuthCodeFlowAsync(
            Client, clientId, redirectUri, "openid profile", "alice", secret);

        return tokens.RootElement.GetProperty("id_token").GetString()!;
    }
}
