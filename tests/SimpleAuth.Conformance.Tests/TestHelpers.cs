using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SimpleAuth.Conformance.Tests;

/// <summary>Shared helpers for conformance tests.</summary>
internal static class TestHelpers
{
    /// <summary>Creates a URL-encoded form content from key=value pairs.</summary>
    internal static StringContent Form(string body) =>
        new(body, Encoding.UTF8, "application/x-www-form-urlencoded");

    /// <summary>Extracts a query parameter from a redirect location URI.</summary>
    internal static string? GetQueryParam(string locationUri, string paramName) =>
        HttpUtility.ParseQueryString(new Uri(locationUri).Query)[paramName];

    /// <summary>Parses JSON response body.</summary>
    internal static async Task<JsonDocument> ParseJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    /// <summary>Creates an HTTP request with X-Test-User header for simulating logged-in user.</summary>
    internal static HttpRequestMessage AuthorizeRequest(string url, string user)
    {
        HttpRequestMessage request = new(HttpMethod.Get, url);
        request.Headers.Add("X-Test-User", user);
        return request;
    }

    /// <summary>Creates an HTTP Basic auth header value.</summary>
    internal static AuthenticationHeaderValue BasicAuth(string clientId, string clientSecret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}")));

    /// <summary>Generates a random PKCE code verifier.</summary>
    internal static string GenerateCodeVerifier()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncode(bytes);
    }

    /// <summary>Computes S256 code challenge from verifier.</summary>
    internal static string ComputeS256Challenge(string verifier)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.ASCII.GetBytes(verifier), hash);
        return Base64UrlEncode(hash);
    }

    /// <summary>Base64url-encodes bytes (no padding).</summary>
    internal static string Base64UrlEncode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    /// <summary>Base64url-decodes a string.</summary>
    internal static byte[] Base64UrlDecode(string input)
    {
        string padded = (input.Length % 4) switch
        {
            2 => input + "==",
            3 => input + "=",
            _ => input,
        };
        return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
    }

    /// <summary>Decodes a JWT payload without signature verification (for test assertions).</summary>
    internal static JsonDocument DecodeJwtPayload(string jwt)
    {
        string[] parts = jwt.Split('.');
        string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
        return JsonDocument.Parse(payloadJson);
    }

    /// <summary>Decodes a JWT header without signature verification.</summary>
    internal static JsonDocument DecodeJwtHeader(string jwt)
    {
        string[] parts = jwt.Split('.');
        string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
        return JsonDocument.Parse(headerJson);
    }

    /// <summary>Creates a valid DPoP proof JWT.</summary>
    internal static string CreateDPopProof(ECDsa key, HttpMethod method, string htu, string? ath = null)
    {
        ECParameters ecParams = key.ExportParameters(includePrivateParameters: false);
        string x = Base64UrlEncode(ecParams.Q.X!);
        string y = Base64UrlEncode(ecParams.Q.Y!);

        var jwk = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = x,
            ["y"] = y,
        };

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method.Method,
            ["htu"] = htu,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };

        if (ath is not null)
        {
            claims["ath"] = ath;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["typ"] = "dpop+jwt",
                ["jwk"] = jwk,
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
        };

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    /// <summary>Computes the ath (access token hash) for a DPoP proof.</summary>
    internal static string ComputeAth(string accessToken)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.ASCII.GetBytes(accessToken), hash);
        return Base64UrlEncode(hash);
    }

    /// <summary>Performs a full authorization code + PKCE flow and returns the token response JSON.</summary>
    internal static async Task<JsonDocument> PerformAuthCodeFlowAsync(
        HttpClient client,
        string clientId,
        string redirectUri,
        string scope,
        string user,
        string? clientSecret = null,
        bool useBasicAuth = false)
    {
        string verifier = GenerateCodeVerifier();
        string challenge = ComputeS256Challenge(verifier);

        // Step 1: Authorize
        string authorizeUrl =
            $"/connect/authorize?response_type=code&client_id={clientId}" +
            $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
            $"&scope={Uri.EscapeDataString(scope)}&state=test-state&nonce=test-nonce" +
            $"&code_challenge={challenge}&code_challenge_method=S256";

        using HttpRequestMessage authorizeReq = AuthorizeRequest(authorizeUrl, user);
        HttpResponseMessage authorizeResp = await client.SendAsync(authorizeReq);

        if (authorizeResp.StatusCode != System.Net.HttpStatusCode.Redirect)
        {
            throw new InvalidOperationException($"Expected redirect, got {authorizeResp.StatusCode}");
        }

        string location = authorizeResp.Headers.Location!.ToString();
        string? code = GetQueryParam(location, "code") ?? throw new InvalidOperationException("No code in redirect");

        // Step 2: Token exchange
        string tokenBody = $"grant_type=authorization_code&code={Uri.EscapeDataString(code)}" +
                           $"&redirect_uri={Uri.EscapeDataString(redirectUri)}&code_verifier={verifier}";

        if (!useBasicAuth)
        {
            tokenBody += $"&client_id={clientId}";
            if (clientSecret is not null)
            {
                tokenBody += $"&client_secret={clientSecret}";
            }
        }

        using HttpRequestMessage tokenReq = new(HttpMethod.Post, "/connect/token")
        {
            Content = Form(tokenBody),
        };

        if (useBasicAuth && clientSecret is not null)
        {
            tokenReq.Headers.Authorization = BasicAuth(clientId, clientSecret);
        }

        HttpResponseMessage tokenResp = await client.SendAsync(tokenReq);

        if (tokenResp.StatusCode != System.Net.HttpStatusCode.OK)
        {
            string err = await tokenResp.Content.ReadAsStringAsync();
            throw new InvalidOperationException($"Token request failed: {tokenResp.StatusCode} — {err}");
        }

        return JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
    }
}
