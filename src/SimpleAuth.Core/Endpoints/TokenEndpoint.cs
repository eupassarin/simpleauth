using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SimpleAuth.Crypto;
using SimpleAuth.Serialization;

namespace SimpleAuth.Endpoints;

/// <summary>Handles the token endpoint.</summary>
internal static class TokenEndpoint
{
    /// <summary>Processes client_credentials and authorization_code token requests.</summary>
    internal static async Task HandleAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            await JsonErrorAsync(context, StatusCodes.Status405MethodNotAllowed, "invalid_request", "POST is required.");
            return;
        }

        IFormCollection form = await context.Request.ReadFormAsync(context.RequestAborted);
        string grantType = form["grant_type"].ToString();

        SimpleAuthServerState state = context.RequestServices.GetRequiredService<SimpleAuthServerState>();
        IClientStore clientStore = context.RequestServices.GetRequiredService<IClientStore>();
        IAuthorizationCodeStore authorizationCodeStore = context.RequestServices.GetRequiredService<IAuthorizationCodeStore>();
        IRefreshTokenStore refreshTokenStore = context.RequestServices.GetRequiredService<IRefreshTokenStore>();
        ITokenStore tokenStore = context.RequestServices.GetRequiredService<ITokenStore>();
        IJtiStore jtiStore = context.RequestServices.GetRequiredService<IJtiStore>();
        JwtService jwt = context.RequestServices.GetRequiredService<JwtService>();

        (Client? client, string clientId, string clientSecret) = await ResolveClientAsync(context, form, clientStore);
        if (client is null)
        {
            await JsonErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_client", "unknown or missing client.");
            return;
        }

        if (!IsClientAuthenticated(client, clientSecret))
        {
            await JsonErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_client", "invalid credentials.");
            return;
        }

        // DPoP proof — optional but validated when present (RFC 9449 §5)
        string? dpopProof = context.Request.Headers["DPoP"].FirstOrDefault();
        string? dpopJkt = null;
        if (!string.IsNullOrWhiteSpace(dpopProof))
        {
            string htu = BuildHtu(context);
            DPopValidationResult dpopResult = await DPopProofValidator.ValidateAsync(
                dpopProof,
                expectedHtm: HttpMethods.Post,
                expectedHtu: htu,
                jtiStore: jtiStore,
                cancellationToken: context.RequestAborted);

            if (!dpopResult.IsValid)
            {
                context.Response.Headers["DPoP-Error"] = dpopResult.Error;
                await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_dpop_proof", dpopResult.Error!);
                return;
            }

            dpopJkt = dpopResult.JktThumbprint;
        }

        if (string.Equals(grantType, GrantType.ClientCredentials, StringComparison.Ordinal))
        {
            await HandleClientCredentialsGrantAsync(context, state, tokenStore, jwt, client, form, dpopJkt);
            return;
        }

        if (string.Equals(grantType, GrantType.AuthorizationCode, StringComparison.Ordinal))
        {
            await HandleAuthorizationCodeGrantAsync(
                context,
                state,
                authorizationCodeStore,
                refreshTokenStore,
                tokenStore,
                jwt,
                client,
                clientId,
                form,
                dpopJkt);
            return;
        }

        if (string.Equals(grantType, GrantType.RefreshToken, StringComparison.Ordinal))
        {
            await HandleRefreshTokenGrantAsync(
                context,
                state,
                refreshTokenStore,
                tokenStore,
                jwt,
                client,
                clientId,
                form,
                dpopJkt);
            return;
        }

        await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "unsupported_grant_type", "Only client_credentials, authorization_code and refresh_token are supported.");
    }

    private static async Task HandleClientCredentialsGrantAsync(
        HttpContext context,
        SimpleAuthServerState state,
        ITokenStore tokenStore,
        JwtService jwt,
        Client client,
        IFormCollection form,
        string? dpopJkt)
    {
        if (!client.AllowedGrantTypes.Contains(GrantType.ClientCredentials, StringComparer.Ordinal))
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "unauthorized_client", "client_credentials is not allowed for this client.");
            return;
        }

        IReadOnlyList<string> requestedScopes = ParseScopes(form["scope"].ToString());
        IReadOnlyList<string> grantedScopes = ValidateRequestedScopes(client, requestedScopes);
        if (grantedScopes.Count == 0)
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_scope", "no valid scopes were requested.");
            return;
        }

        string accessToken = await IssueAccessTokenAsync(context, state, tokenStore, jwt, client, subjectId: null, grantedScopes, dpopJkt: dpopJkt);
        int expiresIn = (int)Math.Max(1, client.AccessTokenLifetime.TotalSeconds);

        var response = new TokenResponse(accessToken, dpopJkt is not null ? "DPoP" : "Bearer", expiresIn)
        {
            Scope = string.Join(' ', grantedScopes),
        };

        await JsonResponseWriter.WriteAsync(context, response, AuthJsonContext.Default.TokenResponse);
    }

    private static async Task HandleAuthorizationCodeGrantAsync(
        HttpContext context,
        SimpleAuthServerState state,
        IAuthorizationCodeStore authorizationCodeStore,
        IRefreshTokenStore refreshTokenStore,
        ITokenStore tokenStore,
        JwtService jwt,
        Client client,
        string clientId,
        IFormCollection form,
        string? dpopJkt)
    {
        if (!client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode, StringComparer.Ordinal))
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "unauthorized_client", "authorization_code is not allowed for this client.");
            return;
        }

        string codeHandle = form["code"].ToString();
        string redirectUri = form["redirect_uri"].ToString();
        string codeVerifier = form["code_verifier"].ToString();

        if (string.IsNullOrWhiteSpace(codeHandle) || string.IsNullOrWhiteSpace(redirectUri) || string.IsNullOrWhiteSpace(codeVerifier))
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "code, redirect_uri and code_verifier are required.");
            return;
        }

        AuthorizationCode? authorizationCode = await authorizationCodeStore.ConsumeAsync(codeHandle, context.RequestAborted);
        if (authorizationCode is null)
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_grant", "the authorization code is invalid or already consumed.");
            return;
        }

        if (!string.Equals(authorizationCode.ClientId, clientId, StringComparison.Ordinal) ||
            !string.Equals(authorizationCode.RedirectUri, redirectUri, StringComparison.Ordinal))
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_grant", "the authorization code does not belong to this client or redirect_uri.");
            return;
        }

        if (!PkceValidator.Validate(codeVerifier, authorizationCode.CodeChallenge))
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_grant", "PKCE validation failed.");
            return;
        }

        string? refreshToken = null;
        string? refreshTokenHandle = null;
        if (CanIssueRefreshToken(client, authorizationCode.GrantedScopes))
        {
            (refreshToken, refreshTokenHandle) = await IssueRefreshTokenAsync(context, refreshTokenStore, client, authorizationCode, authorizationCode.GrantedScopes, dpopJkt);
        }

        string accessToken = await IssueAccessTokenAsync(context, state, tokenStore, jwt, client, authorizationCode.SubjectId, authorizationCode.GrantedScopes, refreshTokenHandle, dpopJkt);

        string? idToken = null;
        if (authorizationCode.GrantedScopes.Contains(StandardScope.OpenId, StringComparer.Ordinal))
        {
            IReadOnlyList<Claim> enrichedClaims = await EnrichIdentityClaimsAsync(
                context, authorizationCode.SubjectId, client.ClientId, authorizationCode.GrantedScopes);

            idToken = jwt.IssueIdToken(
                authorizationCode.SubjectId,
                client.ClientId,
                authorizationCode.Nonce,
                accessToken,
                client.IdentityTokenLifetime,
                enrichedClaims);
        }

        int expiresIn = (int)Math.Max(1, client.AccessTokenLifetime.TotalSeconds);
        var response = new TokenResponse(accessToken, dpopJkt is not null ? "DPoP" : "Bearer", expiresIn)
        {
            RefreshToken = refreshToken,
            IdToken = idToken,
            Scope = string.Join(' ', authorizationCode.GrantedScopes),
        };

        await JsonResponseWriter.WriteAsync(context, response, AuthJsonContext.Default.TokenResponse);
    }

    private static async Task HandleRefreshTokenGrantAsync(
        HttpContext context,
        SimpleAuthServerState state,
        IRefreshTokenStore refreshTokenStore,
        ITokenStore tokenStore,
        JwtService jwt,
        Client client,
        string clientId,
        IFormCollection form,
        string? dpopJkt)
    {
        if (!client.AllowedGrantTypes.Contains(GrantType.RefreshToken, StringComparer.Ordinal))
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "unauthorized_client", "refresh_token is not allowed for this client.");
            return;
        }

        string refreshTokenHandle = form["refresh_token"].ToString();
        if (string.IsNullOrWhiteSpace(refreshTokenHandle))
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "refresh_token is required.");
            return;
        }

        RefreshToken? current = await refreshTokenStore.FindByHandleAsync(refreshTokenHandle, context.RequestAborted);
        if (current is null || !string.Equals(current.ClientId, clientId, StringComparison.Ordinal))
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_grant", "the refresh token is invalid or does not belong to this client.");
            return;
        }

        // RFC 9449 §10.1: DPoP-bound refresh tokens MUST require a matching DPoP proof on refresh.
        if (current.DPopJkt is not null)
        {
            if (dpopJkt is null)
            {
                await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "use_dpop_nonce", "DPoP proof is required for this refresh token.");
                return;
            }

            if (!string.Equals(current.DPopJkt, dpopJkt, StringComparison.Ordinal))
            {
                await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_grant", "DPoP proof key does not match the refresh token binding.");
                return;
            }
        }

        IReadOnlyList<string> requestedScopes = ParseScopes(form["scope"].ToString());
        IReadOnlyList<string> grantedScopes = ValidateRefreshScopes(current.GrantedScopes, requestedScopes);
        if (grantedScopes.Count == 0)
        {
            await JsonErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_scope", "no valid scopes were requested.");
            return;
        }

        // Rotate refresh token and revoke old access tokens BEFORE issuing new ones,
        // so that RevokeByRefreshTokenAsync doesn't accidentally revoke the new access token.
        string nextRefreshTokenHandle = refreshTokenHandle;
        if (client.RefreshTokenUsage == TokenUsage.OneTimeOnly)
        {
            nextRefreshTokenHandle = CreateOpaqueHandle();
            var nextToken = new RefreshToken
            {
                Handle = nextRefreshTokenHandle,
                ClientId = client.ClientId,
                SubjectId = current.SubjectId,
                GrantedScopes = grantedScopes,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = client.RefreshTokenExpiration == TokenExpiration.Sliding
                    ? DateTime.UtcNow.Add(client.RefreshTokenLifetime)
                    : current.ExpiresAt,
                SlidingExpiresAt = client.RefreshTokenExpiration == TokenExpiration.Sliding
                    ? DateTime.UtcNow.Add(client.RefreshTokenLifetime)
                    : current.SlidingExpiresAt,
                SessionId = current.SessionId,
                Generation = current.Generation + 1,
                DPopJkt = current.DPopJkt,
            };

            await refreshTokenStore.ReplaceAsync(refreshTokenHandle, nextToken, context.RequestAborted);
            await tokenStore.RevokeByRefreshTokenAsync(refreshTokenHandle, context.RequestAborted);
        }
        else if (client.RefreshTokenExpiration == TokenExpiration.Sliding)
        {
            var updated = new RefreshToken
            {
                Handle = refreshTokenHandle,
                ClientId = current.ClientId,
                SubjectId = current.SubjectId,
                GrantedScopes = grantedScopes,
                CreatedAt = current.CreatedAt,
                ExpiresAt = current.ExpiresAt,
                SlidingExpiresAt = DateTime.UtcNow.Add(client.RefreshTokenLifetime),
                SessionId = current.SessionId,
                IsRevoked = false,
                Generation = current.Generation,
                DPopJkt = current.DPopJkt,
            };

            await refreshTokenStore.StoreAsync(updated, context.RequestAborted);
        }

        // Issue new access token linked to the NEW refresh token handle.
        string accessToken = await IssueAccessTokenAsync(context, state, tokenStore, jwt, client, current.SubjectId, grantedScopes, nextRefreshTokenHandle, dpopJkt);
        string? idToken = null;
        if (grantedScopes.Contains(StandardScope.OpenId, StringComparer.Ordinal) && !string.IsNullOrWhiteSpace(current.SubjectId))
        {
            IReadOnlyList<Claim> enrichedClaims = await EnrichIdentityClaimsAsync(
                context, current.SubjectId, client.ClientId, grantedScopes);

            idToken = jwt.IssueIdToken(
                current.SubjectId,
                client.ClientId,
                nonce: null,
                accessToken,
                client.IdentityTokenLifetime,
                enrichedClaims);
        }

        int expiresIn = (int)Math.Max(1, client.AccessTokenLifetime.TotalSeconds);
        var response = new TokenResponse(accessToken, dpopJkt is not null ? "DPoP" : "Bearer", expiresIn)
        {
            RefreshToken = nextRefreshTokenHandle,
            IdToken = idToken,
            Scope = string.Join(' ', grantedScopes),
        };

        await JsonResponseWriter.WriteAsync(context, response, AuthJsonContext.Default.TokenResponse);
    }

    private static bool CanIssueRefreshToken(Client client, IReadOnlyList<string> grantedScopes) =>
        client.AllowOfflineAccess &&
        client.AllowedGrantTypes.Contains(GrantType.RefreshToken, StringComparer.Ordinal) &&
        grantedScopes.Contains(StandardScope.OfflineAccess, StringComparer.Ordinal);

    private static async Task<(string Handle, string? AssociatedAccessTokenHandle)> IssueRefreshTokenAsync(
        HttpContext context,
        IRefreshTokenStore refreshTokenStore,
        Client client,
        AuthorizationCode authorizationCode,
        IReadOnlyList<string> grantedScopes,
        string? dpopJkt = null)
    {
        string handle = CreateOpaqueHandle();
        var token = new RefreshToken
        {
            Handle = handle,
            ClientId = client.ClientId,
            SubjectId = authorizationCode.SubjectId,
            GrantedScopes = grantedScopes,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.Add(client.RefreshTokenLifetime),
            SlidingExpiresAt = client.RefreshTokenExpiration == TokenExpiration.Sliding
                ? DateTime.UtcNow.Add(client.RefreshTokenLifetime)
                : null,
            SessionId = authorizationCode.SessionId,
            Generation = 0,
            DPopJkt = dpopJkt,
        };

        await refreshTokenStore.StoreAsync(token, context.RequestAborted);
        return (handle, handle);
    }

    private static async Task<string> IssueAccessTokenAsync(
        HttpContext context,
        SimpleAuthServerState state,
        ITokenStore tokenStore,
        JwtService jwt,
        Client client,
        string? subjectId,
        IReadOnlyList<string> grantedScopes,
        string? refreshTokenHandle = null,
        string? dpopJkt = null)
    {
        if (client.AccessTokenType == AccessTokenType.Reference)
        {
            string handle = CreateOpaqueHandle();
            var issuedToken = new IssuedToken
            {
                Handle = handle,
                ClientId = client.ClientId,
                SubjectId = subjectId,
                GrantedScopes = grantedScopes,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.Add(client.AccessTokenLifetime),
                RefreshTokenHandle = refreshTokenHandle,
                JktThumbprint = dpopJkt,
            };

            await tokenStore.StoreAsync(issuedToken, context.RequestAborted);
            return handle;
        }

        return jwt.IssueAccessToken(
            subject: subjectId,
            clientId: client.ClientId,
            scopes: grantedScopes,
            audiences: [state.Issuer],
            lifetime: client.AccessTokenLifetime,
            cnfJkt: dpopJkt);
    }

    private static IReadOnlyList<string> ValidateRefreshScopes(IReadOnlyList<string> grantedScopes, IReadOnlyList<string> requestedScopes)
    {
        if (requestedScopes.Count == 0)
        {
            return grantedScopes;
        }

        var selected = new List<string>();
        foreach (string scope in requestedScopes)
        {
            if (grantedScopes.Contains(scope, StringComparer.Ordinal))
            {
                selected.Add(scope);
            }
        }

        return selected;
    }

    private static IReadOnlyList<string> ParseScopes(string scopeValue)
    {
        if (string.IsNullOrWhiteSpace(scopeValue))
        {
            return [];
        }

        return scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static IReadOnlyList<string> ValidateRequestedScopes(Client client, IReadOnlyList<string> requestedScopes)
    {
        if (requestedScopes.Count == 0)
        {
            return client.AllowedScopes;
        }

        var granted = new List<string>();
        foreach (string scope in requestedScopes)
        {
            if (client.AllowedScopes.Contains(scope, StringComparer.Ordinal))
            {
                granted.Add(scope);
            }
        }

        return granted;
    }

    private static async Task<(Client? Client, string ClientId, string ClientSecret)> ResolveClientAsync(
        HttpContext context,
        IFormCollection form,
        IClientStore clientStore)
    {
        string clientId;
        string clientSecret;

        if (TryReadBasicClientAuth(context, out clientId, out clientSecret))
        {
            // authenticated via Authorization header
        }
        else
        {
            clientId = form["client_id"].ToString();
            clientSecret = form["client_secret"].ToString();
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            return (null, string.Empty, string.Empty);
        }

        Client? client = await clientStore.FindByClientIdAsync(clientId, context.RequestAborted);
        return (client, clientId, clientSecret);
    }

    private static bool IsClientAuthenticated(Client client, string clientSecret)
    {
        if (!client.RequireClientSecret)
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(clientSecret))
        {
            return false;
        }

        foreach (ClientCredential credential in client.ClientCredentials)
        {
            if (!string.Equals(credential.Type, "SharedSecret", StringComparison.Ordinal))
            {
                continue;
            }

            if (credential.Expiration is DateTime exp && exp <= DateTime.UtcNow)
            {
                continue;
            }

            if (SecretHasher.Verify(clientSecret, credential.Value))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryReadBasicClientAuth(HttpContext context, out string clientId, out string clientSecret)
    {
        clientId = string.Empty;
        clientSecret = string.Empty;

        string? authorization = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string encoded = authorization[6..].Trim();
        byte[] decodedBytes;
        try
        {
            decodedBytes = Convert.FromBase64String(encoded);
        }
        catch (FormatException)
        {
            return false;
        }

        string decoded = Encoding.UTF8.GetString(decodedBytes);
        int separator = decoded.IndexOf(':');
        if (separator < 0)
        {
            return false;
        }

        clientId = Uri.UnescapeDataString(decoded[..separator]);
        clientSecret = Uri.UnescapeDataString(decoded[(separator + 1)..]);
        return true;
    }

    private static async Task JsonErrorAsync(HttpContext context, int statusCode, string error, string? description)
    {
        context.Response.StatusCode = statusCode;
        await JsonResponseWriter.WriteAsync(context, new ErrorResponse(error, description), AuthJsonContext.Default.ErrorResponse);
    }

    private static string CreateOpaqueHandle()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncode(bytes);
    }

    private static async Task<IReadOnlyList<Claim>> EnrichIdentityClaimsAsync(
        HttpContext context,
        string subjectId,
        string clientId,
        IReadOnlyList<string> grantedScopes)
    {
        IEnumerable<IClaimsEnricher> enrichers = context.RequestServices.GetServices<IClaimsEnricher>();
        IEnumerator<IClaimsEnricher> enumerator = enrichers.GetEnumerator();
        if (!enumerator.MoveNext())
        {
            return [];
        }

        var enrichmentContext = new ClaimsEnrichmentContext
        {
            SubjectId = subjectId,
            ClientId = clientId,
            GrantedScopes = grantedScopes,
        };

        do
        {
            await enumerator.Current.EnrichAsync(enrichmentContext, context.RequestAborted);
        }
        while (enumerator.MoveNext());

        return [.. enrichmentContext.Claims];
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes)
    {
        Span<char> buffer = stackalloc char[44];
        Convert.TryToBase64Chars(bytes, buffer, out int written);
        for (int i = 0; i < written; i++)
        {
            buffer[i] = buffer[i] switch
            {
                '+' => '-',
                '/' => '_',
                _ => buffer[i],
            };
        }

        while (written > 0 && buffer[written - 1] == '=')
        {
            written--;
        }

        return new string(buffer[..written]);
    }

    /// <summary>
    /// Builds the HTTP target URI (htu) for DPoP proof validation from the current request.
    /// Strips the query string per RFC 9449 §4.2.
    /// </summary>
    private static string BuildHtu(HttpContext context)
    {
        HttpRequest req = context.Request;
        return $"{req.Scheme}://{req.Host}{req.PathBase}{req.Path}";
    }
}
