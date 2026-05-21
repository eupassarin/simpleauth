using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SimpleAuth.Configuration;
using SimpleAuth.Crypto;
using SimpleAuth.Serialization;
namespace SimpleAuth.Endpoints;

/// <summary>Shared protocol helpers for bearer token endpoints.</summary>
internal static class ProtocolTokenSupport
{
    /// <summary>Attempts to resolve an active access token from the request bearer header.</summary>
    internal static async Task<AccessTokenDetails?> ResolveAccessTokenAsync(HttpContext context)
    {
        string? rawToken = GetBearerToken(context);
        return string.IsNullOrWhiteSpace(rawToken) ? null : await ResolveAccessTokenAsync(context, rawToken);
    }

    /// <summary>Attempts to resolve an active access token by its raw token value.</summary>
    internal static async Task<AccessTokenDetails?> ResolveAccessTokenAsync(HttpContext context, string rawToken)
    {
        return rawToken.Count(c => c == '.') == 2
            ? await ResolveJwtAccessTokenAsync(context, rawToken)
            : await ResolveReferenceAccessTokenAsync(context, rawToken);
    }

    /// <summary>Writes a standard OAuth error response.</summary>
    internal static Task WriteErrorAsync(HttpContext context, int statusCode, string error, string? description)
    {
        context.Response.StatusCode = statusCode;
        return JsonResponseWriter.WriteAsync(context, new ErrorResponse(error, description), AuthJsonContext.Default.ErrorResponse);
    }

    /// <summary>Authenticates the caller client for management-style endpoints.</summary>
    internal static async Task<(Client? Client, string ClientId)> ResolveCallerClientAsync(HttpContext context)
    {
        IFormCollection form = await context.Request.ReadFormAsync(context.RequestAborted);
        string clientId;
        string clientSecret;

        if (TryReadBasicClientAuth(context, out clientId, out clientSecret))
        {
            // header auth
        }
        else
        {
            clientId = form["client_id"].ToString();
            clientSecret = form["client_secret"].ToString();
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            return (null, string.Empty);
        }

        IClientStore clientStore = context.RequestServices.GetRequiredService<IClientStore>();
        Client? client = await clientStore.FindByClientIdAsync(clientId, context.RequestAborted);
        if (client is null)
        {
            return (null, clientId);
        }

        if (!IsClientAuthenticated(client, clientSecret))
        {
            return (null, clientId);
        }

        return (client, clientId);
    }

    private static async Task<AccessTokenDetails?> ResolveJwtAccessTokenAsync(HttpContext context, string token)
    {
        SimpleAuthServerState state = context.RequestServices.GetRequiredService<SimpleAuthServerState>();
        SigningKeyHolder signingKey = context.RequestServices.GetRequiredService<SigningKeyHolder>();

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = state.Issuer,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey.SecurityKey,
            ValidateAudience = true,
            ValidAudience = state.Issuer,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(5),
            RequireSignedTokens = true,
        };

        var handler = new JsonWebTokenHandler();
        TokenValidationResult result = await handler.ValidateTokenAsync(token, parameters);
        if (!result.IsValid || result.ClaimsIdentity is null)
        {
            return null;
        }

        return AccessTokenDetails.FromClaimsIdentity(result.ClaimsIdentity, token, referenceToken: false);
    }

    private static async Task<AccessTokenDetails?> ResolveReferenceAccessTokenAsync(HttpContext context, string handle)
    {
        ITokenStore tokenStore = context.RequestServices.GetRequiredService<ITokenStore>();
        IssuedToken? token = await tokenStore.FindByHandleAsync(handle, context.RequestAborted);
        if (token is null)
        {
            return null;
        }

        return AccessTokenDetails.FromIssuedToken(token, handle);
    }

    private static string? GetBearerToken(HttpContext context)
    {
        string? authorization = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return authorization[7..].Trim();
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
}

/// <summary>Resolved access token metadata.</summary>
internal sealed class AccessTokenDetails
{
    private AccessTokenDetails()
    {
    }

    /// <summary>Gets whether the token was reference-based.</summary>
    internal bool IsReference { get; init; }

    /// <summary>Gets the raw token or handle used on the request.</summary>
    internal required string RawToken { get; init; }

    /// <summary>Gets the token client identifier, if known.</summary>
    internal string? ClientId { get; init; }

    /// <summary>Gets the subject identifier, if present.</summary>
    internal string? SubjectId { get; init; }

    /// <summary>Gets the granted scopes.</summary>
    internal IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>Gets the expiration time if available.</summary>
    internal DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>Gets the token identifier if available.</summary>
    internal string? Jti { get; init; }

    /// <summary>Gets the underlying claims.</summary>
    internal IReadOnlyCollection<Claim> Claims { get; init; } = [];

    /// <summary>
    /// JWK thumbprint from the <c>cnf.jkt</c> claim (RFC 9449).
    /// Non-null when the token is DPoP-bound; null for standard Bearer tokens.
    /// </summary>
    internal string? JktThumbprint { get; init; }

    /// <summary>Creates a detail object from a validated JWT.</summary>
    internal static AccessTokenDetails FromClaimsIdentity(ClaimsIdentity identity, string rawToken, bool referenceToken)
    {
        List<Claim> claims = [.. identity.Claims];
        string? subject = FindFirstValue(identity.Claims, ClaimTypes.NameIdentifier) ?? FindFirstValue(identity.Claims, "sub");
        string? clientId = FindFirstValue(identity.Claims, "client_id");
        string? scope = FindFirstValue(identity.Claims, "scope");
        string? jti = FindFirstValue(identity.Claims, "jti");
        string? exp = FindFirstValue(identity.Claims, "exp");
        string? jkt = ExtractJktFromCnfClaim(identity.Claims);

        return new AccessTokenDetails
        {
            IsReference = referenceToken,
            RawToken = rawToken,
            ClientId = clientId,
            SubjectId = subject,
            Scopes = ParseScopes(scope),
            ExpiresAt = ParseUnixTime(exp),
            Jti = jti,
            Claims = claims,
            JktThumbprint = jkt,
        };
    }

    /// <summary>Creates a detail object from a reference token record.</summary>
    internal static AccessTokenDetails FromIssuedToken(IssuedToken token, string rawToken)
    {
        return new AccessTokenDetails
        {
            IsReference = true,
            RawToken = rawToken,
            ClientId = token.ClientId,
            SubjectId = token.SubjectId,
            Scopes = token.GrantedScopes,
            ExpiresAt = new DateTimeOffset(token.ExpiresAt, TimeSpan.Zero),
            Claims = [],
            JktThumbprint = token.JktThumbprint,
        };
    }

    private static IReadOnlyList<string> ParseScopes(string? scopeValue)
    {
        if (string.IsNullOrWhiteSpace(scopeValue))
        {
            return [];
        }

        return scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static DateTimeOffset? ParseUnixTime(string? value)
    {
        if (!long.TryParse(value, out long unixTime))
        {
            return null;
        }

        return DateTimeOffset.FromUnixTimeSeconds(unixTime);
    }

    private static string? FindFirstValue(IEnumerable<Claim> claims, string type)
    {
        foreach (Claim claim in claims)
        {
            if (string.Equals(claim.Type, type, StringComparison.Ordinal))
            {
                return claim.Value;
            }
        }

        return null;
    }

    /// <summary>
    /// Extracts the DPoP JWK thumbprint from the <c>cnf</c> claim.
    /// Microsoft.IdentityModel flattens nested JSON as a string claim with value = serialized JSON.
    /// </summary>
    private static string? ExtractJktFromCnfClaim(IEnumerable<Claim> claims)
    {
        foreach (Claim claim in claims)
        {
            if (!string.Equals(claim.Type, "cnf", StringComparison.Ordinal))
            {
                continue;
            }

            // Value is the JSON-serialized cnf object, e.g.: {"jkt":"abcdef..."}
            try
            {
                using JsonDocument doc = JsonDocument.Parse(claim.Value);
                if (doc.RootElement.TryGetProperty("jkt", out JsonElement jkt))
                {
                    return jkt.GetString();
                }
            }
            catch
            {
                // ignore parse errors
            }
        }

        return null;
    }
}

/// <summary>Returns the current user's claims.</summary>
internal static class UserInfoEndpoint
{
    /// <summary>Returns user claims based on the bearer token.</summary>
    internal static async Task HandleAsync(HttpContext context)
    {
        // For DPoP-bound tokens the client MUST send the token via DPoP scheme (RFC 9449 §7.1).
        string? rawToken = GetPresentedToken(context, out string presentedScheme);
        if (string.IsNullOrWhiteSpace(rawToken))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_token", "a user access token is required.");
            return;
        }

        AccessTokenDetails? token = await ProtocolTokenSupport.ResolveAccessTokenAsync(context, rawToken);
        if (token is null || string.IsNullOrWhiteSpace(token.SubjectId))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_token", "a user access token is required.");
            return;
        }

        // RFC 9449 §7.1 — DPoP-bound tokens MUST be presented with the "DPoP" scheme.
        if (token.JktThumbprint is not null)
        {
            if (!string.Equals(presentedScheme, "DPoP", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.Headers["WWW-Authenticate"] = "DPoP error=\"invalid_token\", error_description=\"DPoP-bound tokens must use the DPoP authorization scheme.\"";
                await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_token", "DPoP-bound tokens must use the DPoP authorization scheme.");
                return;
            }

            string? dpopProof = context.Request.Headers["DPoP"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(dpopProof))
            {
                context.Response.Headers["WWW-Authenticate"] = "DPoP error=\"invalid_token\", error_description=\"DPoP proof required for this token.\"";
                await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_token", "DPoP proof required for this token.");
                return;
            }

            IJtiStore jtiStore = context.RequestServices.GetRequiredService<IJtiStore>();
            string htu = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}{context.Request.Path}";
            string htm = context.Request.Method;

            DPopValidationResult dpopResult = await DPopProofValidator.ValidateAsync(
                dpopProof,
                expectedHtm: htm,
                expectedHtu: htu,
                jtiStore: jtiStore,
                accessToken: rawToken,
                cancellationToken: context.RequestAborted);

            if (!dpopResult.IsValid)
            {
                context.Response.Headers["WWW-Authenticate"] = $"DPoP error=\"invalid_token\", error_description=\"{dpopResult.Error}\"";
                await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_token", dpopResult.Error!);
                return;
            }

            // The DPoP key used here must match the one bound to the token.
            if (!string.Equals(dpopResult.JktThumbprint, token.JktThumbprint, StringComparison.Ordinal))
            {
                await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_token", "DPoP key mismatch.");
                return;
            }
        }

        var enrichmentContext = new ClaimsEnrichmentContext
        {
            SubjectId = token.SubjectId,
            ClientId = token.ClientId ?? string.Empty,
            GrantedScopes = token.Scopes,
        };

        IEnumerable<IClaimsEnricher> enrichers = context.RequestServices.GetServices<IClaimsEnricher>();
        foreach (IClaimsEnricher enricher in enrichers)
        {
            await enricher.EnrichAsync(enrichmentContext, context.RequestAborted);
        }

        var response = new UserInfoResponse
        {
            ["sub"] = token.SubjectId,
        };

        if (!string.IsNullOrWhiteSpace(token.ClientId))
        {
            response["client_id"] = token.ClientId;
        }

        foreach (Claim claim in token.Claims)
        {
            if (IsProtocolClaim(claim.Type))
            {
                continue;
            }

            response[claim.Type] = CoerceClaimValue(claim);
        }

        foreach (Claim claim in enrichmentContext.Claims)
        {
            if (!IsProtocolClaim(claim.Type))
            {
                response[claim.Type] = CoerceClaimValue(claim);
            }
        }

        await JsonResponseWriter.WriteAsync(context, response, AuthJsonContext.Default.UserInfoResponse);
    }

    // Claims that must be serialized as JSON numbers, not strings (OIDC Core §5.1)
    private static readonly HashSet<string> NumericClaims = new(StringComparer.Ordinal)
    {
        "updated_at", "auth_time", "exp", "iat", "nbf",
    };

    // Claims that contain a JSON object value (OIDC Core §5.1)
    private static readonly HashSet<string> JsonObjectClaims = new(StringComparer.Ordinal)
    {
        "address",
    };

    private static object? CoerceClaimValue(Claim claim)
    {
        if (NumericClaims.Contains(claim.Type) && long.TryParse(claim.Value, out long numericValue))
        {
            return numericValue;
        }

        if (string.Equals(claim.ValueType, ClaimValueTypes.Boolean, StringComparison.Ordinal) &&
            bool.TryParse(claim.Value, out bool boolValue))
        {
            return boolValue;
        }

        // address and similar claims are JSON objects — parse into Dictionary<string, string?> for AOT-safe serialization
        if (JsonObjectClaims.Contains(claim.Type))
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(claim.Value);
                var dict = new Dictionary<string, string?>(StringComparer.Ordinal);
                foreach (JsonProperty prop in doc.RootElement.EnumerateObject())
                {
                    dict[prop.Name] = prop.Value.ValueKind == JsonValueKind.String
                        ? prop.Value.GetString()
                        : prop.Value.ToString();
                }

                return dict;
            }
            catch (JsonException)
            {
                // fall through to return as string
            }
        }

        return claim.Value;
    }

    /// <summary>
    /// Reads the raw access token string from the request, accepting both <c>Bearer</c> and <c>DPoP</c> schemes.
    /// Also accepts <c>access_token</c> in POST body per RFC 6750 §2.2 (optional form parameter method).
    /// Outputs the scheme used so callers can enforce DPoP scheme requirement (RFC 9449 §7.1).
    /// </summary>
    private static string? GetPresentedToken(HttpContext context, out string scheme)
    {
        scheme = string.Empty;
        string? auth = context.Request.Headers.Authorization.ToString();

        if (!string.IsNullOrWhiteSpace(auth))
        {
            if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                scheme = "Bearer";
                return auth[7..].Trim();
            }

            if (auth.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
            {
                scheme = "DPoP";
                return auth[5..].Trim();
            }
        }

        // RFC 6750 §2.2 — access token in POST body (optional, for compatibility)
        if (context.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase) &&
            context.Request.HasFormContentType)
        {
            string? bodyToken = context.Request.Form["access_token"].ToString();
            if (!string.IsNullOrWhiteSpace(bodyToken))
            {
                scheme = "Bearer";
                return bodyToken;
            }
        }

        return null;
    }

    private static bool IsProtocolClaim(string type) =>
        string.Equals(type, "iss", StringComparison.Ordinal) ||
        string.Equals(type, "aud", StringComparison.Ordinal) ||
        string.Equals(type, "exp", StringComparison.Ordinal) ||
        string.Equals(type, "iat", StringComparison.Ordinal) ||
        string.Equals(type, "nbf", StringComparison.Ordinal) ||
        string.Equals(type, "jti", StringComparison.Ordinal) ||
        string.Equals(type, "scope", StringComparison.Ordinal) ||
        string.Equals(type, "client_id", StringComparison.Ordinal) ||
        string.Equals(type, "at_hash", StringComparison.Ordinal) ||
        string.Equals(type, "cnf", StringComparison.Ordinal) ||
        string.Equals(type, "nonce", StringComparison.Ordinal);
}

/// <summary>Returns token metadata for RFC 7662 introspection.</summary>
internal static class IntrospectionEndpoint
{
    /// <summary>Returns whether the supplied token is active.</summary>
    internal static async Task HandleAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status405MethodNotAllowed, "invalid_request", "POST is required.");
            return;
        }

        IFormCollection form = await context.Request.ReadFormAsync(context.RequestAborted);
        string tokenValue = form["token"].ToString();
        if (string.IsNullOrWhiteSpace(tokenValue))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "token is required.");
            return;
        }

        (Client? callerClient, string callerClientId) = await ProtocolTokenSupport.ResolveCallerClientAsync(context);
        if (callerClient is null)
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_client", "client authentication is required.");
            return;
        }

        AccessTokenDetails? token = await ProtocolTokenSupport.ResolveAccessTokenAsync(context, tokenValue);

        if (token is null)
        {
            var inactive = new IntrospectionResponse { Active = false };
            await JsonResponseWriter.WriteAsync(context, inactive, AuthJsonContext.Default.IntrospectionResponse);
            return;
        }

        var response = new IntrospectionResponse
        {
            Active = true,
            ClientId = token.ClientId ?? callerClientId,
            Sub = token.SubjectId,
            Scope = token.Scopes.Count == 0 ? null : string.Join(' ', token.Scopes),
            Exp = token.ExpiresAt?.ToUnixTimeSeconds(),
            TokenType = token.IsReference ? "reference" : "jwt",
        };

        await JsonResponseWriter.WriteAsync(context, response, AuthJsonContext.Default.IntrospectionResponse);
    }

}

/// <summary>Revokes access or refresh tokens.</summary>
internal static class RevocationEndpoint
{
    /// <summary>Revokes a token handle and always returns 200.</summary>
    internal static async Task HandleAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status405MethodNotAllowed, "invalid_request", "POST is required.");
            return;
        }

        IFormCollection form = await context.Request.ReadFormAsync(context.RequestAborted);
        string tokenValue = form["token"].ToString();
        if (string.IsNullOrWhiteSpace(tokenValue))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "token is required.");
            return;
        }

        (Client? callerClient, string callerClientId) = await ProtocolTokenSupport.ResolveCallerClientAsync(context);
        if (callerClient is null)
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_client", "client authentication is required.");
            return;
        }

        // RFC 7009 §2.1: The server responds with 200 for both successful revocation
        // and invalid/unowned tokens — MUST NOT reveal token ownership to other clients.
        string hint = form["token_type_hint"].ToString();
        if (string.Equals(hint, "refresh_token", StringComparison.Ordinal))
        {
            IRefreshTokenStore refreshTokenStore = context.RequestServices.GetRequiredService<IRefreshTokenStore>();
            RefreshToken? refreshToken = await refreshTokenStore.FindByHandleAsync(tokenValue, context.RequestAborted);
            if (refreshToken is null || !string.Equals(refreshToken.ClientId, callerClientId, StringComparison.Ordinal))
            {
                // Token not found or belongs to another client — silently return 200.
                context.Response.StatusCode = StatusCodes.Status200OK;
                await context.Response.CompleteAsync();
                return;
            }

            await refreshTokenStore.RevokeAsync(tokenValue, context.RequestAborted);
        }
        else
        {
            ITokenStore tokenStore = context.RequestServices.GetRequiredService<ITokenStore>();
            IssuedToken? issuedToken = await tokenStore.FindByHandleAsync(tokenValue, context.RequestAborted);
            if (issuedToken is null || !string.Equals(issuedToken.ClientId, callerClientId, StringComparison.Ordinal))
            {
                // Token not found or belongs to another client — silently return 200.
                context.Response.StatusCode = StatusCodes.Status200OK;
                await context.Response.CompleteAsync();
                return;
            }

            await tokenStore.RevokeAsync(tokenValue, context.RequestAborted);
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        await context.Response.CompleteAsync();
    }
}

/// <summary>
/// OIDC RP-Initiated Logout per OpenID Connect RP-Initiated Logout 1.0.
/// Revokes all tokens for the subject identified by <c>id_token_hint</c>
/// and redirects to <c>post_logout_redirect_uri</c> if provided.
/// </summary>
internal static class EndSessionEndpoint
{
    /// <summary>Processes the end-session request.</summary>
    internal static async Task HandleAsync(HttpContext context)
    {
        string? idTokenHint;
        string? postLogoutRedirectUri;
        string? state;
        string? clientIdParam;

        if (HttpMethods.IsPost(context.Request.Method))
        {
            IFormCollection form = await context.Request.ReadFormAsync(context.RequestAborted);
            idTokenHint = form["id_token_hint"].ToString();
            postLogoutRedirectUri = form["post_logout_redirect_uri"].ToString();
            state = form["state"].ToString();
            clientIdParam = form["client_id"].ToString();
        }
        else
        {
            idTokenHint = context.Request.Query["id_token_hint"].ToString();
            postLogoutRedirectUri = context.Request.Query["post_logout_redirect_uri"].ToString();
            state = context.Request.Query["state"].ToString();
            clientIdParam = context.Request.Query["client_id"].ToString();
        }

        // Attempt to identify the session from the id_token_hint.
        string? subjectId = null;
        string? clientId = null;

        if (!string.IsNullOrWhiteSpace(idTokenHint))
        {
            (subjectId, clientId) = await TryExtractFromIdTokenHintAsync(context, idTokenHint);
        }

        // Fall back to the explicit client_id parameter.
        if (string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(clientIdParam))
        {
            clientId = clientIdParam;
        }

        // Revoke all tokens for the identified subject + client.
        if (!string.IsNullOrWhiteSpace(subjectId) && !string.IsNullOrWhiteSpace(clientId))
        {
            IRefreshTokenStore refreshStore = context.RequestServices.GetRequiredService<IRefreshTokenStore>();
            ITokenStore tokenStore = context.RequestServices.GetRequiredService<ITokenStore>();

            await refreshStore.RevokeAllAsync(subjectId, clientId, context.RequestAborted);
            await tokenStore.RevokeAllAsync(subjectId, clientId, context.RequestAborted);
        }

        // Sign out the user — clear the session cookie so prompt=none works correctly.
        // Guard against minimal test environments where the cookie handler may not be registered.
        try
        {
            SimpleAuthServerConfiguration cfg = context.RequestServices.GetRequiredService<SimpleAuthServerConfiguration>();
            await context.SignOutAsync(cfg.Interaction.CookieScheme);
        }
        catch (InvalidOperationException)
        {
            // No cookie authentication handler registered — skip sign-out (e.g., test environments).
        }

        // OIDC RP-Initiated Logout §2.1: post_logout_redirect_uri MUST be validated
        // against the client's registered URIs to prevent open redirect attacks.
        if (!string.IsNullOrWhiteSpace(postLogoutRedirectUri) && !string.IsNullOrWhiteSpace(clientId))
        {
            IClientStore clientStore = context.RequestServices.GetRequiredService<IClientStore>();
            Client? client = await clientStore.FindByClientIdAsync(clientId, context.RequestAborted);

            if (client?.PostLogoutRedirectUris?.Contains(postLogoutRedirectUri) == true)
            {
                string redirectTarget;
                if (string.IsNullOrWhiteSpace(state))
                {
                    redirectTarget = postLogoutRedirectUri;
                }
                else
                {
                    char separator = postLogoutRedirectUri.Contains('?') ? '&' : '?';
                    redirectTarget = $"{postLogoutRedirectUri}{separator}state={Uri.EscapeDataString(state)}";
                }

                context.Response.Redirect(redirectTarget);
                return;
            }
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
    }

    private static async Task<(string? SubjectId, string? ClientId)> TryExtractFromIdTokenHintAsync(
        HttpContext context, string idTokenHint)
    {
        SimpleAuthServerState state = context.RequestServices.GetRequiredService<SimpleAuthServerState>();
        SigningKeyHolder signingKey = context.RequestServices.GetRequiredService<SigningKeyHolder>();

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = state.Issuer,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey.SecurityKey,
#pragma warning disable CA5404 // id_token_hint: audience unknown a priori; lifetime ignored per OIDC RP-Initiated Logout spec.
            ValidateAudience = false,
            ValidateLifetime = false,
#pragma warning restore CA5404
            RequireSignedTokens = true,
        };

        var handler = new JsonWebTokenHandler();
        TokenValidationResult result = await handler.ValidateTokenAsync(idTokenHint, parameters);
        if (!result.IsValid || result.ClaimsIdentity is null)
        {
            return (null, null);
        }

        string? sub = null;
        string? aud = null;

        foreach (Claim claim in result.ClaimsIdentity.Claims)
        {
            if (string.Equals(claim.Type, "sub", StringComparison.Ordinal))
            {
                sub = claim.Value;
            }
            else if (string.Equals(claim.Type, "aud", StringComparison.Ordinal))
            {
                aud = claim.Value;
            }
            else if (string.Equals(claim.Type, "azp", StringComparison.Ordinal) && aud is null)
            {
                aud = claim.Value;
            }
        }

        return (sub, aud);
    }
}
