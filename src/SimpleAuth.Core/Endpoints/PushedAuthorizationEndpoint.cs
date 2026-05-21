using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SimpleAuth.Configuration;
using SimpleAuth.Crypto;
using SimpleAuth.Serialization;

namespace SimpleAuth.Endpoints;

/// <summary>
/// Handles the Pushed Authorization Request endpoint (RFC 9126).
/// <c>POST /connect/par</c> — accepts the same parameters as the authorize endpoint,
/// authenticates the client, and returns a short-lived <c>request_uri</c> handle.
/// </summary>
internal static class PushedAuthorizationEndpoint
{
    private const string RequestUriPrefix = "urn:ietf:params:oauth:request-uri:";

    /// <summary>Handles a PAR request.</summary>
    internal static async Task HandleAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status405MethodNotAllowed, "invalid_request", "POST is required.");
            return;
        }

        IFormCollection form = await context.Request.ReadFormAsync(context.RequestAborted);

        IClientStore clientStore = context.RequestServices.GetRequiredService<IClientStore>();
        (Client? client, _, string clientSecret) = await ResolveClientAsync(context, form, clientStore);

        if (client is null)
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_client", "Unknown or missing client.");
            return;
        }

        if (!IsClientAuthenticated(client, clientSecret))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "invalid_client", "Invalid client credentials.");
            return;
        }

        string responseType = form["response_type"].ToString();
        string redirectUri = form["redirect_uri"].ToString();
        string scope = form["scope"].ToString();
        string codeChallenge = form["code_challenge"].ToString();
        string codeChallengeMethod = form["code_challenge_method"].ToString();
        string state = form["state"].ToString();
        string nonce = form["nonce"].ToString();
        string responseMode = form["response_mode"].ToString();

        if (!string.Equals(responseType, "code", StringComparison.Ordinal))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "unsupported_response_type", "Only response_type=code is supported.");
            return;
        }

        if (string.IsNullOrWhiteSpace(redirectUri) || string.IsNullOrWhiteSpace(scope))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "redirect_uri and scope are required.");
            return;
        }

        if (!client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "redirect_uri is not registered for this client.");
            return;
        }

        if (!client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode, StringComparer.Ordinal))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "unauthorized_client", "authorization_code is not allowed for this client.");
            return;
        }

        if (!PkceValidator.IsMethodAllowed(codeChallengeMethod) || string.IsNullOrWhiteSpace(codeChallenge))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "PKCE S256 is required.");
            return;
        }

        SimpleAuthServerConfiguration cfg = context.RequestServices.GetRequiredService<SimpleAuthServerConfiguration>();
        DateTime now = DateTime.UtcNow;

        var entry = new ParEntry
        {
            RequestUri = RequestUriPrefix + CreateHandle(),
            ClientId = client.ClientId,
            RedirectUri = redirectUri,
            Scope = scope,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            ResponseType = responseType,
            State = string.IsNullOrWhiteSpace(state) ? null : state,
            Nonce = string.IsNullOrWhiteSpace(nonce) ? null : nonce,
            ResponseMode = string.IsNullOrWhiteSpace(responseMode) ? null : responseMode,
            CreatedAt = now,
            ExpiresAt = now.Add(cfg.Par.RequestLifetime),
        };

        IParStore parStore = context.RequestServices.GetRequiredService<IParStore>();
        await parStore.StoreAsync(entry, context.RequestAborted);

        int expiresIn = (int)cfg.Par.RequestLifetime.TotalSeconds;
        var response = new ParResponse(entry.RequestUri, expiresIn);

        context.Response.StatusCode = StatusCodes.Status201Created;
        context.Response.ContentType = "application/json; charset=utf-8";
        await JsonResponseWriter.WriteAsync(context, response, AuthJsonContext.Default.ParResponse);
    }

    private static string CreateHandle()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private static async Task<(Client? Client, string ClientId, string ClientSecret)> ResolveClientAsync(
        HttpContext context,
        IFormCollection form,
        IClientStore clientStore)
    {
        // Basic authentication header
        string? authHeader = context.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            byte[] decodedBytes;
            try
            {
                decodedBytes = Convert.FromBase64String(authHeader[6..].Trim());
            }
            catch (FormatException)
            {
                return (null, string.Empty, string.Empty);
            }

            string decoded = System.Text.Encoding.UTF8.GetString(decodedBytes);
            int colon = decoded.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0)
            {
                string id = Uri.UnescapeDataString(decoded[..colon]);
                string secret = Uri.UnescapeDataString(decoded[(colon + 1)..]);
                Client? c = await clientStore.FindByClientIdAsync(id, context.RequestAborted);
                return (c, id, secret);
            }
        }

        // Form body
        string clientId = form["client_id"].ToString();
        string clientSecret = form["client_secret"].ToString();
        if (!string.IsNullOrWhiteSpace(clientId))
        {
            Client? c = await clientStore.FindByClientIdAsync(clientId, context.RequestAborted);
            return (c, clientId, clientSecret);
        }

        return (null, string.Empty, string.Empty);
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
}
