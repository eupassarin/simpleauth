using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SimpleAuth.Configuration;
using SimpleAuth.Crypto;
using SimpleAuth.Serialization;

namespace SimpleAuth.Endpoints;

/// <summary>Serves the cached discovery document.</summary>
internal static class DiscoveryEndpoint
{
    /// <summary>Writes the discovery JSON document (state resolved from DI).</summary>
    internal static Task HandleAsync(HttpContext context)
    {
        SimpleAuthServerState state = context.RequestServices.GetRequiredService<SimpleAuthServerState>();
        return HandleAsync(context, state);
    }

    /// <summary>Writes the discovery JSON document.</summary>
    internal static Task HandleAsync(HttpContext context, SimpleAuthServerState state)
    {
        context.Response.ContentType = "application/json; charset=utf-8";
        return context.Response.Body.WriteAsync(state.DiscoveryJson, context.RequestAborted).AsTask();
    }
}

/// <summary>Serves the cached JWKS document.</summary>
internal static class JwksEndpoint
{
    /// <summary>Writes the JWKS JSON document (state resolved from DI).</summary>
    internal static Task HandleAsync(HttpContext context)
    {
        SimpleAuthServerState state = context.RequestServices.GetRequiredService<SimpleAuthServerState>();
        return HandleAsync(context, state);
    }

    /// <summary>Writes the JWKS JSON document.</summary>
    internal static Task HandleAsync(HttpContext context, SimpleAuthServerState state)
    {
        context.Response.ContentType = "application/json; charset=utf-8";
        return context.Response.Body.WriteAsync(state.JwksJson, context.RequestAborted).AsTask();
    }
}

/// <summary>Issues authorization codes for the authorization code flow.</summary>
internal static class AuthorizationEndpoint
{
    /// <summary>Handles browser-based authorization requests.</summary>
    internal static async Task HandleAsync(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsPost(context.Request.Method))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status405MethodNotAllowed, "invalid_request", "GET or POST is required.");
            return;
        }

        SimpleAuthServerConfiguration cfg = context.RequestServices.GetRequiredService<SimpleAuthServerConfiguration>();

        string responseType;
        string clientId;
        string redirectUri;
        string scopeValue;
        string state;
        string nonce;
        string codeChallenge;
        string codeChallengeMethod;
        string responseMode;

        // RFC 9126 §4 — if request_uri is present, load params from the PAR entry.
        string requestUri = ReadParameter(context, "request_uri");
        if (!string.IsNullOrWhiteSpace(requestUri))
        {
            string parClientId = ReadParameter(context, "client_id");
            if (string.IsNullOrWhiteSpace(parClientId))
            {
                await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "client_id is required alongside request_uri.");
                return;
            }

            IParStore parStore = context.RequestServices.GetRequiredService<IParStore>();
            ParEntry? entry = await parStore.ConsumeAsync(requestUri, context.RequestAborted);

            if (entry is null)
            {
                await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "request_uri is unknown or expired.");
                return;
            }

            // RFC 9126 §4 — client_id in query MUST match the one that submitted the PAR.
            if (!string.Equals(entry.ClientId, parClientId, StringComparison.Ordinal))
            {
                await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "client_id mismatch.");
                return;
            }

            responseType = entry.ResponseType;
            clientId = entry.ClientId;
            redirectUri = entry.RedirectUri;
            scopeValue = entry.Scope;
            state = entry.State ?? string.Empty;
            nonce = entry.Nonce ?? string.Empty;
            codeChallenge = entry.CodeChallenge;
            codeChallengeMethod = entry.CodeChallengeMethod;
            responseMode = entry.ResponseMode ?? string.Empty;
        }
        else
        {
            // Direct (non-PAR) authorize request.
            if (cfg.Par.Enabled && cfg.Par.Required)
            {
                await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "Pushed Authorization Requests are required.");
                return;
            }

            responseType = ReadParameter(context, "response_type");
            clientId = ReadParameter(context, "client_id");
            redirectUri = ReadParameter(context, "redirect_uri");
            scopeValue = ReadParameter(context, "scope");
            state = ReadParameter(context, "state");
            nonce = ReadParameter(context, "nonce");
            codeChallenge = ReadParameter(context, "code_challenge");
            codeChallengeMethod = ReadParameter(context, "code_challenge_method");
            responseMode = ReadParameter(context, "response_mode");
        }

        if (!string.Equals(responseType, "code", StringComparison.Ordinal))
        {
            // OAuth 2.1 §4.1.2.1: MUST NOT redirect to an unvalidated redirect_uri.
            // Return a direct error since we haven't validated redirect_uri yet.
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "unsupported_response_type", "Only response_type=code is supported.");
            return;
        }

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri) || string.IsNullOrWhiteSpace(scopeValue))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "client_id, redirect_uri and scope are required.");
            return;
        }

        IClientStore clientStore = context.RequestServices.GetRequiredService<IClientStore>();
        Client? client = await clientStore.FindByClientIdAsync(clientId, context.RequestAborted);

        // RFC 9700 §2.9: unknown client or unregistered redirect_uri MUST NOT redirect.
        if (client is null || !client.Enabled)
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "unauthorized_client", "Unknown or disabled client.");
            return;
        }

        if (!IsRegisteredRedirectUri(client, redirectUri))
        {
            await ProtocolTokenSupport.WriteErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "redirect_uri is not registered.");
            return;
        }

        if (!PkceValidator.IsMethodAllowed(codeChallengeMethod) || string.IsNullOrWhiteSpace(codeChallenge))
        {
            await RedirectOrErrorAsync(context, redirectUri, state, "invalid_request", "PKCE S256 is required.");
            return;
        }

        if (!client.AllowedGrantTypes.Contains(GrantType.AuthorizationCode, StringComparer.Ordinal))
        {
            await RedirectOrErrorAsync(context, redirectUri, state, "unauthorized_client", "authorization_code is not allowed for this client.");
            return;
        }

        IReadOnlyList<string> requestedScopes = ParseScopes(scopeValue);
        IReadOnlyList<string> grantedScopes = ValidateScopes(client, requestedScopes);
        if (grantedScopes.Count == 0)
        {
            await RedirectOrErrorAsync(context, redirectUri, state, "invalid_scope", "No valid scopes were requested.");
            return;
        }

        ClaimsPrincipal? user = context.User;
        string? subjectId = user?.FindFirst("sub")?.Value ?? user?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            // OIDC §3.1.2.6: prompt=none MUST return login_required if not authenticated.
            string prompt = ReadParameter(context, "prompt");
            if (string.Equals(prompt, "none", StringComparison.OrdinalIgnoreCase))
            {
                await RedirectOrErrorAsync(context, redirectUri, state, "login_required", "The user is not authenticated.");
                return;
            }

            // Redirect to login page with returnUrl
            string returnUrl = context.Request.Path + context.Request.QueryString;
            string loginUrl = $"{cfg.Interaction.LoginPath}?{Uri.EscapeDataString(cfg.Interaction.ReturnUrlParameter)}={Uri.EscapeDataString(returnUrl)}";
            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = loginUrl;
            return;
        }

        // Check consent
        if (client.RequireConsent)
        {
            IConsentStore consentStore = context.RequestServices.GetRequiredService<IConsentStore>();
            UserConsent? existingConsent = await consentStore.FindAsync(subjectId, client.ClientId, context.RequestAborted);
            bool hasConsent = existingConsent is not null && grantedScopes.All(s => existingConsent.GrantedScopes.Contains(s, StringComparer.Ordinal));

            if (!hasConsent)
            {
                string prompt = ReadParameter(context, "prompt");
                if (string.Equals(prompt, "none", StringComparison.OrdinalIgnoreCase))
                {
                    await RedirectOrErrorAsync(context, redirectUri, state, "consent_required", "User consent is required.");
                    return;
                }

                string returnUrl = context.Request.Path + context.Request.QueryString;
                string consentUrl = $"{cfg.Interaction.ConsentPath}?{Uri.EscapeDataString(cfg.Interaction.ReturnUrlParameter)}={Uri.EscapeDataString(returnUrl)}";
                context.Response.StatusCode = StatusCodes.Status302Found;
                context.Response.Headers.Location = consentUrl;
                return;
            }
        }

        var code = new AuthorizationCode
        {
            Code = CreateOpaqueHandle(),
            ClientId = client.ClientId,
            SubjectId = subjectId,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            GrantedScopes = grantedScopes,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.Add(client.AuthorizationCodeLifetime),
            Nonce = string.IsNullOrWhiteSpace(nonce) ? null : nonce,
        };

        IAuthorizationCodeStore codeStore = context.RequestServices.GetRequiredService<IAuthorizationCodeStore>();
        await codeStore.StoreAsync(code, context.RequestAborted);

        if (string.Equals(responseMode, "form_post", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.StatusCode = StatusCodes.Status200OK;
            string html = BuildFormPostHtml(redirectUri, code.Code, state);
            await context.Response.WriteAsync(html);
            return;
        }

        string redirect = AppendQuery(redirectUri, "code", code.Code);
        if (!string.IsNullOrWhiteSpace(state))
        {
            redirect = AppendQuery(redirect, "state", state);
        }

        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = redirect;
    }

    private static IReadOnlyList<string> ParseScopes(string scopeValue) =>
        scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static IReadOnlyList<string> ValidateScopes(Client client, IReadOnlyList<string> requestedScopes)
    {
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

    private static bool IsRegisteredRedirectUri(Client client, string redirectUri) =>
        client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal);

    private static string ReadParameter(HttpContext context, string key)
    {
        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasFormContentType)
        {
            return context.Request.Form[key].ToString();
        }

        return context.Request.Query[key].ToString();
    }

    private static string CreateOpaqueHandle()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncode(bytes);
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

    private static string AppendQuery(string uri, string name, string value)
    {
        string separator = uri.Contains('?') ? "&" : "?";
        return $"{uri}{separator}{Uri.EscapeDataString(name)}={Uri.EscapeDataString(value)}";
    }

    private static async Task RedirectOrErrorAsync(HttpContext context, string redirectUri, string state, string error, string description)
    {
        if (!string.IsNullOrWhiteSpace(redirectUri))
        {
            string redirect = AppendQuery(redirectUri, "error", error);
            redirect = AppendQuery(redirect, "error_description", description);
            if (!string.IsNullOrWhiteSpace(state))
            {
                redirect = AppendQuery(redirect, "state", state);
            }

            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = redirect;
            await context.Response.CompleteAsync();
            return;
        }

        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json; charset=utf-8";
        await JsonResponseWriter.WriteAsync(context, new ErrorResponse(error, description), AuthJsonContext.Default.ErrorResponse);
    }

    private static string BuildFormPostHtml(string redirectUri, string code, string state)
    {
        var sb = new System.Text.StringBuilder(512);
        sb.Append("<!DOCTYPE html><html><head><title>Submit</title></head><body onload=\"document.forms[0].submit()\">");
        sb.Append("<form method=\"POST\" action=\"");
        sb.Append(System.Net.WebUtility.HtmlEncode(redirectUri));
        sb.Append("\">");
        sb.Append("<input type=\"hidden\" name=\"code\" value=\"");
        sb.Append(System.Net.WebUtility.HtmlEncode(code));
        sb.Append("\"/>");
        if (!string.IsNullOrWhiteSpace(state))
        {
            sb.Append("<input type=\"hidden\" name=\"state\" value=\"");
            sb.Append(System.Net.WebUtility.HtmlEncode(state));
            sb.Append("\"/>");
        }
        sb.Append("<noscript><button type=\"submit\">Continue</button></noscript></form></body></html>");
        return sb.ToString();
    }
}
