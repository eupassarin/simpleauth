using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using SimpleAuth.Configuration;

namespace SimpleAuth.Endpoints;

/// <summary>Built-in minimal login and consent UI pages for SimpleAuth.</summary>
internal static class InteractionEndpoints
{
    /// <summary>Renders the login form (GET) or processes login (POST).</summary>
    internal static async Task HandleLoginAsync(HttpContext context)
    {
        var cfg = context.RequestServices.GetRequiredService<SimpleAuthServerConfiguration>();
        string returnUrl = context.Request.Query[cfg.Interaction.ReturnUrlParameter].ToString();

        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasFormContentType)
        {
            string formReturnUrl = context.Request.Form[cfg.Interaction.ReturnUrlParameter].ToString();
            if (!string.IsNullOrWhiteSpace(formReturnUrl))
            {
                returnUrl = formReturnUrl;
            }
        }

        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            returnUrl = "/";
        }

        if (HttpMethods.IsGet(context.Request.Method))
        {
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync(BuildLoginHtml(returnUrl));
            return;
        }

        // POST — process login
        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        string username = context.Request.Form["username"].ToString();

        if (string.IsNullOrWhiteSpace(username))
        {
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync(BuildLoginHtml(returnUrl, "Username is required."));
            return;
        }

        // The built-in login accepts any username/password for development.
        long authTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new List<Claim>
        {
            new("sub", username),
            new(ClaimTypes.NameIdentifier, username),
            new("name", username),
            // OIDC Core §2: auth_time = when the End-User was authenticated.
            new("auth_time", authTime.ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        };

        var identity = new ClaimsIdentity(claims, cfg.Interaction.CookieScheme);
        var principal = new ClaimsPrincipal(identity);

        await context.SignInAsync(cfg.Interaction.CookieScheme, principal);

        if (!IsLocalUrl(returnUrl))
        {
            returnUrl = "/";
        }

        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = returnUrl;
    }

    /// <summary>Renders the consent form (GET) or processes consent (POST).</summary>
    internal static async Task HandleConsentAsync(HttpContext context)
    {
        var cfg = context.RequestServices.GetRequiredService<SimpleAuthServerConfiguration>();
        string returnUrl = context.Request.Query[cfg.Interaction.ReturnUrlParameter].ToString();

        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasFormContentType)
        {
            string formReturnUrl = context.Request.Form[cfg.Interaction.ReturnUrlParameter].ToString();
            if (!string.IsNullOrWhiteSpace(formReturnUrl))
            {
                returnUrl = formReturnUrl;
            }
        }

        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            returnUrl = "/";
        }

        string? subjectId = context.User?.FindFirst("sub")?.Value ?? context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            // Not authenticated, redirect to login
            string loginUrl = $"{cfg.Interaction.LoginPath}?{Uri.EscapeDataString(cfg.Interaction.ReturnUrlParameter)}={Uri.EscapeDataString(context.Request.Path + context.Request.QueryString)}";
            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = loginUrl;
            return;
        }

        // Parse the authorize request parameters from returnUrl to show scope info
        string clientId = "";
        string scopeValue = "";
        if (returnUrl.Contains('?'))
        {
            var queryString = QueryHelpers.ParseQuery(returnUrl.Split('?', 2)[1]);
            clientId = queryString.TryGetValue("client_id", out var cid) ? cid.ToString() : "";
            scopeValue = queryString.TryGetValue("scope", out var sc) ? sc.ToString() : "";
        }

        if (HttpMethods.IsGet(context.Request.Method))
        {
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync(BuildConsentHtml(returnUrl, clientId, scopeValue));
            return;
        }

        // POST — process consent decision
        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        string decision = context.Request.Form["decision"].ToString();

        if (string.Equals(decision, "allow", StringComparison.OrdinalIgnoreCase))
        {
            // Store consent
            IConsentStore consentStore = context.RequestServices.GetRequiredService<IConsentStore>();
            var consent = new UserConsent
            {
                SubjectId = subjectId,
                ClientId = clientId,
                GrantedScopes = scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                CreatedAt = DateTime.UtcNow,
            };
            await consentStore.StoreAsync(consent, context.RequestAborted);
        }

        if (!IsLocalUrl(returnUrl))
        {
            returnUrl = "/";
        }

        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = returnUrl;
    }

    /// <summary>Handles logout.</summary>
    internal static async Task HandleLogoutAsync(HttpContext context)
    {
        var cfg = context.RequestServices.GetRequiredService<SimpleAuthServerConfiguration>();
        await context.SignOutAsync(cfg.Interaction.CookieScheme);
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.WriteAsync("<!DOCTYPE html><html><body><p>You have been logged out.</p><a href=\"/\">Home</a></body></html>");
    }

    private static bool IsLocalUrl(string url) =>
        !string.IsNullOrWhiteSpace(url) && url.StartsWith('/') && !url.StartsWith("//");

    private static string BuildLoginHtml(string returnUrl, string? error = null)
    {
        string errorHtml = error is not null ? $"<p style=\"color:red\">{System.Net.WebUtility.HtmlEncode(error)}</p>" : "";
        string encodedReturnUrl = System.Net.WebUtility.HtmlEncode(returnUrl);
        return $$"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Login — SimpleAuth</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 2rem; width: 100%; max-width: 400px; }
        h1 { font-size: 1.5rem; margin-bottom: 1.5rem; text-align: center; color: #333; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.25rem; color: #555; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.5rem 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }
        input:focus { outline: none; border-color: #0066cc; box-shadow: 0 0 0 2px rgba(0,102,204,0.2); }
        button { width: 100%; padding: 0.75rem; background: #0066cc; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
        button:hover { background: #0052a3; }
        .info { font-size: 0.75rem; color: #888; text-align: center; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="card">
        <h1>&#128274; SimpleAuth Login</h1>
        {{errorHtml}}
        <form method="POST">
            <input type="hidden" name="returnUrl" value="{{encodedReturnUrl}}"/>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus/>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password"/>
            </div>
            <button type="submit">Sign In</button>
        </form>
        <p class="info">Built-in development login. Any username is accepted.</p>
    </div>
</body>
</html>
""";
    }

    private static string BuildConsentHtml(string returnUrl, string clientId, string scopeValue)
    {
        string[] scopes = scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string scopeList = string.Join("", scopes.Select(s => $"<li><code>{System.Net.WebUtility.HtmlEncode(s)}</code></li>"));
        string encodedReturnUrl = System.Net.WebUtility.HtmlEncode(returnUrl);
        string encodedClientId = System.Net.WebUtility.HtmlEncode(clientId);
        return $$"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Consent — SimpleAuth</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 2rem; width: 100%; max-width: 450px; }
        h1 { font-size: 1.5rem; margin-bottom: 0.5rem; text-align: center; color: #333; }
        .client { text-align: center; color: #666; margin-bottom: 1.5rem; }
        ul { list-style: none; margin-bottom: 1.5rem; }
        li { padding: 0.5rem; border-bottom: 1px solid #eee; }
        .buttons { display: flex; gap: 1rem; }
        button { flex: 1; padding: 0.75rem; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
        .allow { background: #0066cc; color: white; }
        .allow:hover { background: #0052a3; }
        .deny { background: #eee; color: #333; }
        .deny:hover { background: #ddd; }
    </style>
</head>
<body>
    <div class="card">
        <h1>&#128273; Authorization Request</h1>
        <p class="client"><strong>{{encodedClientId}}</strong> is requesting access to:</p>
        <ul>{{scopeList}}</ul>
        <form method="POST">
            <input type="hidden" name="returnUrl" value="{{encodedReturnUrl}}"/>
            <div class="buttons">
                <button type="submit" name="decision" value="allow" class="allow">Allow</button>
                <button type="submit" name="decision" value="deny" class="deny">Deny</button>
            </div>
        </form>
    </div>
</body>
</html>
""";
    }
}
