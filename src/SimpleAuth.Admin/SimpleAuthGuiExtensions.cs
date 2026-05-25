using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace SimpleAuth.Admin;

/// <summary>Extension methods for registering the SimpleAuth admin GUI.</summary>
public static class SimpleAuthGuiExtensions
{
    /// <summary>
    /// Registers the SimpleAuth admin GUI services.
    /// Requires <c>AddSimpleAuthEntityFramework</c> to be called first.
    /// </summary>
    public static IServiceCollection AddSimpleAuthGui(
        this IServiceCollection services,
        Action<SimpleAuthGuiConfiguration> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var config = new SimpleAuthGuiConfiguration();
        configure(config);

        if (string.IsNullOrEmpty(config.AdminPasswordHash))
        {
            throw new InvalidOperationException(
                "Admin password must be set. Call gui.SetPassword(\"...\") in AddSimpleAuthGui configuration.");
        }

        services.AddSingleton(config);

        services.AddAuthentication(config.CookieScheme)
            .AddCookie(config.CookieScheme, options =>
            {
                options.Cookie.Name = config.CookieName;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.ExpireTimeSpan = config.SessionLifetime;
                options.LoginPath = $"{config.PathPrefix}/login";
                options.AccessDeniedPath = $"{config.PathPrefix}/login";
            });

        services.AddAuthorization(options =>
        {
            options.AddPolicy("SimpleAuthAdmin", policy =>
                policy.RequireAuthenticatedUser()
                      .AddAuthenticationSchemes(config.CookieScheme));
        });

        services.AddRazorComponents()
            .AddInteractiveServerComponents();

        return services;
    }

    /// <summary>
    /// Maps the SimpleAuth admin GUI endpoints (Blazor Server + login/logout).
    /// Registers all required middleware: static files, authentication, authorization,
    /// and antiforgery. A single call is all that's needed.
    /// </summary>
    public static WebApplication MapSimpleAuthGui(this WebApplication app)
    {
        // Required middleware — safe to call even if already registered by the host
        app.UseStaticFiles();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();

        SimpleAuthGuiConfiguration config = app.Services
            .GetRequiredService<SimpleAuthGuiConfiguration>();

        string prefix = config.PathPrefix.TrimEnd('/');

        // Login POST endpoint
        app.MapPost($"{prefix}/login", async context =>
        {
            IFormCollection form = await context.Request.ReadFormAsync();
            string username = form["username"].ToString();
            string password = form["password"].ToString();

            if (string.Equals(username, config.AdminUsername, StringComparison.OrdinalIgnoreCase) &&
                config.VerifyPassword(password))
            {
                List<Claim> claims =
                [
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Role, "SimpleAuthAdmin"),
                ];

                var identity = new ClaimsIdentity(claims, config.CookieScheme);
                var principal = new ClaimsPrincipal(identity);

                await context.SignInAsync(config.CookieScheme, principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.Add(config.SessionLifetime),
                    });

                context.Response.Redirect(prefix);
                return;
            }

            context.Response.Redirect($"{prefix}/login?error=invalid");
        });

        // Logout endpoint
        app.MapGet($"{prefix}/logout", async context =>
        {
            await context.SignOutAsync(config.CookieScheme);
            context.Response.Redirect($"{prefix}/login");
        });

        // Map Blazor
        app.MapRazorComponents<Components.App>()
            .AddInteractiveServerRenderMode();

        return app;
    }
}
