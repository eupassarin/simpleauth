using BlazorBlueprint.Components;
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

        services.AddBlazorBlueprintComponents();

        services.AddCascadingAuthenticationState();

        return services;
    }

    /// <summary>
    /// Registers middleware required by the admin GUI: static files, authentication,
    /// authorization, and antiforgery. Must be called <b>before</b> any endpoint mapping.
    /// </summary>
    public static WebApplication UseSimpleAuthGui(this WebApplication app)
    {
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();
        return app;
    }

    /// <summary>
    /// Maps the SimpleAuth admin GUI endpoints (Blazor Server + login/logout).
    /// Call <c>UseSimpleAuthGui()</c> first to register the required middleware.
    /// </summary>
    public static WebApplication MapSimpleAuthGui(this WebApplication app)
    {
        SimpleAuthGuiConfiguration config = app.Services
            .GetRequiredService<SimpleAuthGuiConfiguration>();

        string prefix = config.PathPrefix.TrimEnd('/');

        // Serve static web assets (_content/*, _framework/*)
        app.MapStaticAssets();

        // Logout endpoint (plain HTTP GET — sign out and redirect to login)
        app.MapGet($"{prefix}/logout", async context =>
        {
            await context.SignOutAsync(config.CookieScheme);
            context.Response.Redirect($"{prefix}/login");
        });

        // Map Blazor (also handles GET + POST /admin/login via Login.razor)
        app.MapRazorComponents<Components.App>()
            .AddInteractiveServerRenderMode();

        return app;
    }
}
