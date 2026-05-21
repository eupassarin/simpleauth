using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SimpleAuth.Configuration;

namespace SimpleAuth.Endpoints;

/// <summary>Routing helpers that map the built-in SimpleAuth endpoints.</summary>
public static class SimpleAuthEndpointMiddlewareExtensions
{
    /// <summary>Adds the discovery endpoints to the pipeline.</summary>
    public static WebApplication MapSimpleAuthWellKnown(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.MapGet("/.well-known/openid-configuration", DiscoveryEndpoint.HandleAsync);
        app.MapGet("/.well-known/jwks.json", JwksEndpoint.HandleAsync);

        return app;
    }

    /// <summary>Adds the protocol endpoints to the pipeline.</summary>
    public static WebApplication MapSimpleAuthConnect(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var cfg = app.Services.GetRequiredService<SimpleAuthServerConfiguration>();

        IEndpointConventionBuilder authorizeRoute = app
            .MapMethods("/connect/authorize", ["GET", "POST"], AuthorizationEndpoint.HandleAsync);

        IEndpointConventionBuilder tokenRoute = app
            .MapPost("/connect/token", TokenEndpoint.HandleAsync);

        app.MapGet("/connect/userinfo", UserInfoEndpoint.HandleAsync);
        app.MapPost("/connect/userinfo", UserInfoEndpoint.HandleAsync);
        app.MapPost("/connect/introspect", IntrospectionEndpoint.HandleAsync);
        app.MapPost("/connect/revocation", RevocationEndpoint.HandleAsync);
        app.MapGet("/connect/endsession", EndSessionEndpoint.HandleAsync);
        app.MapPost("/connect/endsession", EndSessionEndpoint.HandleAsync);

        if (cfg.Par.Enabled)
        {
            app.MapPost("/connect/par", PushedAuthorizationEndpoint.HandleAsync);
        }

        if (cfg.RateLimit.Enabled)
        {
            authorizeRoute.RequireRateLimiting(RateLimitPolicyNames.Authorize);
            tokenRoute.RequireRateLimiting(RateLimitPolicyNames.Token);
        }

        return app;
    }
}
