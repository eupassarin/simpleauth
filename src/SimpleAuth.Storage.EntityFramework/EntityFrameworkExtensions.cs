using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SimpleAuth.EntityFramework.Stores;

namespace SimpleAuth.EntityFramework;

/// <summary>
/// Extension methods for registering the EF Core storage implementation with SimpleAuth.
/// </summary>
public static class EntityFrameworkExtensions
{
    /// <summary>
    /// Registers all SimpleAuth stores backed by the given <typeparamref name="TContext"/>.
    /// </summary>
    /// <typeparam name="TContext">
    /// Your application's <see cref="DbContext"/>, which must derive from <see cref="SimpleAuthDbContext"/>.
    /// </typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/> for chaining.</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddSimpleAuth(options => { options.Issuer = "https://auth.example.com"; })
    ///     .AddSimpleAuthEntityFramework&lt;AppDbContext&gt;();
    ///
    /// // In AppDbContext.OnConfiguring:
    /// optionsBuilder.UseSqlite("Data Source=simpleauth.db");
    /// </code>
    /// </example>
    public static IServiceCollection AddSimpleAuthEntityFramework<TContext>(
        this IServiceCollection services)
        where TContext : SimpleAuthDbContext
    {
        services.AddScoped<IClientStore>(sp => new EfClientStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IResourceStore>(sp => new EfResourceStore(sp.GetRequiredService<TContext>()));

        services.AddScoped<IAuthorizationCodeStore>(sp => new EfAuthorizationCodeStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IRefreshTokenStore>(sp => new EfRefreshTokenStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<ITokenStore>(sp => new EfTokenStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IParStore>(sp => new EfParStore(sp.GetRequiredService<TContext>()));

        services.AddScoped<ISigningKeyStore>(sp => new EfSigningKeyStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IJtiStore>(sp => new EfJtiStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IConsentStore>(sp => new EfConsentStore(sp.GetRequiredService<TContext>()));

        // Admin stores
        services.AddScoped<IAdminClientStore>(sp => new EfAdminClientStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IAdminResourceStore>(sp => new EfAdminResourceStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IAdminTokenStore>(sp => new EfAdminTokenStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IServerSettingsStore>(sp => new EfServerSettingsStore(sp.GetRequiredService<TContext>()));

        return services;
    }

    /// <summary>
    /// Registers only the transactional EF Core stores — authorization codes, refresh tokens,
    /// access tokens, PAR entries, JTIs, and user consents.
    /// </summary>
    /// <remarks>
    /// Use this overload when clients, API scopes, and signing keys are managed separately
    /// (e.g., via <c>server.Store.UseInMemory</c> in <c>AddSimpleAuth</c> or an external Key Vault).
    /// The last-registered implementation wins in ASP.NET Core DI, so call this method
    /// <em>after</em> <c>AddSimpleAuth</c>.
    /// </remarks>
    /// <typeparam name="TContext">
    /// A <see cref="DbContext"/> derived from <see cref="SimpleAuthDbContext"/>.
    /// </typeparam>
    public static IServiceCollection AddSimpleAuthEntityFrameworkTransactionalStores<TContext>(
        this IServiceCollection services)
        where TContext : SimpleAuthDbContext
    {
        services.AddScoped<IAuthorizationCodeStore>(sp => new EfAuthorizationCodeStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IRefreshTokenStore>(sp => new EfRefreshTokenStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<ITokenStore>(sp => new EfTokenStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IParStore>(sp => new EfParStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IJtiStore>(sp => new EfJtiStore(sp.GetRequiredService<TContext>()));
        services.AddScoped<IConsentStore>(sp => new EfConsentStore(sp.GetRequiredService<TContext>()));

        return services;
    }

    /// <summary>
    /// Applies any pending migrations and optionally seeds initial data.
    /// Call this from your application startup.
    /// </summary>
    /// <param name="context">The <see cref="SimpleAuthDbContext"/> to migrate.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    public static async Task MigrateAsync(
        this SimpleAuthDbContext context,
        CancellationToken cancellationToken = default) =>
        await context.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
}
