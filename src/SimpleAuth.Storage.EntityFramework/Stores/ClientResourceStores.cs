using Microsoft.EntityFrameworkCore;
using SimpleAuth.EntityFramework.Entities;

namespace SimpleAuth.EntityFramework.Stores;

/// <summary>EF Core implementation of <see cref="IClientStore"/>.</summary>
internal sealed class EfClientStore : IClientStore
{
    private readonly SimpleAuthDbContext _context;

    public EfClientStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async ValueTask<Client?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ClientEntity? entity = await _context.Clients
            .AsNoTracking()
            .Where(c => c.ClientId == clientId && c.Enabled)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return entity is null ? null : MapToModel(entity);
    }

    private static Client MapToModel(ClientEntity e) => new()
    {
        ClientId = e.ClientId,
        ClientName = e.ClientName,
        Description = e.Description,
        Enabled = e.Enabled,
        AllowedGrantTypes = JsonConverters.DeserializeStringList(e.AllowedGrantTypes),
        RedirectUris = JsonConverters.DeserializeStringList(e.RedirectUris),
        PostLogoutRedirectUris = JsonConverters.DeserializeStringList(e.PostLogoutRedirectUris),
        AllowedCorsOrigins = JsonConverters.DeserializeStringList(e.AllowedCorsOrigins),
        AllowedScopes = JsonConverters.DeserializeStringList(e.AllowedScopes),
        ClientCredentials = JsonConverters.DeserializeObject<List<ClientCredential>>(e.ClientCredentials) ?? [],
        Claims = JsonConverters.DeserializeObject<List<ClientClaim>>(e.Claims) ?? [],
        TokenEndpointAuthMethod = e.TokenEndpointAuthMethod,
        RequireClientSecret = e.RequireClientSecret,
        Jwks = e.JwksJson is null ? null : new ClientJwks { Json = e.JwksJson },
        JwksUri = e.JwksUri,
        RequirePkce = e.RequirePkce,
        AllowOfflineAccess = e.AllowOfflineAccess,
        AccessTokenLifetime = TimeSpan.FromSeconds(e.AccessTokenLifetimeSeconds),
        AuthorizationCodeLifetime = TimeSpan.FromSeconds(e.AuthorizationCodeLifetimeSeconds),
        RefreshTokenLifetime = TimeSpan.FromSeconds(e.RefreshTokenLifetimeSeconds),
        IdentityTokenLifetime = TimeSpan.FromSeconds(e.IdentityTokenLifetimeSeconds),
        RefreshTokenUsage = (TokenUsage)e.RefreshTokenUsage,
        RefreshTokenExpiration = (TokenExpiration)e.RefreshTokenExpiration,
        AccessTokenType = (AccessTokenType)e.AccessTokenType,
        RequireConsent = e.RequireConsent,
        AllowRememberConsent = e.AllowRememberConsent,
        AlwaysIncludeUserClaimsInIdToken = e.AlwaysIncludeUserClaimsInIdToken,
        SubjectType = (SubjectType)e.SubjectType,
        PairwiseSectorIdentifierUri = e.PairwiseSectorIdentifierUri,
    };
}

/// <summary>EF Core implementation of <see cref="IResourceStore"/>.</summary>
internal sealed class EfResourceStore : IResourceStore
{
    private readonly SimpleAuthDbContext _context;

    public EfResourceStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async ValueTask<IReadOnlyList<Scope>> FindScopesByNameAsync(
        IEnumerable<string> scopeNames,
        CancellationToken cancellationToken = default)
    {
        List<string> names = [.. scopeNames];

        return await _context.Scopes
            .AsNoTracking()
            .Where(s => s.Enabled && names.Contains(s.Name))
            .Select(s => new Scope
            {
                Name = s.Name,
                DisplayName = s.DisplayName,
                Description = s.Description,
                ShowInDiscoveryDocument = s.ShowInDiscoveryDocument,
                Required = s.Required,
                Emphasize = s.Emphasize,
                Enabled = s.Enabled,
            })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyList<IdentityScope>> FindIdentityScopesByNameAsync(
        IEnumerable<string> scopeNames,
        CancellationToken cancellationToken = default)
    {
        List<string> names = [.. scopeNames];

        List<IdentityScopeEntity> entities = await _context.IdentityScopes
            .AsNoTracking()
            .Where(s => s.Enabled && names.Contains(s.Name))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return [.. entities.Select(MapIdentityScope)];
    }

    public async ValueTask<IReadOnlyList<ProtectedResource>> FindResourcesByScopeAsync(
        IEnumerable<string> scopeNames,
        CancellationToken cancellationToken = default)
    {
        List<string> names = [.. scopeNames];

        // Load all enabled resources, then filter in memory by scope overlap.
        // This avoids a JSON_CONTAINS / LIKE query which is provider-specific.
        List<ProtectedResourceEntity> all = await _context.ProtectedResources
            .AsNoTracking()
            .Where(r => r.Enabled)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        List<ProtectedResource> result = [];
        foreach (ProtectedResourceEntity entity in all)
        {
            IReadOnlyList<string> scopes = JsonConverters.DeserializeStringList(entity.Scopes);
            if (scopes.Any(names.Contains))
            {
                result.Add(MapProtectedResource(entity, scopes));
            }
        }

        return result;
    }

    public async ValueTask<ProtectedResource?> FindResourceByNameAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        ProtectedResourceEntity? entity = await _context.ProtectedResources
            .AsNoTracking()
            .Where(r => r.Name == name && r.Enabled)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            return null;
        }

        IReadOnlyList<string> scopes = JsonConverters.DeserializeStringList(entity.Scopes);
        return MapProtectedResource(entity, scopes);
    }

    public async ValueTask<IReadOnlyList<IdentityScope>> GetAllEnabledIdentityScopesAsync(
        CancellationToken cancellationToken = default)
    {
        List<IdentityScopeEntity> entities = await _context.IdentityScopes
            .AsNoTracking()
            .Where(s => s.Enabled)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return [.. entities.Select(MapIdentityScope)];
    }

    public async ValueTask<IReadOnlyList<Scope>> GetAllEnabledScopesAsync(
        CancellationToken cancellationToken = default)
    {
        return await _context.Scopes
            .AsNoTracking()
            .Where(s => s.Enabled)
            .Select(s => new Scope
            {
                Name = s.Name,
                DisplayName = s.DisplayName,
                Description = s.Description,
                ShowInDiscoveryDocument = s.ShowInDiscoveryDocument,
                Required = s.Required,
                Emphasize = s.Emphasize,
                Enabled = s.Enabled,
            })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static IdentityScope MapIdentityScope(IdentityScopeEntity e) => new()
    {
        Name = e.Name,
        DisplayName = e.DisplayName,
        Description = e.Description,
        ClaimTypes = JsonConverters.DeserializeStringList(e.ClaimTypes),
        Required = e.Required,
        Emphasize = e.Emphasize,
        ShowInDiscoveryDocument = e.ShowInDiscoveryDocument,
        Enabled = e.Enabled,
    };

    private static ProtectedResource MapProtectedResource(ProtectedResourceEntity e, IReadOnlyList<string> scopes) =>
        new()
        {
            Name = e.Name,
            DisplayName = e.DisplayName,
            Scopes = scopes,
            Enabled = e.Enabled,
        };
}
