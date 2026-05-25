using Microsoft.EntityFrameworkCore;
using SimpleAuth.EntityFramework.Entities;

namespace SimpleAuth.EntityFramework.Stores;

/// <summary>EF Core implementation of <see cref="IAdminClientStore"/>.</summary>
internal sealed class EfAdminClientStore : IAdminClientStore
{
    private readonly SimpleAuthDbContext _context;

    public EfAdminClientStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task<IReadOnlyList<Client>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        List<ClientEntity> entities = await _context.Clients
            .AsNoTracking()
            .OrderBy(c => c.ClientId)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return [.. entities.Select(MapToModel)];
    }

    public async Task<Client?> FindByIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ClientEntity? entity = await _context.Clients
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken)
            .ConfigureAwait(false);

        return entity is null ? null : MapToModel(entity);
    }

    public async Task AddAsync(Client client, CancellationToken cancellationToken = default)
    {
        ClientEntity? existing = await _context.Clients
            .FirstOrDefaultAsync(c => c.ClientId == client.ClientId, cancellationToken)
            .ConfigureAwait(false);

        if (existing is not null)
        {
            throw new InvalidOperationException($"Client '{client.ClientId}' already exists.");
        }

        _context.Clients.Add(MapToEntity(client));
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task UpdateAsync(Client client, CancellationToken cancellationToken = default)
    {
        ClientEntity? entity = await _context.Clients
            .FirstOrDefaultAsync(c => c.ClientId == client.ClientId, cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            throw new InvalidOperationException($"Client '{client.ClientId}' not found.");
        }

        ApplyToEntity(client, entity);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ClientEntity? entity = await _context.Clients
            .FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken)
            .ConfigureAwait(false);

        if (entity is not null)
        {
            _context.Clients.Remove(entity);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
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

    private static ClientEntity MapToEntity(Client c) => new()
    {
        ClientId = c.ClientId,
        ClientName = c.ClientName,
        Description = c.Description,
        Enabled = c.Enabled,
        AllowedGrantTypes = JsonConverters.SerializeStringList(c.AllowedGrantTypes),
        RedirectUris = JsonConverters.SerializeStringList(c.RedirectUris),
        PostLogoutRedirectUris = JsonConverters.SerializeStringList(c.PostLogoutRedirectUris),
        AllowedCorsOrigins = JsonConverters.SerializeStringList(c.AllowedCorsOrigins),
        AllowedScopes = JsonConverters.SerializeStringList(c.AllowedScopes),
        ClientCredentials = JsonConverters.SerializeObject(c.ClientCredentials),
        Claims = JsonConverters.SerializeObject(c.Claims),
        TokenEndpointAuthMethod = c.TokenEndpointAuthMethod,
        RequireClientSecret = c.RequireClientSecret,
        JwksJson = c.Jwks?.Json,
        JwksUri = c.JwksUri,
        RequirePkce = c.RequirePkce,
        AllowOfflineAccess = c.AllowOfflineAccess,
        AccessTokenLifetimeSeconds = (int)c.AccessTokenLifetime.TotalSeconds,
        AuthorizationCodeLifetimeSeconds = (int)c.AuthorizationCodeLifetime.TotalSeconds,
        RefreshTokenLifetimeSeconds = (int)c.RefreshTokenLifetime.TotalSeconds,
        IdentityTokenLifetimeSeconds = (int)c.IdentityTokenLifetime.TotalSeconds,
        RefreshTokenUsage = (int)c.RefreshTokenUsage,
        RefreshTokenExpiration = (int)c.RefreshTokenExpiration,
        AccessTokenType = (int)c.AccessTokenType,
        RequireConsent = c.RequireConsent,
        AllowRememberConsent = c.AllowRememberConsent,
        AlwaysIncludeUserClaimsInIdToken = c.AlwaysIncludeUserClaimsInIdToken,
        SubjectType = (int)c.SubjectType,
        PairwiseSectorIdentifierUri = c.PairwiseSectorIdentifierUri,
    };

    private static void ApplyToEntity(Client c, ClientEntity e)
    {
        e.ClientName = c.ClientName;
        e.Description = c.Description;
        e.Enabled = c.Enabled;
        e.AllowedGrantTypes = JsonConverters.SerializeStringList(c.AllowedGrantTypes);
        e.RedirectUris = JsonConverters.SerializeStringList(c.RedirectUris);
        e.PostLogoutRedirectUris = JsonConverters.SerializeStringList(c.PostLogoutRedirectUris);
        e.AllowedCorsOrigins = JsonConverters.SerializeStringList(c.AllowedCorsOrigins);
        e.AllowedScopes = JsonConverters.SerializeStringList(c.AllowedScopes);
        e.ClientCredentials = JsonConverters.SerializeObject(c.ClientCredentials);
        e.Claims = JsonConverters.SerializeObject(c.Claims);
        e.TokenEndpointAuthMethod = c.TokenEndpointAuthMethod;
        e.RequireClientSecret = c.RequireClientSecret;
        e.JwksJson = c.Jwks?.Json;
        e.JwksUri = c.JwksUri;
        e.RequirePkce = c.RequirePkce;
        e.AllowOfflineAccess = c.AllowOfflineAccess;
        e.AccessTokenLifetimeSeconds = (int)c.AccessTokenLifetime.TotalSeconds;
        e.AuthorizationCodeLifetimeSeconds = (int)c.AuthorizationCodeLifetime.TotalSeconds;
        e.RefreshTokenLifetimeSeconds = (int)c.RefreshTokenLifetime.TotalSeconds;
        e.IdentityTokenLifetimeSeconds = (int)c.IdentityTokenLifetime.TotalSeconds;
        e.RefreshTokenUsage = (int)c.RefreshTokenUsage;
        e.RefreshTokenExpiration = (int)c.RefreshTokenExpiration;
        e.AccessTokenType = (int)c.AccessTokenType;
        e.RequireConsent = c.RequireConsent;
        e.AllowRememberConsent = c.AllowRememberConsent;
        e.AlwaysIncludeUserClaimsInIdToken = c.AlwaysIncludeUserClaimsInIdToken;
        e.SubjectType = (int)c.SubjectType;
        e.PairwiseSectorIdentifierUri = c.PairwiseSectorIdentifierUri;
    }
}

/// <summary>EF Core implementation of <see cref="IAdminResourceStore"/>.</summary>
internal sealed class EfAdminResourceStore : IAdminResourceStore
{
    private readonly SimpleAuthDbContext _context;

    public EfAdminResourceStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    // ── Scopes ──────────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<Scope>> GetAllScopesAsync(CancellationToken cancellationToken = default) =>
        await _context.Scopes
            .AsNoTracking()
            .OrderBy(s => s.Name)
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

    public async Task AddScopeAsync(Scope scope, CancellationToken cancellationToken = default)
    {
        _context.Scopes.Add(new ScopeEntity
        {
            Name = scope.Name,
            DisplayName = scope.DisplayName,
            Description = scope.Description,
            ShowInDiscoveryDocument = scope.ShowInDiscoveryDocument,
            Required = scope.Required,
            Emphasize = scope.Emphasize,
            Enabled = scope.Enabled,
        });
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task UpdateScopeAsync(Scope scope, CancellationToken cancellationToken = default)
    {
        ScopeEntity? entity = await _context.Scopes
            .FirstOrDefaultAsync(s => s.Name == scope.Name, cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            throw new InvalidOperationException($"Scope '{scope.Name}' not found.");
        }

        entity.DisplayName = scope.DisplayName;
        entity.Description = scope.Description;
        entity.ShowInDiscoveryDocument = scope.ShowInDiscoveryDocument;
        entity.Required = scope.Required;
        entity.Emphasize = scope.Emphasize;
        entity.Enabled = scope.Enabled;
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteScopeAsync(string name, CancellationToken cancellationToken = default)
    {
        ScopeEntity? entity = await _context.Scopes
            .FirstOrDefaultAsync(s => s.Name == name, cancellationToken)
            .ConfigureAwait(false);

        if (entity is not null)
        {
            _context.Scopes.Remove(entity);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    // ── Identity Scopes ─────────────────────────────────────────────────────

    public async Task<IReadOnlyList<IdentityScope>> GetAllIdentityScopesAsync(CancellationToken cancellationToken = default)
    {
        List<IdentityScopeEntity> entities = await _context.IdentityScopes
            .AsNoTracking()
            .OrderBy(s => s.Name)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return [.. entities.Select(e => new IdentityScope
        {
            Name = e.Name,
            DisplayName = e.DisplayName,
            Description = e.Description,
            ClaimTypes = JsonConverters.DeserializeStringList(e.ClaimTypes),
            Required = e.Required,
            Emphasize = e.Emphasize,
            ShowInDiscoveryDocument = e.ShowInDiscoveryDocument,
            Enabled = e.Enabled,
        })];
    }

    public async Task AddIdentityScopeAsync(IdentityScope scope, CancellationToken cancellationToken = default)
    {
        _context.IdentityScopes.Add(new IdentityScopeEntity
        {
            Name = scope.Name,
            DisplayName = scope.DisplayName,
            Description = scope.Description,
            ClaimTypes = JsonConverters.SerializeStringList(scope.ClaimTypes),
            Required = scope.Required,
            Emphasize = scope.Emphasize,
            ShowInDiscoveryDocument = scope.ShowInDiscoveryDocument,
            Enabled = scope.Enabled,
        });
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task UpdateIdentityScopeAsync(IdentityScope scope, CancellationToken cancellationToken = default)
    {
        IdentityScopeEntity? entity = await _context.IdentityScopes
            .FirstOrDefaultAsync(s => s.Name == scope.Name, cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            throw new InvalidOperationException($"Identity scope '{scope.Name}' not found.");
        }

        entity.DisplayName = scope.DisplayName;
        entity.Description = scope.Description;
        entity.ClaimTypes = JsonConverters.SerializeStringList(scope.ClaimTypes);
        entity.Required = scope.Required;
        entity.Emphasize = scope.Emphasize;
        entity.ShowInDiscoveryDocument = scope.ShowInDiscoveryDocument;
        entity.Enabled = scope.Enabled;
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteIdentityScopeAsync(string name, CancellationToken cancellationToken = default)
    {
        IdentityScopeEntity? entity = await _context.IdentityScopes
            .FirstOrDefaultAsync(s => s.Name == name, cancellationToken)
            .ConfigureAwait(false);

        if (entity is not null)
        {
            _context.IdentityScopes.Remove(entity);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    // ── Protected Resources ─────────────────────────────────────────────────

    public async Task<IReadOnlyList<ProtectedResource>> GetAllResourcesAsync(CancellationToken cancellationToken = default)
    {
        List<ProtectedResourceEntity> entities = await _context.ProtectedResources
            .AsNoTracking()
            .OrderBy(r => r.Name)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return [.. entities.Select(e => new ProtectedResource
        {
            Name = e.Name,
            DisplayName = e.DisplayName,
            Scopes = JsonConverters.DeserializeStringList(e.Scopes),
            Enabled = e.Enabled,
        })];
    }

    public async Task AddResourceAsync(ProtectedResource resource, CancellationToken cancellationToken = default)
    {
        _context.ProtectedResources.Add(new ProtectedResourceEntity
        {
            Name = resource.Name,
            DisplayName = resource.DisplayName,
            Scopes = JsonConverters.SerializeStringList(resource.Scopes),
            Enabled = resource.Enabled,
        });
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task UpdateResourceAsync(ProtectedResource resource, CancellationToken cancellationToken = default)
    {
        ProtectedResourceEntity? entity = await _context.ProtectedResources
            .FirstOrDefaultAsync(r => r.Name == resource.Name, cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            throw new InvalidOperationException($"Resource '{resource.Name}' not found.");
        }

        entity.DisplayName = resource.DisplayName;
        entity.Scopes = JsonConverters.SerializeStringList(resource.Scopes);
        entity.Enabled = resource.Enabled;
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteResourceAsync(string name, CancellationToken cancellationToken = default)
    {
        ProtectedResourceEntity? entity = await _context.ProtectedResources
            .FirstOrDefaultAsync(r => r.Name == name, cancellationToken)
            .ConfigureAwait(false);

        if (entity is not null)
        {
            _context.ProtectedResources.Remove(entity);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}

/// <summary>EF Core implementation of <see cref="IAdminTokenStore"/>.</summary>
internal sealed class EfAdminTokenStore : IAdminTokenStore
{
    private readonly SimpleAuthDbContext _context;

    public EfAdminTokenStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task<IReadOnlyList<TokenSummary>> GetActiveTokensAsync(
        string? subjectId = null, string? clientId = null,
        int skip = 0, int take = 50,
        CancellationToken cancellationToken = default)
    {
        IQueryable<IssuedTokenEntity> query = _context.IssuedTokens
            .AsNoTracking()
            .Where(t => !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow);

        if (!string.IsNullOrEmpty(subjectId))
        {
            query = query.Where(t => t.SubjectId == subjectId);
        }

        if (!string.IsNullOrEmpty(clientId))
        {
            query = query.Where(t => t.ClientId == clientId);
        }

        List<IssuedTokenEntity> entities = await query
            .OrderByDescending(t => t.CreatedAt)
            .Skip(skip).Take(take)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return [.. entities.Select(t => new TokenSummary
        {
            Handle = t.Handle,
            SubjectId = t.SubjectId,
            ClientId = t.ClientId,
            Scopes = JsonConverters.DeserializeStringList(t.GrantedScopes),
            CreatedAt = t.CreatedAt,
            ExpiresAt = t.ExpiresAt,
            IsRevoked = t.IsRevoked,
        })];
    }

    public async Task<IReadOnlyList<TokenSummary>> GetActiveRefreshTokensAsync(
        string? subjectId = null, string? clientId = null,
        int skip = 0, int take = 50,
        CancellationToken cancellationToken = default)
    {
        IQueryable<RefreshTokenEntity> query = _context.RefreshTokens
            .AsNoTracking()
            .Where(t => !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow);

        if (!string.IsNullOrEmpty(subjectId))
        {
            query = query.Where(t => t.SubjectId == subjectId);
        }

        if (!string.IsNullOrEmpty(clientId))
        {
            query = query.Where(t => t.ClientId == clientId);
        }

        List<RefreshTokenEntity> entities = await query
            .OrderByDescending(t => t.CreatedAt)
            .Skip(skip).Take(take)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return [.. entities.Select(t => new TokenSummary
        {
            Handle = t.Handle,
            SubjectId = t.SubjectId,
            ClientId = t.ClientId,
            Scopes = JsonConverters.DeserializeStringList(t.GrantedScopes),
            CreatedAt = t.CreatedAt,
            ExpiresAt = t.ExpiresAt,
            IsRevoked = t.IsRevoked,
        })];
    }

    public async Task<int> CountActiveTokensAsync(CancellationToken cancellationToken = default) =>
        await _context.IssuedTokens
            .Where(t => !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
            .CountAsync(cancellationToken)
            .ConfigureAwait(false);

    public async Task<int> CountActiveRefreshTokensAsync(CancellationToken cancellationToken = default) =>
        await _context.RefreshTokens
            .Where(t => !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
            .CountAsync(cancellationToken)
            .ConfigureAwait(false);

    public async Task RevokeTokenAsync(string handle, CancellationToken cancellationToken = default)
    {
        IssuedTokenEntity? entity = await _context.IssuedTokens
            .FirstOrDefaultAsync(t => t.Handle == handle, cancellationToken)
            .ConfigureAwait(false);

        if (entity is not null)
        {
            entity.IsRevoked = true;
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task RevokeRefreshTokenAsync(string handle, CancellationToken cancellationToken = default)
    {
        RefreshTokenEntity? entity = await _context.RefreshTokens
            .FirstOrDefaultAsync(t => t.Handle == handle, cancellationToken)
            .ConfigureAwait(false);

        if (entity is not null)
        {
            entity.IsRevoked = true;
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task RevokeAllForSubjectAsync(string subjectId, string? clientId = null, CancellationToken cancellationToken = default)
    {
        IQueryable<IssuedTokenEntity> tokens = _context.IssuedTokens
            .Where(t => t.SubjectId == subjectId && !t.IsRevoked);
        IQueryable<RefreshTokenEntity> refreshTokens = _context.RefreshTokens
            .Where(t => t.SubjectId == subjectId && !t.IsRevoked);

        if (!string.IsNullOrEmpty(clientId))
        {
            tokens = tokens.Where(t => t.ClientId == clientId);
            refreshTokens = refreshTokens.Where(t => t.ClientId == clientId);
        }

        await foreach (IssuedTokenEntity token in tokens.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            token.IsRevoked = true;
        }

        await foreach (RefreshTokenEntity token in refreshTokens.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            token.IsRevoked = true;
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>EF Core implementation of <see cref="IServerSettingsStore"/>.</summary>
internal sealed class EfServerSettingsStore : IServerSettingsStore
{
    private readonly SimpleAuthDbContext _context;

    public EfServerSettingsStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        ServerSettingsEntity? entity = await _context.ServerSettings
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.Key == key, cancellationToken)
            .ConfigureAwait(false);
        return entity?.Value;
    }

    public async Task<IReadOnlyDictionary<string, string>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        List<ServerSettingsEntity> entities = await _context.ServerSettings
            .AsNoTracking()
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return entities.ToDictionary(e => e.Key, e => e.Value);
    }

    public async Task SetAsync(string key, string value, CancellationToken cancellationToken = default)
    {
        ServerSettingsEntity? entity = await _context.ServerSettings
            .FirstOrDefaultAsync(s => s.Key == key, cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            _context.ServerSettings.Add(new ServerSettingsEntity
            {
                Key = key,
                Value = value,
                UpdatedAt = DateTime.UtcNow,
            });
        }
        else
        {
            entity.Value = value;
            entity.UpdatedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SetManyAsync(IEnumerable<KeyValuePair<string, string>> settings, CancellationToken cancellationToken = default)
    {
        foreach (KeyValuePair<string, string> kv in settings)
        {
            ServerSettingsEntity? entity = await _context.ServerSettings
                .FirstOrDefaultAsync(s => s.Key == kv.Key, cancellationToken)
                .ConfigureAwait(false);

            if (entity is null)
            {
                _context.ServerSettings.Add(new ServerSettingsEntity
                {
                    Key = kv.Key,
                    Value = kv.Value,
                    UpdatedAt = DateTime.UtcNow,
                });
            }
            else
            {
                entity.Value = kv.Value;
                entity.UpdatedAt = DateTime.UtcNow;
            }
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        ServerSettingsEntity? entity = await _context.ServerSettings
            .FirstOrDefaultAsync(s => s.Key == key, cancellationToken)
            .ConfigureAwait(false);

        if (entity is not null)
        {
            _context.ServerSettings.Remove(entity);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
