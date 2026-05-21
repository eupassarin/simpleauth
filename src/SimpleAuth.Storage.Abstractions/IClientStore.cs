namespace SimpleAuth;

/// <summary>Read-only lookup of registered <see cref="Client"/> records.</summary>
public interface IClientStore
{
    /// <summary>
    /// Finds a client by its <paramref name="clientId"/>.
    /// Returns <see langword="null"/> if the client is not registered or is disabled.
    /// </summary>
    ValueTask<Client?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default);
}

/// <summary>Read-only lookup of <see cref="Scope"/>, <see cref="IdentityScope"/> and <see cref="ProtectedResource"/> records.</summary>
public interface IResourceStore
{
    /// <summary>Returns all enabled <see cref="Scope"/> entries matching the given <paramref name="scopeNames"/>.</summary>
    ValueTask<IReadOnlyList<Scope>> FindScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default);

    /// <summary>Returns all enabled <see cref="IdentityScope"/> entries matching the given <paramref name="scopeNames"/>.</summary>
    ValueTask<IReadOnlyList<IdentityScope>> FindIdentityScopesByNameAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns all enabled <see cref="ProtectedResource"/> entries that contain
    /// at least one of the requested <paramref name="scopeNames"/>.
    /// </summary>
    ValueTask<IReadOnlyList<ProtectedResource>> FindResourcesByScopeAsync(IEnumerable<string> scopeNames, CancellationToken cancellationToken = default);

    /// <summary>Returns a <see cref="ProtectedResource"/> by its unique <paramref name="name"/>.</summary>
    ValueTask<ProtectedResource?> FindResourceByNameAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Returns all enabled identity scopes. Used to build the discovery document.</summary>
    ValueTask<IReadOnlyList<IdentityScope>> GetAllEnabledIdentityScopesAsync(CancellationToken cancellationToken = default);

    /// <summary>Returns all enabled API scopes. Used to build the discovery document.</summary>
    ValueTask<IReadOnlyList<Scope>> GetAllEnabledScopesAsync(CancellationToken cancellationToken = default);
}
