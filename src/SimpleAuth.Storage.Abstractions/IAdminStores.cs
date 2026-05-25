namespace SimpleAuth;

/// <summary>
/// Administrative operations for <see cref="Client"/> records.
/// Used by the admin GUI to perform CRUD without server restart.
/// </summary>
public interface IAdminClientStore
{
    /// <summary>Returns all registered clients (including disabled).</summary>
    Task<IReadOnlyList<Client>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>Finds a client by ID (including disabled). Returns null if not found.</summary>
    Task<Client?> FindByIdAsync(string clientId, CancellationToken cancellationToken = default);

    /// <summary>Adds a new client. Throws if a client with the same ID already exists.</summary>
    Task AddAsync(Client client, CancellationToken cancellationToken = default);

    /// <summary>Updates an existing client. Throws if not found.</summary>
    Task UpdateAsync(Client client, CancellationToken cancellationToken = default);

    /// <summary>Deletes a client by ID. No-op if not found.</summary>
    Task DeleteAsync(string clientId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Administrative operations for scopes and resources.
/// </summary>
public interface IAdminResourceStore
{
    // ── Scopes ──────────────────────────────────────────────────────────────

    /// <summary>Returns all API scopes (including disabled).</summary>
    Task<IReadOnlyList<Scope>> GetAllScopesAsync(CancellationToken cancellationToken = default);

    /// <summary>Adds a new API scope.</summary>
    Task AddScopeAsync(Scope scope, CancellationToken cancellationToken = default);

    /// <summary>Updates an existing API scope.</summary>
    Task UpdateScopeAsync(Scope scope, CancellationToken cancellationToken = default);

    /// <summary>Deletes an API scope by name.</summary>
    Task DeleteScopeAsync(string name, CancellationToken cancellationToken = default);

    // ── Identity Scopes ─────────────────────────────────────────────────────

    /// <summary>Returns all identity scopes (including disabled).</summary>
    Task<IReadOnlyList<IdentityScope>> GetAllIdentityScopesAsync(CancellationToken cancellationToken = default);

    /// <summary>Adds a new identity scope.</summary>
    Task AddIdentityScopeAsync(IdentityScope scope, CancellationToken cancellationToken = default);

    /// <summary>Updates an existing identity scope.</summary>
    Task UpdateIdentityScopeAsync(IdentityScope scope, CancellationToken cancellationToken = default);

    /// <summary>Deletes an identity scope by name.</summary>
    Task DeleteIdentityScopeAsync(string name, CancellationToken cancellationToken = default);

    // ── Protected Resources ─────────────────────────────────────────────────

    /// <summary>Returns all protected resources (including disabled).</summary>
    Task<IReadOnlyList<ProtectedResource>> GetAllResourcesAsync(CancellationToken cancellationToken = default);

    /// <summary>Adds a new protected resource.</summary>
    Task AddResourceAsync(ProtectedResource resource, CancellationToken cancellationToken = default);

    /// <summary>Updates an existing protected resource.</summary>
    Task UpdateResourceAsync(ProtectedResource resource, CancellationToken cancellationToken = default);

    /// <summary>Deletes a protected resource by name.</summary>
    Task DeleteResourceAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>
/// Administrative view of active tokens for monitoring and revocation.
/// </summary>
public interface IAdminTokenStore
{
    /// <summary>Returns active access tokens, optionally filtered.</summary>
    Task<IReadOnlyList<TokenSummary>> GetActiveTokensAsync(
        string? subjectId = null,
        string? clientId = null,
        int skip = 0,
        int take = 50,
        CancellationToken cancellationToken = default);

    /// <summary>Returns active refresh tokens, optionally filtered.</summary>
    Task<IReadOnlyList<TokenSummary>> GetActiveRefreshTokensAsync(
        string? subjectId = null,
        string? clientId = null,
        int skip = 0,
        int take = 50,
        CancellationToken cancellationToken = default);

    /// <summary>Returns total count of active access tokens.</summary>
    Task<int> CountActiveTokensAsync(CancellationToken cancellationToken = default);

    /// <summary>Returns total count of active refresh tokens.</summary>
    Task<int> CountActiveRefreshTokensAsync(CancellationToken cancellationToken = default);

    /// <summary>Revokes a specific access token by handle.</summary>
    Task RevokeTokenAsync(string handle, CancellationToken cancellationToken = default);

    /// <summary>Revokes a specific refresh token by handle.</summary>
    Task RevokeRefreshTokenAsync(string handle, CancellationToken cancellationToken = default);

    /// <summary>Revokes all tokens for a subject/client pair.</summary>
    Task RevokeAllForSubjectAsync(string subjectId, string? clientId = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Persists and retrieves server-level settings that can be changed at runtime via the admin GUI.
/// </summary>
public interface IServerSettingsStore
{
    /// <summary>Gets a setting value by key. Returns null if not set.</summary>
    Task<string?> GetAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>Gets all settings as a dictionary.</summary>
    Task<IReadOnlyDictionary<string, string>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>Sets a setting value (insert or update).</summary>
    Task SetAsync(string key, string value, CancellationToken cancellationToken = default);

    /// <summary>Sets multiple settings atomically.</summary>
    Task SetManyAsync(IEnumerable<KeyValuePair<string, string>> settings, CancellationToken cancellationToken = default);

    /// <summary>Deletes a setting by key.</summary>
    Task DeleteAsync(string key, CancellationToken cancellationToken = default);
}

/// <summary>Summary of an active token for admin display.</summary>
public sealed class TokenSummary
{
    /// <summary>Token handle (opaque reference).</summary>
    public required string Handle { get; init; }

    /// <summary>Subject identifier (user).</summary>
    public string? SubjectId { get; init; }

    /// <summary>Client that requested the token.</summary>
    public required string ClientId { get; init; }

    /// <summary>Scopes granted.</summary>
    public IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>When the token was issued.</summary>
    public required DateTime CreatedAt { get; init; }

    /// <summary>When the token expires.</summary>
    public required DateTime ExpiresAt { get; init; }

    /// <summary>Whether the token has been revoked.</summary>
    public bool IsRevoked { get; init; }
}
