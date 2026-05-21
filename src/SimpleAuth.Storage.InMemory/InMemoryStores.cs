using System.Collections.Concurrent;

namespace SimpleAuth;

/// <summary>
/// In-memory <see cref="IClientStore"/> implementation for development and tests.
/// </summary>
public sealed class InMemoryClientStore : IClientStore
{
    private readonly ConcurrentDictionary<string, Client> _clients;

    /// <summary>
    /// Creates a store seeded with the provided clients.
    /// </summary>
    /// <param name="clients">Initial clients.</param>
    public InMemoryClientStore(IEnumerable<Client>? clients = null)
    {
        _clients = new ConcurrentDictionary<string, Client>(StringComparer.Ordinal);

        if (clients is not null)
        {
            foreach (Client client in clients)
            {
                _clients[client.ClientId] = client;
            }
        }
    }

    /// <summary>Adds or replaces a client.</summary>
    public void Upsert(Client client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _clients[client.ClientId] = client;
    }

    /// <inheritdoc />
    public ValueTask<Client?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_clients.TryGetValue(clientId, out Client? client) && client.Enabled)
        {
            return ValueTask.FromResult<Client?>(client);
        }

        return ValueTask.FromResult<Client?>(null);
    }
}

/// <summary>
/// In-memory <see cref="IResourceStore"/> implementation for development and tests.
/// </summary>
public sealed class InMemoryResourceStore : IResourceStore
{
    private readonly ConcurrentDictionary<string, Scope> _scopes;
    private readonly ConcurrentDictionary<string, IdentityScope> _identityScopes;
    private readonly ConcurrentDictionary<string, ProtectedResource> _resources;

    /// <summary>
    /// Creates a store seeded with the provided values.
    /// </summary>
    public InMemoryResourceStore(
        IEnumerable<Scope>? scopes = null,
        IEnumerable<IdentityScope>? identityScopes = null,
        IEnumerable<ProtectedResource>? resources = null)
    {
        _scopes = new ConcurrentDictionary<string, Scope>(StringComparer.Ordinal);
        _identityScopes = new ConcurrentDictionary<string, IdentityScope>(StringComparer.Ordinal);
        _resources = new ConcurrentDictionary<string, ProtectedResource>(StringComparer.Ordinal);

        if (scopes is not null)
        {
            foreach (Scope scope in scopes)
            {
                _scopes[scope.Name] = scope;
            }
        }

        if (identityScopes is not null)
        {
            foreach (IdentityScope scope in identityScopes)
            {
                _identityScopes[scope.Name] = scope;
            }
        }

        if (resources is not null)
        {
            foreach (ProtectedResource resource in resources)
            {
                _resources[resource.Name] = resource;
            }
        }
    }

    /// <summary>Adds or replaces a scope.</summary>
    public void UpsertScope(Scope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        _scopes[scope.Name] = scope;
    }

    /// <summary>Adds or replaces an identity scope.</summary>
    public void UpsertIdentityScope(IdentityScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        _identityScopes[scope.Name] = scope;
    }

    /// <summary>Adds or replaces a protected resource.</summary>
    public void UpsertResource(ProtectedResource resource)
    {
        ArgumentNullException.ThrowIfNull(resource);
        _resources[resource.Name] = resource;
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<Scope>> FindScopesByNameAsync(
        IEnumerable<string> scopeNames,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new List<Scope>();

        foreach (string scopeName in scopeNames)
        {
            if (_scopes.TryGetValue(scopeName, out Scope? scope) && scope.Enabled)
            {
                result.Add(scope);
            }
        }

        return ValueTask.FromResult<IReadOnlyList<Scope>>(result);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<IdentityScope>> FindIdentityScopesByNameAsync(
        IEnumerable<string> scopeNames,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new List<IdentityScope>();

        foreach (string scopeName in scopeNames)
        {
            if (_identityScopes.TryGetValue(scopeName, out IdentityScope? scope) && scope.Enabled)
            {
                result.Add(scope);
            }
        }

        return ValueTask.FromResult<IReadOnlyList<IdentityScope>>(result);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<ProtectedResource>> FindResourcesByScopeAsync(
        IEnumerable<string> scopeNames,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        HashSet<string> requested = new HashSet<string>(scopeNames, StringComparer.Ordinal);
        var result = new List<ProtectedResource>();

        foreach (ProtectedResource resource in _resources.Values)
        {
            if (!resource.Enabled)
            {
                continue;
            }

            foreach (string scopeName in resource.Scopes)
            {
                if (requested.Contains(scopeName))
                {
                    result.Add(resource);
                    break;
                }
            }
        }

        return ValueTask.FromResult<IReadOnlyList<ProtectedResource>>(result);
    }

    /// <inheritdoc />
    public ValueTask<ProtectedResource?> FindResourceByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_resources.TryGetValue(name, out ProtectedResource? resource) && resource.Enabled)
        {
            return ValueTask.FromResult<ProtectedResource?>(resource);
        }

        return ValueTask.FromResult<ProtectedResource?>(null);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<IdentityScope>> GetAllEnabledIdentityScopesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new List<IdentityScope>();

        foreach (IdentityScope scope in _identityScopes.Values)
        {
            if (scope.Enabled)
            {
                result.Add(scope);
            }
        }

        return ValueTask.FromResult<IReadOnlyList<IdentityScope>>(result);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<Scope>> GetAllEnabledScopesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new List<Scope>();

        foreach (Scope scope in _scopes.Values)
        {
            if (scope.Enabled)
            {
                result.Add(scope);
            }
        }

        return ValueTask.FromResult<IReadOnlyList<Scope>>(result);
    }
}

/// <summary>
/// In-memory <see cref="IAuthorizationCodeStore"/> implementation.
/// </summary>
public sealed class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, AuthorizationCode> _codes;

    /// <summary>Creates an empty authorization code store.</summary>
    public InMemoryAuthorizationCodeStore()
    {
        _codes = new Dictionary<string, AuthorizationCode>(StringComparer.Ordinal);
    }

    /// <summary>
    /// Seeds the store with existing authorization codes.
    /// </summary>
    public InMemoryAuthorizationCodeStore(IEnumerable<AuthorizationCode>? codes)
        : this()
    {
        if (codes is not null)
        {
            foreach (AuthorizationCode code in codes)
            {
                _codes[code.Code] = code;
            }
        }
    }

    /// <inheritdoc />
    public Task StoreAsync(AuthorizationCode code, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(code);

        lock (_gate)
        {
            _codes[code.Code] = code;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<AuthorizationCode?> ConsumeAsync(string codeHandle, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            if (!_codes.TryGetValue(codeHandle, out AuthorizationCode? code))
            {
                return Task.FromResult<AuthorizationCode?>(null);
            }

            _codes.Remove(codeHandle);

            if (code.IsConsumed || code.ExpiresAt <= DateTime.UtcNow)
            {
                return Task.FromResult<AuthorizationCode?>(null);
            }

            return Task.FromResult<AuthorizationCode?>(new AuthorizationCode
            {
                Code = code.Code,
                ClientId = code.ClientId,
                SubjectId = code.SubjectId,
                RedirectUri = code.RedirectUri,
                CodeChallenge = code.CodeChallenge,
                GrantedScopes = code.GrantedScopes,
                CreatedAt = code.CreatedAt,
                ExpiresAt = code.ExpiresAt,
                Nonce = code.Nonce,
                SessionId = code.SessionId,
                AuthTime = code.AuthTime,
                AcrValue = code.AcrValue,
                IsConsumed = true,
            });
        }
    }

    /// <inheritdoc />
    public Task RemoveAllAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            var keysToRemove = new List<string>();

            foreach (KeyValuePair<string, AuthorizationCode> entry in _codes)
            {
                if (string.Equals(entry.Value.SubjectId, subjectId, StringComparison.Ordinal) &&
                    string.Equals(entry.Value.ClientId, clientId, StringComparison.Ordinal))
                {
                    keysToRemove.Add(entry.Key);
                }
            }

            foreach (string key in keysToRemove)
            {
                _codes.Remove(key);
            }
        }

        return Task.CompletedTask;
    }
}

/// <summary>
/// In-memory <see cref="IRefreshTokenStore"/> implementation.
/// </summary>
public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, RefreshToken> _tokens;

    /// <summary>Creates an empty refresh token store.</summary>
    public InMemoryRefreshTokenStore()
    {
        _tokens = new Dictionary<string, RefreshToken>(StringComparer.Ordinal);
    }

    /// <summary>
    /// Seeds the store with existing refresh tokens.
    /// </summary>
    public InMemoryRefreshTokenStore(IEnumerable<RefreshToken>? tokens)
        : this()
    {
        if (tokens is not null)
        {
            foreach (RefreshToken token in tokens)
            {
                _tokens[token.Handle] = token;
            }
        }
    }

    /// <inheritdoc />
    public Task StoreAsync(RefreshToken token, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(token);

        lock (_gate)
        {
            _tokens[token.Handle] = token;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<RefreshToken?> FindByHandleAsync(string handle, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            if (!_tokens.TryGetValue(handle, out RefreshToken? token))
            {
                return Task.FromResult<RefreshToken?>(null);
            }

            DateTime effectiveExpiry = token.SlidingExpiresAt is DateTime sliding && sliding < token.ExpiresAt
                ? sliding
                : token.ExpiresAt;

            if (token.IsRevoked || effectiveExpiry <= DateTime.UtcNow)
            {
                _tokens.Remove(handle);
                return Task.FromResult<RefreshToken?>(null);
            }

            return Task.FromResult<RefreshToken?>(token);
        }
    }

    /// <inheritdoc />
    public Task ReplaceAsync(string oldHandle, RefreshToken newToken, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(newToken);

        lock (_gate)
        {
            _tokens.Remove(oldHandle);
            _tokens[newToken.Handle] = newToken;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeAsync(string handle, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            if (_tokens.TryGetValue(handle, out RefreshToken? token))
            {
                _tokens[handle] = new RefreshToken
                {
                    Handle = token.Handle,
                    ClientId = token.ClientId,
                    SubjectId = token.SubjectId,
                    GrantedScopes = token.GrantedScopes,
                    CreatedAt = token.CreatedAt,
                    ExpiresAt = token.ExpiresAt,
                    SlidingExpiresAt = token.SlidingExpiresAt,
                    SessionId = token.SessionId,
                    IsRevoked = true,
                    Generation = token.Generation,
                    DPopJkt = token.DPopJkt,
                };
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeAllAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            var keysToRevoke = new List<string>();

            foreach (KeyValuePair<string, RefreshToken> entry in _tokens)
            {
                if (string.Equals(entry.Value.SubjectId, subjectId, StringComparison.Ordinal) &&
                    string.Equals(entry.Value.ClientId, clientId, StringComparison.Ordinal))
                {
                    keysToRevoke.Add(entry.Key);
                }
            }

            foreach (string key in keysToRevoke)
            {
                RevokeKey(key);
            }
        }

        return Task.CompletedTask;
    }

    private void RevokeKey(string key)
    {
        if (_tokens.TryGetValue(key, out RefreshToken? token))
        {
            _tokens[key] = new RefreshToken
            {
                Handle = token.Handle,
                ClientId = token.ClientId,
                SubjectId = token.SubjectId,
                GrantedScopes = token.GrantedScopes,
                CreatedAt = token.CreatedAt,
                ExpiresAt = token.ExpiresAt,
                SlidingExpiresAt = token.SlidingExpiresAt,
                SessionId = token.SessionId,
                IsRevoked = true,
                Generation = token.Generation,
                DPopJkt = token.DPopJkt,
            };
        }
    }
}

/// <summary>
/// In-memory <see cref="ITokenStore"/> implementation.
/// </summary>
public sealed class InMemoryTokenStore : ITokenStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, IssuedToken> _tokens;

    /// <summary>Creates an empty token store.</summary>
    public InMemoryTokenStore()
    {
        _tokens = new Dictionary<string, IssuedToken>(StringComparer.Ordinal);
    }

    /// <summary>
    /// Seeds the store with existing issued tokens.
    /// </summary>
    public InMemoryTokenStore(IEnumerable<IssuedToken>? tokens)
        : this()
    {
        if (tokens is not null)
        {
            foreach (IssuedToken token in tokens)
            {
                _tokens[token.Handle] = token;
            }
        }
    }

    /// <inheritdoc />
    public Task StoreAsync(IssuedToken token, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(token);

        lock (_gate)
        {
            _tokens[token.Handle] = token;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IssuedToken?> FindByHandleAsync(string handle, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            if (!_tokens.TryGetValue(handle, out IssuedToken? token))
            {
                return Task.FromResult<IssuedToken?>(null);
            }

            if (token.IsRevoked || token.ExpiresAt <= DateTime.UtcNow)
            {
                _tokens.Remove(handle);
                return Task.FromResult<IssuedToken?>(null);
            }

            return Task.FromResult<IssuedToken?>(token);
        }
    }

    /// <inheritdoc />
    public Task RevokeAsync(string handle, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            if (_tokens.TryGetValue(handle, out IssuedToken? token))
            {
                _tokens[handle] = new IssuedToken
                {
                    Handle = token.Handle,
                    ClientId = token.ClientId,
                    SubjectId = token.SubjectId,
                    GrantedScopes = token.GrantedScopes,
                    CreatedAt = token.CreatedAt,
                    ExpiresAt = token.ExpiresAt,
                    IsRevoked = true,
                    RefreshTokenHandle = token.RefreshTokenHandle,
                    JktThumbprint = token.JktThumbprint,
                };
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeByRefreshTokenAsync(string refreshTokenHandle, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            var keysToRevoke = new List<string>();

            foreach (KeyValuePair<string, IssuedToken> entry in _tokens)
            {
                if (string.Equals(entry.Value.RefreshTokenHandle, refreshTokenHandle, StringComparison.Ordinal))
                {
                    keysToRevoke.Add(entry.Key);
                }
            }

            foreach (string key in keysToRevoke)
            {
                RevokeKey(key);
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeAllAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            var keysToRevoke = new List<string>();

            foreach (KeyValuePair<string, IssuedToken> entry in _tokens)
            {
                if (string.Equals(entry.Value.SubjectId, subjectId, StringComparison.Ordinal) &&
                    string.Equals(entry.Value.ClientId, clientId, StringComparison.Ordinal))
                {
                    keysToRevoke.Add(entry.Key);
                }
            }

            foreach (string key in keysToRevoke)
            {
                RevokeKey(key);
            }
        }

        return Task.CompletedTask;
    }

    private void RevokeKey(string handle)
    {
        if (_tokens.TryGetValue(handle, out IssuedToken? token))
        {
            _tokens[handle] = new IssuedToken
            {
                Handle = token.Handle,
                ClientId = token.ClientId,
                SubjectId = token.SubjectId,
                GrantedScopes = token.GrantedScopes,
                CreatedAt = token.CreatedAt,
                ExpiresAt = token.ExpiresAt,
                IsRevoked = true,
                RefreshTokenHandle = token.RefreshTokenHandle,
                JktThumbprint = token.JktThumbprint,
            };
        }
    }
}

/// <summary>
/// In-memory <see cref="ISigningKeyStore"/> implementation.
/// </summary>
public sealed class InMemorySigningKeyStore : ISigningKeyStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, SigningKeyInfo> _keys;

    /// <summary>Creates an empty signing key store.</summary>
    public InMemorySigningKeyStore()
    {
        _keys = new Dictionary<string, SigningKeyInfo>(StringComparer.Ordinal);
    }

    /// <summary>
    /// Seeds the store with existing signing keys.
    /// </summary>
    public InMemorySigningKeyStore(IEnumerable<SigningKeyInfo>? keys)
        : this()
    {
        if (keys is not null)
        {
            foreach (SigningKeyInfo key in keys)
            {
                _keys[key.KeyId] = key;
            }
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<SigningKeyInfo>> GetActiveKeysAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            DateTime now = DateTime.UtcNow;
            var result = new List<SigningKeyInfo>();

            foreach (SigningKeyInfo key in _keys.Values)
            {
                if (key.RetireAt > now && key.RemoveAt > now)
                {
                    result.Add(key);
                }
            }

            return Task.FromResult<IReadOnlyList<SigningKeyInfo>>(result);
        }
    }

    /// <inheritdoc />
    public Task<SigningKeyInfo?> GetPrimaryKeyAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            DateTime now = DateTime.UtcNow;

            foreach (SigningKeyInfo key in _keys.Values)
            {
                if (key.IsPrimary && key.RemoveAt > now)
                {
                    return Task.FromResult<SigningKeyInfo?>(key);
                }
            }

            return Task.FromResult<SigningKeyInfo?>(null);
        }
    }

    /// <inheritdoc />
    public Task AddAsync(SigningKeyInfo key, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(key);

        lock (_gate)
        {
            if (key.IsPrimary)
            {
                DemotePrimary();
            }

            _keys[key.KeyId] = key;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SetPrimaryAsync(string keyId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            if (!_keys.TryGetValue(keyId, out SigningKeyInfo? existing))
            {
                return Task.CompletedTask;
            }

            DemotePrimary();
            _keys[keyId] = new SigningKeyInfo
            {
                KeyId = existing.KeyId,
                Algorithm = existing.Algorithm,
                PrivateKeyPem = existing.PrivateKeyPem,
                CreatedAt = existing.CreatedAt,
                RetireAt = existing.RetireAt,
                RemoveAt = existing.RemoveAt,
                IsPrimary = true,
            };
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RemoveExpiredAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            DateTime now = DateTime.UtcNow;
            var keysToRemove = new List<string>();

            foreach (KeyValuePair<string, SigningKeyInfo> entry in _keys)
            {
                if (entry.Value.RemoveAt <= now)
                {
                    keysToRemove.Add(entry.Key);
                }
            }

            foreach (string keyId in keysToRemove)
            {
                _keys.Remove(keyId);
            }
        }

        return Task.CompletedTask;
    }

    private void DemotePrimary()
    {
        var currentKeys = _keys.Keys.ToArray();
        foreach (string keyId in currentKeys)
        {
            SigningKeyInfo key = _keys[keyId];
            if (key.IsPrimary)
            {
                _keys[keyId] = new SigningKeyInfo
                {
                    KeyId = key.KeyId,
                    Algorithm = key.Algorithm,
                    PrivateKeyPem = key.PrivateKeyPem,
                    CreatedAt = key.CreatedAt,
                    RetireAt = key.RetireAt,
                    RemoveAt = key.RemoveAt,
                    IsPrimary = false,
                };
            }
        }
    }
}

/// <summary>
/// In-memory <see cref="IJtiStore"/> implementation.
/// </summary>
public sealed class InMemoryJtiStore : IJtiStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, DateTime> _jtis;

    /// <summary>Creates an empty JTI store.</summary>
    public InMemoryJtiStore()
    {
        _jtis = new Dictionary<string, DateTime>(StringComparer.Ordinal);
    }

    /// <inheritdoc />
    public Task<bool> TryConsumeAsync(string jti, DateTime expiry, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            DateTime now = DateTime.UtcNow;
            PruneExpired(now);

            if (_jtis.TryGetValue(jti, out DateTime existingExpiry))
            {
                if (existingExpiry > now)
                {
                    return Task.FromResult(false);
                }

                _jtis.Remove(jti);
            }

            _jtis[jti] = expiry;
            return Task.FromResult(true);
        }
    }

    private void PruneExpired(DateTime now)
    {
        var expired = new List<string>();

        foreach (KeyValuePair<string, DateTime> entry in _jtis)
        {
            if (entry.Value <= now)
            {
                expired.Add(entry.Key);
            }
        }

        foreach (string key in expired)
        {
            _jtis.Remove(key);
        }
    }
}

/// <summary>
/// In-memory <see cref="IConsentStore"/> implementation.
/// </summary>
public sealed class InMemoryConsentStore : IConsentStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<(string SubjectId, string ClientId), UserConsent> _consents;

    /// <summary>Creates an empty consent store.</summary>
    public InMemoryConsentStore()
    {
        _consents = new Dictionary<(string SubjectId, string ClientId), UserConsent>();
    }

    /// <inheritdoc />
    public Task<UserConsent?> FindAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            if (!_consents.TryGetValue((subjectId, clientId), out UserConsent? consent))
            {
                return Task.FromResult<UserConsent?>(null);
            }

            if (consent.ExpiresAt is DateTime expiresAt && expiresAt <= DateTime.UtcNow)
            {
                _consents.Remove((subjectId, clientId));
                return Task.FromResult<UserConsent?>(null);
            }

            return Task.FromResult<UserConsent?>(consent);
        }
    }

    /// <inheritdoc />
    public Task StoreAsync(UserConsent consent, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(consent);

        lock (_gate)
        {
            _consents[(consent.SubjectId, consent.ClientId)] = consent;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RemoveAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            _consents.Remove((subjectId, clientId));
        }

        return Task.CompletedTask;
    }
}

/// <summary>In-memory <see cref="IParStore"/> implementation.</summary>
public sealed class InMemoryParStore : IParStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, ParEntry> _entries = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task StoreAsync(ParEntry entry, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(entry);

        lock (_gate)
        {
            _entries[entry.RequestUri] = entry;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<ParEntry?> ConsumeAsync(string requestUri, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(requestUri);

        lock (_gate)
        {
            if (!_entries.Remove(requestUri, out ParEntry? entry))
            {
                return Task.FromResult<ParEntry?>(null);
            }

            if (entry.ExpiresAt <= DateTime.UtcNow)
            {
                return Task.FromResult<ParEntry?>(null);
            }

            return Task.FromResult<ParEntry?>(entry);
        }
    }
}
