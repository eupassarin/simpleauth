namespace SimpleAuth;

/// <summary>
/// Stores and retrieves <see cref="AuthorizationCode"/> records.
/// All operations on codes MUST be atomic to prevent replay attacks.
/// </summary>
public interface IAuthorizationCodeStore
{
    /// <summary>Persists a newly issued authorization code.</summary>
    Task StoreAsync(AuthorizationCode code, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically retrieves and marks a code as consumed.
    /// Returns <see langword="null"/> if the code is not found, already consumed, or expired.
    /// </summary>
    /// <remarks>
    /// This operation MUST be atomic. Implementations using SQL should use a single
    /// <c>UPDATE ... OUTPUT</c> or equivalent. Implementations using Redis should use a Lua script.
    /// A second call with the same handle MUST return <see langword="null"/>.
    /// </remarks>
    Task<AuthorizationCode?> ConsumeAsync(string codeHandle, CancellationToken cancellationToken = default);

    /// <summary>Removes all authorization codes for the given subject and client (e.g., on logout).</summary>
    Task RemoveAllAsync(string subjectId, string clientId, CancellationToken cancellationToken = default);
}

/// <summary>Stores and retrieves <see cref="RefreshToken"/> records.</summary>
public interface IRefreshTokenStore
{
    /// <summary>Persists a newly issued refresh token.</summary>
    Task StoreAsync(RefreshToken token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a refresh token by its handle without consuming it.
    /// Returns <see langword="null"/> if not found, expired, or revoked.
    /// </summary>
    Task<RefreshToken?> FindByHandleAsync(string handle, CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces an existing refresh token with a new one (rotation).
    /// The old token MUST be atomically invalidated and the new token persisted.
    /// </summary>
    Task ReplaceAsync(string oldHandle, RefreshToken newToken, CancellationToken cancellationToken = default);

    /// <summary>Revokes a specific refresh token.</summary>
    Task RevokeAsync(string handle, CancellationToken cancellationToken = default);

    /// <summary>Revokes all refresh tokens for the given subject and client.</summary>
    Task RevokeAllAsync(string subjectId, string clientId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Stores and retrieves <see cref="ParEntry"/> records for Pushed Authorization Requests (RFC 9126).
/// </summary>
public interface IParStore
{
    /// <summary>Persists a newly received PAR entry.</summary>
    Task StoreAsync(ParEntry entry, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically retrieves and removes a PAR entry by its <paramref name="requestUri"/>.
    /// Returns <see langword="null"/> if not found or expired.
    /// Each entry MUST be consumable only once.
    /// </summary>
    Task<ParEntry?> ConsumeAsync(string requestUri, CancellationToken cancellationToken = default);
}

/// <summary>Stores and retrieves <see cref="IssuedToken"/> records for revocation and introspection.</summary>
public interface ITokenStore
{
    /// <summary>Persists a record of an issued access token.</summary>
    Task StoreAsync(IssuedToken token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds an issued token record by its reference handle.
    /// Returns <see langword="null"/> if the token is not found, expired, or revoked.
    /// </summary>
    Task<IssuedToken?> FindByHandleAsync(string handle, CancellationToken cancellationToken = default);

    /// <summary>Marks an issued token as revoked.</summary>
    Task RevokeAsync(string handle, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all access tokens associated with the given <paramref name="refreshTokenHandle"/>.
    /// Called when a refresh token is revoked.
    /// </summary>
    Task RevokeByRefreshTokenAsync(string refreshTokenHandle, CancellationToken cancellationToken = default);

    /// <summary>Revokes all access tokens for the given subject and client (e.g., on logout).</summary>
    Task RevokeAllAsync(string subjectId, string clientId, CancellationToken cancellationToken = default);
}
