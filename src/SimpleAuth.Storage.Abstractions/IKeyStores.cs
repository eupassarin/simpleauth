namespace SimpleAuth;

/// <summary>Persists and retrieves <see cref="SigningKeyInfo"/> records for key rotation.</summary>
public interface ISigningKeyStore
{
    /// <summary>Returns all active signing keys (not yet retired or removed).</summary>
    Task<IReadOnlyList<SigningKeyInfo>> GetActiveKeysAsync(CancellationToken cancellationToken = default);

    /// <summary>Returns the current primary signing key.</summary>
    Task<SigningKeyInfo?> GetPrimaryKeyAsync(CancellationToken cancellationToken = default);

    /// <summary>Adds a new signing key to the store.</summary>
    Task AddAsync(SigningKeyInfo key, CancellationToken cancellationToken = default);

    /// <summary>Sets the specified key as the primary signing key. Previous primary is demoted.</summary>
    Task SetPrimaryAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>Removes signing keys whose <see cref="SigningKeyInfo.RemoveAt"/> is in the past.</summary>
    Task RemoveExpiredAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Prevents replay of <c>private_key_jwt</c> assertions by tracking consumed JTIs.
/// Implementations MUST be thread-safe and, in distributed deployments, use a shared store (e.g., Redis).
/// </summary>
public interface IJtiStore
{
    /// <summary>
    /// Atomically records a JTI and returns <see langword="true"/> if it was new.
    /// Returns <see langword="false"/> if the JTI was already present (replay detected).
    /// The JTI is automatically expired after <paramref name="expiry"/>.
    /// </summary>
    /// <remarks>
    /// Redis implementations should use <c>SET key NX EX seconds</c>.
    /// SQL implementations should use a unique constraint with a background cleanup job.
    /// </remarks>
    Task<bool> TryConsumeAsync(string jti, DateTime expiry, CancellationToken cancellationToken = default);
}

/// <summary>Stores and retrieves <see cref="UserConsent"/> records.</summary>
public interface IConsentStore
{
    /// <summary>
    /// Returns the stored consent for a subject/client pair, or <see langword="null"/> if none exists.
    /// Expired consents are returned as <see langword="null"/>.
    /// </summary>
    Task<UserConsent?> FindAsync(string subjectId, string clientId, CancellationToken cancellationToken = default);

    /// <summary>Stores or updates a consent record.</summary>
    Task StoreAsync(UserConsent consent, CancellationToken cancellationToken = default);

    /// <summary>Removes the consent record for a subject/client pair.</summary>
    Task RemoveAsync(string subjectId, string clientId, CancellationToken cancellationToken = default);
}
