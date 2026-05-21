using Microsoft.EntityFrameworkCore;
using SimpleAuth.EntityFramework.Entities;

namespace SimpleAuth.EntityFramework.Stores;

/// <summary>EF Core implementation of <see cref="ISigningKeyStore"/>.</summary>
internal sealed class EfSigningKeyStore : ISigningKeyStore
{
    private readonly SimpleAuthDbContext _context;

    public EfSigningKeyStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task<IReadOnlyList<SigningKeyInfo>> GetActiveKeysAsync(CancellationToken cancellationToken = default)
    {
        DateTime now = DateTime.UtcNow;

        return await _context.SigningKeys
            .AsNoTracking()
            .Where(k => k.RemoveAt > now)
            .OrderByDescending(k => k.IsPrimary)
            .ThenByDescending(k => k.CreatedAt)
            .Select(k => new SigningKeyInfo
            {
                KeyId = k.KeyId,
                Algorithm = k.Algorithm,
                PrivateKeyPem = k.PrivateKeyPem,
                CreatedAt = k.CreatedAt,
                RetireAt = k.RetireAt,
                RemoveAt = k.RemoveAt,
                IsPrimary = k.IsPrimary,
            })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<SigningKeyInfo?> GetPrimaryKeyAsync(CancellationToken cancellationToken = default)
    {
        DateTime now = DateTime.UtcNow;

        SigningKeyEntity? entity = await _context.SigningKeys
            .AsNoTracking()
            .Where(k => k.IsPrimary && k.RetireAt > now)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return entity is null ? null : MapToModel(entity);
    }

    public async Task AddAsync(SigningKeyInfo key, CancellationToken cancellationToken = default)
    {
        SigningKeyEntity entity = new()
        {
            KeyId = key.KeyId,
            Algorithm = key.Algorithm,
            PrivateKeyPem = key.PrivateKeyPem,
            CreatedAt = key.CreatedAt,
            RetireAt = key.RetireAt,
            RemoveAt = key.RemoveAt,
            IsPrimary = key.IsPrimary,
        };

        _context.SigningKeys.Add(entity);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SetPrimaryAsync(string keyId, CancellationToken cancellationToken = default)
    {
        // Use a transaction to prevent race conditions during concurrent key rotations.
        await using var transaction = await _context.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        // Demote all current primary keys, then promote the target.
        await _context.SigningKeys
            .Where(k => k.IsPrimary)
            .ExecuteUpdateAsync(setters => setters.SetProperty(k => k.IsPrimary, false), cancellationToken)
            .ConfigureAwait(false);

        await _context.SigningKeys
            .Where(k => k.KeyId == keyId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(k => k.IsPrimary, true), cancellationToken)
            .ConfigureAwait(false);

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RemoveExpiredAsync(CancellationToken cancellationToken = default)
    {
        DateTime now = DateTime.UtcNow;

        await _context.SigningKeys
            .Where(k => k.RemoveAt <= now)
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static SigningKeyInfo MapToModel(SigningKeyEntity e) => new()
    {
        KeyId = e.KeyId,
        Algorithm = e.Algorithm,
        PrivateKeyPem = e.PrivateKeyPem,
        CreatedAt = e.CreatedAt,
        RetireAt = e.RetireAt,
        RemoveAt = e.RemoveAt,
        IsPrimary = e.IsPrimary,
    };
}

/// <summary>
/// EF Core implementation of <see cref="IJtiStore"/>.
/// Uses a unique primary key constraint — a duplicate <c>INSERT</c> will throw
/// <see cref="DbUpdateException"/>, which is caught and interpreted as a replay.
/// </summary>
internal sealed class EfJtiStore : IJtiStore
{
    private readonly SimpleAuthDbContext _context;

    public EfJtiStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task<bool> TryConsumeAsync(string jti, DateTime expiry, CancellationToken cancellationToken = default)
    {
        // Clear any previously tracked entity with the same PK so that the
        // duplicate-key detection always reaches the database constraint.
        _context.ChangeTracker.Clear();
        _context.JtiRecords.Add(new JtiRecordEntity { Jti = jti, ExpiresAt = expiry });
        try
        {
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateException)
        {
            // Duplicate key — this JTI was already consumed (replay detected).
            _context.ChangeTracker.Clear();
            return false;
        }
    }
}

/// <summary>EF Core implementation of <see cref="IConsentStore"/>.</summary>
internal sealed class EfConsentStore : IConsentStore
{
    private readonly SimpleAuthDbContext _context;

    public EfConsentStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task<UserConsent?> FindAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        DateTime now = DateTime.UtcNow;

        Entities.UserConsentEntity? entity = await _context.UserConsents
            .AsNoTracking()
            .Where(c => c.SubjectId == subjectId
                     && c.ClientId == clientId
                     && (c.ExpiresAt == null || c.ExpiresAt > now))
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return entity is null ? null : MapToModel(entity);
    }

    public async Task StoreAsync(UserConsent consent, CancellationToken cancellationToken = default)
    {
        Entities.UserConsentEntity? existing = await _context.UserConsents
            .Where(c => c.SubjectId == consent.SubjectId && c.ClientId == consent.ClientId)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (existing is not null)
        {
            existing.GrantedScopes = JsonConverters.SerializeStringList(consent.GrantedScopes);
            existing.CreatedAt = consent.CreatedAt;
            existing.ExpiresAt = consent.ExpiresAt;
        }
        else
        {
            _context.UserConsents.Add(new Entities.UserConsentEntity
            {
                SubjectId = consent.SubjectId,
                ClientId = consent.ClientId,
                GrantedScopes = JsonConverters.SerializeStringList(consent.GrantedScopes),
                CreatedAt = consent.CreatedAt,
                ExpiresAt = consent.ExpiresAt,
            });
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RemoveAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        await _context.UserConsents
            .Where(c => c.SubjectId == subjectId && c.ClientId == clientId)
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static UserConsent MapToModel(Entities.UserConsentEntity e) => new()
    {
        SubjectId = e.SubjectId,
        ClientId = e.ClientId,
        GrantedScopes = JsonConverters.DeserializeStringList(e.GrantedScopes),
        CreatedAt = e.CreatedAt,
        ExpiresAt = e.ExpiresAt,
    };
}
