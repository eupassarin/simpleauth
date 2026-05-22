using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SimpleAuth.EntityFramework.Entities;

namespace SimpleAuth.EntityFramework.Stores;

/// <summary>
/// EF Core implementation of <see cref="IAuthorizationCodeStore"/>.
/// <see cref="ConsumeAsync"/> uses a serializable transaction to guarantee atomicity —
/// a code can only be redeemed once even under concurrent requests.
/// </summary>
internal sealed class EfAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly SimpleAuthDbContext _context;

    public EfAuthorizationCodeStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task StoreAsync(AuthorizationCode code, CancellationToken cancellationToken = default)
    {
        AuthorizationCodeEntity entity = new()
        {
            Handle = code.Code,
            ClientId = code.ClientId,
            SubjectId = code.SubjectId,
            RedirectUri = code.RedirectUri,
            CodeChallenge = code.CodeChallenge,
            GrantedScopes = JsonConverters.SerializeStringList(code.GrantedScopes),
            CreatedAt = code.CreatedAt,
            ExpiresAt = code.ExpiresAt,
            Nonce = code.Nonce,
            SessionId = code.SessionId,
            AuthTime = code.AuthTime,
            AcrValue = code.AcrValue,
            IsConsumed = false,
        };

        _context.AuthorizationCodes.Add(entity);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<CodeConsumeResult> ConsumeAsync(string codeHandle, CancellationToken cancellationToken = default)
    {
        using IDbContextTransaction tx = await _context.Database
            .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            .ConfigureAwait(false);

        // Find the code regardless of IsConsumed, so we can detect reuse.
        AuthorizationCodeEntity? entity = await _context.AuthorizationCodes
            .Where(c => c.Handle == codeHandle)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return CodeConsumeResult.Invalid;
        }

        if (entity.IsConsumed)
        {
            // Replay attack — code was already consumed.
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return CodeConsumeResult.Reused(entity.SubjectId, entity.ClientId);
        }

        if (entity.ExpiresAt <= DateTime.UtcNow)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return CodeConsumeResult.Invalid;
        }

        entity.IsConsumed = true;
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);

        return CodeConsumeResult.Success(MapToModel(entity));
    }

    public async Task RemoveAllAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        await _context.AuthorizationCodes
            .Where(c => c.SubjectId == subjectId && c.ClientId == clientId)
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static AuthorizationCode MapToModel(AuthorizationCodeEntity e) => new()
    {
        Code = e.Handle,
        ClientId = e.ClientId,
        SubjectId = e.SubjectId,
        RedirectUri = e.RedirectUri,
        CodeChallenge = e.CodeChallenge,
        GrantedScopes = JsonConverters.DeserializeStringList(e.GrantedScopes),
        CreatedAt = e.CreatedAt,
        ExpiresAt = e.ExpiresAt,
        Nonce = e.Nonce,
        SessionId = e.SessionId,
        AuthTime = e.AuthTime,
        AcrValue = e.AcrValue,
        IsConsumed = e.IsConsumed,
    };
}

/// <summary>EF Core implementation of <see cref="IRefreshTokenStore"/>.</summary>
internal sealed class EfRefreshTokenStore : IRefreshTokenStore
{
    private readonly SimpleAuthDbContext _context;

    public EfRefreshTokenStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task StoreAsync(RefreshToken token, CancellationToken cancellationToken = default)
    {
        RefreshTokenEntity entity = new()
        {
            Handle = token.Handle,
            ClientId = token.ClientId,
            SubjectId = token.SubjectId,
            GrantedScopes = JsonConverters.SerializeStringList(token.GrantedScopes),
            CreatedAt = token.CreatedAt,
            ExpiresAt = token.ExpiresAt,
            SlidingExpiresAt = token.SlidingExpiresAt,
            SessionId = token.SessionId,
            IsRevoked = false,
            Generation = token.Generation,
            DPopJkt = token.DPopJkt,
        };

        _context.RefreshTokens.Add(entity);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<RefreshToken?> FindByHandleAsync(string handle, CancellationToken cancellationToken = default)
    {
        RefreshTokenEntity? entity = await _context.RefreshTokens
            .Where(r => r.Handle == handle && !r.IsRevoked && r.ExpiresAt > DateTime.UtcNow)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return entity is null ? null : MapToModel(entity);
    }

    public async Task ReplaceAsync(string oldHandle, RefreshToken newToken, CancellationToken cancellationToken = default)
    {
        using IDbContextTransaction tx = await _context.Database
            .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            .ConfigureAwait(false);

        await _context.RefreshTokens
            .Where(r => r.Handle == oldHandle)
            .ExecuteUpdateAsync(setters => setters.SetProperty(r => r.IsRevoked, true), cancellationToken)
            .ConfigureAwait(false);

        RefreshTokenEntity newEntity = new()
        {
            Handle = newToken.Handle,
            ClientId = newToken.ClientId,
            SubjectId = newToken.SubjectId,
            GrantedScopes = JsonConverters.SerializeStringList(newToken.GrantedScopes),
            CreatedAt = newToken.CreatedAt,
            ExpiresAt = newToken.ExpiresAt,
            SlidingExpiresAt = newToken.SlidingExpiresAt,
            SessionId = newToken.SessionId,
            IsRevoked = false,
            Generation = newToken.Generation,
            DPopJkt = newToken.DPopJkt,
        };

        _context.RefreshTokens.Add(newEntity);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RevokeAsync(string handle, CancellationToken cancellationToken = default)
    {
        await _context.RefreshTokens
            .Where(r => r.Handle == handle)
            .ExecuteUpdateAsync(setters => setters.SetProperty(r => r.IsRevoked, true), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task RevokeAllAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        await _context.RefreshTokens
            .Where(r => r.SubjectId == subjectId && r.ClientId == clientId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(r => r.IsRevoked, true), cancellationToken)
            .ConfigureAwait(false);
    }

    private static RefreshToken MapToModel(RefreshTokenEntity e) => new()
    {
        Handle = e.Handle,
        ClientId = e.ClientId,
        SubjectId = e.SubjectId,
        GrantedScopes = JsonConverters.DeserializeStringList(e.GrantedScopes),
        CreatedAt = e.CreatedAt,
        ExpiresAt = e.ExpiresAt,
        SlidingExpiresAt = e.SlidingExpiresAt,
        SessionId = e.SessionId,
        IsRevoked = e.IsRevoked,
        Generation = e.Generation,
        DPopJkt = e.DPopJkt,
    };
}

/// <summary>EF Core implementation of <see cref="ITokenStore"/>.</summary>
internal sealed class EfTokenStore : ITokenStore
{
    private readonly SimpleAuthDbContext _context;

    public EfTokenStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task StoreAsync(IssuedToken token, CancellationToken cancellationToken = default)
    {
        IssuedTokenEntity entity = new()
        {
            Handle = token.Handle,
            ClientId = token.ClientId,
            SubjectId = token.SubjectId,
            GrantedScopes = JsonConverters.SerializeStringList(token.GrantedScopes),
            CreatedAt = token.CreatedAt,
            ExpiresAt = token.ExpiresAt,
            IsRevoked = false,
            RefreshTokenHandle = token.RefreshTokenHandle,
            AuthorizationCodeHandle = token.AuthorizationCodeHandle,
            JktThumbprint = token.JktThumbprint,
        };

        _context.IssuedTokens.Add(entity);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IssuedToken?> FindByHandleAsync(string handle, CancellationToken cancellationToken = default)
    {
        IssuedTokenEntity? entity = await _context.IssuedTokens
            .Where(t => t.Handle == handle && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return entity is null ? null : MapToModel(entity);
    }

    public async Task RevokeAsync(string handle, CancellationToken cancellationToken = default)
    {
        await _context.IssuedTokens
            .Where(t => t.Handle == handle)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.IsRevoked, true), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task RevokeByRefreshTokenAsync(string refreshTokenHandle, CancellationToken cancellationToken = default)
    {
        await _context.IssuedTokens
            .Where(t => t.RefreshTokenHandle == refreshTokenHandle)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.IsRevoked, true), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task RevokeAllAsync(string subjectId, string clientId, CancellationToken cancellationToken = default)
    {
        await _context.IssuedTokens
            .Where(t => t.SubjectId == subjectId && t.ClientId == clientId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.IsRevoked, true), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task RevokeByAuthCodeHandleAsync(string authorizationCodeHandle, CancellationToken cancellationToken = default)
    {
        await _context.IssuedTokens
            .Where(t => t.AuthorizationCodeHandle == authorizationCodeHandle)
            .ExecuteUpdateAsync(setters => setters.SetProperty(t => t.IsRevoked, true), cancellationToken)
            .ConfigureAwait(false);
    }

    private static IssuedToken MapToModel(IssuedTokenEntity e) => new()
    {
        Handle = e.Handle,
        ClientId = e.ClientId,
        SubjectId = e.SubjectId,
        GrantedScopes = JsonConverters.DeserializeStringList(e.GrantedScopes),
        CreatedAt = e.CreatedAt,
        ExpiresAt = e.ExpiresAt,
        IsRevoked = e.IsRevoked,
        RefreshTokenHandle = e.RefreshTokenHandle,
        AuthorizationCodeHandle = e.AuthorizationCodeHandle,
        JktThumbprint = e.JktThumbprint,
    };
}

/// <summary>
/// EF Core implementation of <see cref="IParStore"/>.
/// <see cref="ConsumeAsync"/> uses a serializable transaction for one-time-use enforcement.
/// </summary>
internal sealed class EfParStore : IParStore
{
    private readonly SimpleAuthDbContext _context;

    public EfParStore(SimpleAuthDbContext context)
    {
        _context = context;
    }

    public async Task StoreAsync(ParEntry entry, CancellationToken cancellationToken = default)
    {
        ParEntryEntity entity = new()
        {
            RequestUri = entry.RequestUri,
            ClientId = entry.ClientId,
            RedirectUri = entry.RedirectUri,
            Scope = entry.Scope,
            CodeChallenge = entry.CodeChallenge,
            CodeChallengeMethod = entry.CodeChallengeMethod,
            ResponseType = entry.ResponseType,
            State = entry.State,
            Nonce = entry.Nonce,
            CreatedAt = entry.CreatedAt,
            ExpiresAt = entry.ExpiresAt,
        };

        _context.ParEntries.Add(entity);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ParEntry?> ConsumeAsync(string requestUri, CancellationToken cancellationToken = default)
    {
        using IDbContextTransaction tx = await _context.Database
            .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            .ConfigureAwait(false);

        ParEntryEntity? entity = await _context.ParEntries
            .Where(p => p.RequestUri == requestUri && p.ExpiresAt > DateTime.UtcNow)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return null;
        }

        _context.ParEntries.Remove(entity);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);

        return MapToModel(entity);
    }

    private static ParEntry MapToModel(ParEntryEntity e) => new()
    {
        RequestUri = e.RequestUri,
        ClientId = e.ClientId,
        RedirectUri = e.RedirectUri,
        Scope = e.Scope,
        CodeChallenge = e.CodeChallenge,
        CodeChallengeMethod = e.CodeChallengeMethod,
        ResponseType = e.ResponseType,
        State = e.State,
        Nonce = e.Nonce,
        CreatedAt = e.CreatedAt,
        ExpiresAt = e.ExpiresAt,
    };
}
