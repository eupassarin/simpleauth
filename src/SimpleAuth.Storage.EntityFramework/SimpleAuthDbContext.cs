using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SimpleAuth.EntityFramework.Entities;

namespace SimpleAuth.EntityFramework;

/// <summary>
/// EF Core <see cref="DbContext"/> for SimpleAuth persistence.
/// Consumers must derive from this class (or register it directly) and configure the provider.
/// </summary>
public class SimpleAuthDbContext : DbContext
{
    /// <inheritdoc />
    public SimpleAuthDbContext(DbContextOptions options) : base(options) { }

    /// <summary>Registered OAuth 2.1 clients.</summary>
    internal DbSet<ClientEntity> Clients => Set<ClientEntity>();

    /// <summary>Authorization codes (single-use, short-lived).</summary>
    internal DbSet<AuthorizationCodeEntity> AuthorizationCodes => Set<AuthorizationCodeEntity>();

    /// <summary>Refresh token records.</summary>
    internal DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();

    /// <summary>Issued (reference) access tokens.</summary>
    internal DbSet<IssuedTokenEntity> IssuedTokens => Set<IssuedTokenEntity>();

    /// <summary>PAR entries (RFC 9126).</summary>
    internal DbSet<ParEntryEntity> ParEntries => Set<ParEntryEntity>();

    /// <summary>Signing key records for key rotation.</summary>
    internal DbSet<SigningKeyEntity> SigningKeys => Set<SigningKeyEntity>();

    /// <summary>JTI replay prevention records.</summary>
    internal DbSet<JtiRecordEntity> JtiRecords => Set<JtiRecordEntity>();

    /// <summary>User consent records.</summary>
    internal DbSet<UserConsentEntity> UserConsents => Set<UserConsentEntity>();

    /// <summary>Server settings (key-value, runtime configurable via admin GUI).</summary>
    internal DbSet<ServerSettingsEntity> ServerSettings => Set<ServerSettingsEntity>();

    /// <summary>API scope registrations.</summary>
    internal DbSet<ScopeEntity> Scopes => Set<ScopeEntity>();

    /// <summary>OIDC identity scope registrations.</summary>
    internal DbSet<IdentityScopeEntity> IdentityScopes => Set<IdentityScopeEntity>();

    /// <summary>Protected resource (API) registrations.</summary>
    internal DbSet<ProtectedResourceEntity> ProtectedResources => Set<ProtectedResourceEntity>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        ConfigureClient(modelBuilder.Entity<ClientEntity>());
        ConfigureAuthorizationCode(modelBuilder.Entity<AuthorizationCodeEntity>());
        ConfigureRefreshToken(modelBuilder.Entity<RefreshTokenEntity>());
        ConfigureIssuedToken(modelBuilder.Entity<IssuedTokenEntity>());
        ConfigureParEntry(modelBuilder.Entity<ParEntryEntity>());
        ConfigureSigningKey(modelBuilder.Entity<SigningKeyEntity>());
        ConfigureJtiRecord(modelBuilder.Entity<JtiRecordEntity>());
        ConfigureUserConsent(modelBuilder.Entity<UserConsentEntity>());
        ConfigureIdentityScope(modelBuilder.Entity<IdentityScopeEntity>());
        ConfigureServerSettings(modelBuilder.Entity<ServerSettingsEntity>());
    }

    // ── Entity configurations ────────────────────────────────────────────────────

    private static void ConfigureClient(EntityTypeBuilder<ClientEntity> b)
    {
        b.ToTable("Clients");
        b.HasIndex(e => e.ClientId).IsUnique();
    }

    private static void ConfigureAuthorizationCode(EntityTypeBuilder<AuthorizationCodeEntity> b)
    {
        b.ToTable("AuthorizationCodes");
        b.HasIndex(e => e.Handle).IsUnique();
        b.HasIndex(e => new { e.SubjectId, e.ClientId });
        b.HasIndex(e => e.ExpiresAt); // for cleanup queries
    }

    private static void ConfigureRefreshToken(EntityTypeBuilder<RefreshTokenEntity> b)
    {
        b.ToTable("RefreshTokens");
        b.HasIndex(e => e.Handle).IsUnique();
        b.HasIndex(e => new { e.SubjectId, e.ClientId });
        b.HasIndex(e => e.ExpiresAt);
    }

    private static void ConfigureIssuedToken(EntityTypeBuilder<IssuedTokenEntity> b)
    {
        b.ToTable("IssuedTokens");
        b.HasIndex(e => e.Handle).IsUnique();
        b.HasIndex(e => new { e.SubjectId, e.ClientId });
        b.HasIndex(e => e.RefreshTokenHandle);
        b.HasIndex(e => e.AuthorizationCodeHandle);
        b.HasIndex(e => e.ExpiresAt);
    }

    private static void ConfigureParEntry(EntityTypeBuilder<ParEntryEntity> b)
    {
        b.ToTable("ParEntries");
        b.HasIndex(e => e.ExpiresAt);
    }

    private static void ConfigureSigningKey(EntityTypeBuilder<SigningKeyEntity> b)
    {
        b.ToTable("SigningKeys");
        b.HasIndex(e => e.IsPrimary);
        b.HasIndex(e => e.RemoveAt);
    }

    private static void ConfigureJtiRecord(EntityTypeBuilder<JtiRecordEntity> b)
    {
        b.ToTable("JtiRecords");
        // Unique constraint is the key itself (KeyId = Jti); duplicate insert fails
        b.HasIndex(e => e.ExpiresAt); // for cleanup
    }

    private static void ConfigureUserConsent(EntityTypeBuilder<UserConsentEntity> b)
    {
        b.ToTable("UserConsents");
        b.HasKey(e => new { e.SubjectId, e.ClientId });
        b.HasIndex(e => new { e.SubjectId, e.ClientId }).IsUnique();
    }

    private static void ConfigureIdentityScope(EntityTypeBuilder<IdentityScopeEntity> b) =>
        b.ToTable("IdentityScopes");

    private static void ConfigureServerSettings(EntityTypeBuilder<ServerSettingsEntity> b) =>
        b.ToTable("ServerSettings");
}

/// <summary>Reusable JSON value converters for entity collections.</summary>
internal static class JsonConverters
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    internal static string SerializeStringList(IEnumerable<string> list) =>
        JsonSerializer.Serialize(list, Options);

    internal static IReadOnlyList<string> DeserializeStringList(string json) =>
        JsonSerializer.Deserialize<List<string>>(json, Options) ?? [];

    internal static string SerializeObject<T>(T obj) =>
        JsonSerializer.Serialize(obj, Options);

    internal static T? DeserializeObject<T>(string? json) =>
        json is null ? default : JsonSerializer.Deserialize<T>(json, Options);
}
