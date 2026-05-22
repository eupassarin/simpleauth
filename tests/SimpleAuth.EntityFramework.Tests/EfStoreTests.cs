using SimpleAuth.EntityFramework.Stores;

namespace SimpleAuth.EntityFramework.Tests;

/// <summary>
/// Integration tests for the EF Core store implementations.
/// Each test creates an isolated SQLite file database with a fresh schema.
/// </summary>
public sealed class EfStoreTests
{
    // ── IAuthorizationCodeStore ──────────────────────────────────────────────

    [Fact]
    public async Task AuthorizationCode_StoreAndConsume_ReturnsCode()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfAuthorizationCodeStore store = new(db);
            await store.StoreAsync(BuildCode("code-001"));

            CodeConsumeResult result = await store.ConsumeAsync("code-001");

            Assert.Equal(CodeConsumeStatus.Success, result.Status);
            Assert.NotNull(result.Code);
            Assert.Equal("code-001", result.Code.Code);
            Assert.Equal("client1", result.Code.ClientId);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task AuthorizationCode_ConsumeIsOneTimeOnly()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfAuthorizationCodeStore store = new(db);
            await store.StoreAsync(BuildCode("code-replay"));

            CodeConsumeResult first = await store.ConsumeAsync("code-replay");
            CodeConsumeResult second = await store.ConsumeAsync("code-replay");

            Assert.Equal(CodeConsumeStatus.Success, first.Status);
            Assert.Equal(CodeConsumeStatus.Reused, second.Status);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task AuthorizationCode_ExpiredCode_ReturnsNull()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfAuthorizationCodeStore store = new(db);
            await store.StoreAsync(BuildCode("code-exp", expiresAt: DateTime.UtcNow.AddSeconds(-1)));

            Assert.Equal(CodeConsumeStatus.Invalid, (await store.ConsumeAsync("code-exp")).Status);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task AuthorizationCode_UnknownHandle_ReturnsNull()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfAuthorizationCodeStore store = new(db);
            Assert.Equal(CodeConsumeStatus.Invalid, (await store.ConsumeAsync("no-such-code")).Status);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task AuthorizationCode_RemoveAll_DeletesBySubjectAndClient()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfAuthorizationCodeStore store = new(db);
            await store.StoreAsync(BuildCode("code-a", subjectId: "user1", clientId: "client1"));
            await store.StoreAsync(BuildCode("code-b", subjectId: "user1", clientId: "client2"));

            await store.RemoveAllAsync("user1", "client1");

            Assert.Equal(CodeConsumeStatus.Invalid, (await store.ConsumeAsync("code-a")).Status);
            Assert.Equal(CodeConsumeStatus.Success, (await store.ConsumeAsync("code-b")).Status);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    // ── IRefreshTokenStore ───────────────────────────────────────────────────

    [Fact]
    public async Task RefreshToken_StoreAndFind_ReturnsToken()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfRefreshTokenStore store = new(db);
            await store.StoreAsync(BuildRefreshToken("rt-001"));

            RefreshToken? result = await store.FindByHandleAsync("rt-001");

            Assert.NotNull(result);
            Assert.Equal("rt-001", result.Handle);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task RefreshToken_Revoked_NotFound()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfRefreshTokenStore store = new(db);
            await store.StoreAsync(BuildRefreshToken("rt-rev"));
            await store.RevokeAsync("rt-rev");

            Assert.Null(await store.FindByHandleAsync("rt-rev"));
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task RefreshToken_Replace_OldRevokedNewFound()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfRefreshTokenStore store = new(db);
            await store.StoreAsync(BuildRefreshToken("rt-old"));
            await store.ReplaceAsync("rt-old", BuildRefreshToken("rt-new", generation: 1));

            Assert.Null(await store.FindByHandleAsync("rt-old"));
            Assert.NotNull(await store.FindByHandleAsync("rt-new"));
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task RefreshToken_RevokeAll_OnlyTargetedClientRevoked()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfRefreshTokenStore store = new(db);
            await store.StoreAsync(BuildRefreshToken("rt-x1", clientId: "client1"));
            await store.StoreAsync(BuildRefreshToken("rt-x2", clientId: "client2"));

            await store.RevokeAllAsync("user1", "client1");

            Assert.Null(await store.FindByHandleAsync("rt-x1"));
            Assert.NotNull(await store.FindByHandleAsync("rt-x2"));
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    // ── ITokenStore ──────────────────────────────────────────────────────────

    [Fact]
    public async Task IssuedToken_StoreAndFind_ReturnsToken()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfTokenStore store = new(db);
            await store.StoreAsync(BuildIssuedToken("tok-001"));

            IssuedToken? result = await store.FindByHandleAsync("tok-001");

            Assert.NotNull(result);
            Assert.Equal("tok-001", result.Handle);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task IssuedToken_Revoke_NotFoundAfter()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfTokenStore store = new(db);
            await store.StoreAsync(BuildIssuedToken("tok-rev"));
            await store.RevokeAsync("tok-rev");

            Assert.Null(await store.FindByHandleAsync("tok-rev"));
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task IssuedToken_RevokeByRefreshToken_OnlyLinkedRevoked()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfTokenStore store = new(db);
            await store.StoreAsync(BuildIssuedToken("tok-linked", refreshHandle: "rt-linked"));
            await store.StoreAsync(BuildIssuedToken("tok-other", refreshHandle: "rt-other"));

            await store.RevokeByRefreshTokenAsync("rt-linked");

            Assert.Null(await store.FindByHandleAsync("tok-linked"));
            Assert.NotNull(await store.FindByHandleAsync("tok-other"));
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task IssuedToken_DPoP_JktThumbprintRoundtrips()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfTokenStore store = new(db);
            await store.StoreAsync(BuildIssuedToken("tok-dpop", jkt: "abc123jkt"));

            IssuedToken? result = await store.FindByHandleAsync("tok-dpop");

            Assert.NotNull(result);
            Assert.Equal("abc123jkt", result.JktThumbprint);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    // ── IParStore ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ParEntry_StoreAndConsume_ReturnsEntry()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfParStore store = new(db);
            await store.StoreAsync(BuildParEntry("urn:par:001"));

            ParEntry? result = await store.ConsumeAsync("urn:par:001");

            Assert.NotNull(result);
            Assert.Equal("client1", result.ClientId);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task ParEntry_ConsumeIsOneTimeOnly()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfParStore store = new(db);
            await store.StoreAsync(BuildParEntry("urn:par:replay"));

            ParEntry? first = await store.ConsumeAsync("urn:par:replay");
            ParEntry? second = await store.ConsumeAsync("urn:par:replay");

            Assert.NotNull(first);
            Assert.Null(second);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task ParEntry_Expired_ReturnsNull()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfParStore store = new(db);
            await store.StoreAsync(BuildParEntry("urn:par:exp", expiresAt: DateTime.UtcNow.AddSeconds(-1)));

            Assert.Null(await store.ConsumeAsync("urn:par:exp"));
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    // ── IJtiStore ────────────────────────────────────────────────────────────

    [Fact]
    public async Task JtiStore_NewJti_ReturnsTrue()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfJtiStore store = new(db);
            bool result = await store.TryConsumeAsync("jti-new", DateTime.UtcNow.AddMinutes(5));
            Assert.True(result);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task JtiStore_ReplayJti_ReturnsFalse()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfJtiStore store = new(db);
            await store.TryConsumeAsync("jti-replay", DateTime.UtcNow.AddMinutes(5));
            bool replay = await store.TryConsumeAsync("jti-replay", DateTime.UtcNow.AddMinutes(5));
            Assert.False(replay);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    // ── IConsentStore ────────────────────────────────────────────────────────

    [Fact]
    public async Task ConsentStore_StoreAndFind_ReturnsConsent()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfConsentStore store = new(db);
            UserConsent consent = new()
            {
                SubjectId = "user1",
                ClientId = "client1",
                GrantedScopes = ["openid", "profile"],
                CreatedAt = DateTime.UtcNow,
            };

            await store.StoreAsync(consent);
            UserConsent? result = await store.FindAsync("user1", "client1");

            Assert.NotNull(result);
            Assert.Contains("openid", result.GrantedScopes);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task ConsentStore_Update_OverwritesExisting()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfConsentStore store = new(db);
            await store.StoreAsync(new UserConsent
            {
                SubjectId = "user2",
                ClientId = "client1",
                GrantedScopes = ["openid"],
                CreatedAt = DateTime.UtcNow,
            });
            await store.StoreAsync(new UserConsent
            {
                SubjectId = "user2",
                ClientId = "client1",
                GrantedScopes = ["openid", "email"],
                CreatedAt = DateTime.UtcNow,
            });

            UserConsent? result = await store.FindAsync("user2", "client1");
            Assert.NotNull(result);
            Assert.Equal(2, result.GrantedScopes.Count);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task ConsentStore_Remove_DeletesConsent()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfConsentStore store = new(db);
            await store.StoreAsync(new UserConsent
            {
                SubjectId = "user3",
                ClientId = "client1",
                GrantedScopes = ["openid"],
                CreatedAt = DateTime.UtcNow,
            });
            await store.RemoveAsync("user3", "client1");

            Assert.Null(await store.FindAsync("user3", "client1"));
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    // ── ISigningKeyStore ─────────────────────────────────────────────────────

    [Fact]
    public async Task SigningKeyStore_AddAndGetPrimary_ReturnsPrimaryKey()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfSigningKeyStore store = new(db);
            await store.AddAsync(BuildSigningKey("key-001", isPrimary: true));

            SigningKeyInfo? primary = await store.GetPrimaryKeyAsync();

            Assert.NotNull(primary);
            Assert.Equal("key-001", primary.KeyId);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task SigningKeyStore_SetPrimary_PromotesKey()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfSigningKeyStore store = new(db);
            await store.AddAsync(BuildSigningKey("key-a", isPrimary: true));
            await store.AddAsync(BuildSigningKey("key-b", isPrimary: false));

            await store.SetPrimaryAsync("key-b");
            SigningKeyInfo? primary = await store.GetPrimaryKeyAsync();

            Assert.NotNull(primary);
            Assert.Equal("key-b", primary.KeyId);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task SigningKeyStore_GetActiveKeys_ExcludesExpired()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfSigningKeyStore store = new(db);
            await store.AddAsync(BuildSigningKey("key-active", isPrimary: true));
            await store.AddAsync(BuildSigningKey("key-expired", isPrimary: false,
                removeAt: DateTime.UtcNow.AddSeconds(-1)));

            IReadOnlyList<SigningKeyInfo> keys = await store.GetActiveKeysAsync();

            Assert.Single(keys);
            Assert.Equal("key-active", keys[0].KeyId);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    [Fact]
    public async Task SigningKeyStore_RemoveExpired_DeletesOldKeys()
    {
        TestDbContext db = await TestDb.CreateAsync();
        try
        {
            EfSigningKeyStore store = new(db);
            await store.AddAsync(BuildSigningKey("key-keep", isPrimary: true));
            await store.AddAsync(BuildSigningKey("key-del", isPrimary: false,
                removeAt: DateTime.UtcNow.AddSeconds(-1)));

            await store.RemoveExpiredAsync();
            IReadOnlyList<SigningKeyInfo> keys = await store.GetActiveKeysAsync();

            Assert.Single(keys);
            Assert.Equal("key-keep", keys[0].KeyId);
        }
        finally { await TestDb.DestroyAsync(db); }
    }

    // ── Builders ─────────────────────────────────────────────────────────────

    private static AuthorizationCode BuildCode(
        string handle,
        string subjectId = "user1",
        string clientId = "client1",
        DateTime? expiresAt = null) =>
        new()
        {
            Code = handle,
            ClientId = clientId,
            SubjectId = subjectId,
            RedirectUri = "https://app.example.com/callback",
            CodeChallenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            GrantedScopes = ["openid"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt ?? DateTime.UtcNow.AddMinutes(5),
        };

    private static RefreshToken BuildRefreshToken(
        string handle,
        string subjectId = "user1",
        string clientId = "client1",
        int generation = 0) =>
        new()
        {
            Handle = handle,
            ClientId = clientId,
            SubjectId = subjectId,
            GrantedScopes = ["openid", "offline_access"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(30),
            Generation = generation,
        };

    private static IssuedToken BuildIssuedToken(
        string handle,
        string? refreshHandle = null,
        string? jkt = null) =>
        new()
        {
            Handle = handle,
            ClientId = "client1",
            SubjectId = "user1",
            GrantedScopes = ["openid"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            RefreshTokenHandle = refreshHandle,
            JktThumbprint = jkt,
        };

    private static ParEntry BuildParEntry(string requestUri, DateTime? expiresAt = null) =>
        new()
        {
            RequestUri = requestUri,
            ClientId = "client1",
            RedirectUri = "https://app.example.com/callback",
            Scope = "openid profile",
            CodeChallenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            CodeChallengeMethod = "S256",
            ResponseType = "code",
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt ?? DateTime.UtcNow.AddSeconds(90),
        };

    private static SigningKeyInfo BuildSigningKey(
        string keyId,
        bool isPrimary = false,
        DateTime? removeAt = null) =>
        new()
        {
            KeyId = keyId,
            Algorithm = "ES256",
            PrivateKeyPem = "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----",
            CreatedAt = DateTime.UtcNow,
            RetireAt = DateTime.UtcNow.AddDays(30),
            RemoveAt = removeAt ?? DateTime.UtcNow.AddDays(60),
            IsPrimary = isPrimary,
        };
}
