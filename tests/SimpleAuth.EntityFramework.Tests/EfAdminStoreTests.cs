using SimpleAuth.EntityFramework.Stores;

namespace SimpleAuth.EntityFramework.Tests;

public sealed class EfAdminClientStoreTests
{
    [Fact]
    public async Task AddAndRetrieveClient()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfAdminClientStore(db);

        var client = new Client
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            AllowedGrantTypes = [GrantType.AuthorizationCode],
            RedirectUris = ["https://example.com/cb"],
            AllowedScopes = ["openid"],
        };

        await store.AddAsync(client);

        var found = await store.FindByIdAsync("test-client");
        Assert.NotNull(found);
        Assert.Equal("test-client", found.ClientId);
        Assert.Equal("Test Client", found.ClientName);
        Assert.Contains("openid", found.AllowedScopes);

        await TestDb.DestroyAsync(db);
    }

    [Fact]
    public async Task GetAllReturnsAllClients()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfAdminClientStore(db);

        await store.AddAsync(new Client
        {
            ClientId = "c1",
            ClientName = "Client 1",
            AllowedGrantTypes = [GrantType.AuthorizationCode],
        });
        await store.AddAsync(new Client
        {
            ClientId = "c2",
            ClientName = "Client 2",
            AllowedGrantTypes = [GrantType.ClientCredentials],
        });

        var all = await store.GetAllAsync();
        Assert.Equal(2, all.Count);

        await TestDb.DestroyAsync(db);
    }

    [Fact]
    public async Task UpdateClient()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfAdminClientStore(db);

        await store.AddAsync(new Client
        {
            ClientId = "update-me",
            ClientName = "Original",
            AllowedGrantTypes = [GrantType.AuthorizationCode],
            AllowedScopes = ["openid"],
        });

        await store.UpdateAsync(new Client
        {
            ClientId = "update-me",
            ClientName = "Updated",
            AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            AllowedScopes = ["openid", "profile"],
        });

        var found = await store.FindByIdAsync("update-me");
        Assert.NotNull(found);
        Assert.Equal("Updated", found.ClientName);
        Assert.Contains("profile", found.AllowedScopes);

        await TestDb.DestroyAsync(db);
    }

    [Fact]
    public async Task DeleteClient()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfAdminClientStore(db);

        await store.AddAsync(new Client
        {
            ClientId = "delete-me",
            ClientName = "To Delete",
            AllowedGrantTypes = [GrantType.AuthorizationCode],
        });

        await store.DeleteAsync("delete-me");

        var found = await store.FindByIdAsync("delete-me");
        Assert.Null(found);

        await TestDb.DestroyAsync(db);
    }
}

public sealed class EfAdminResourceStoreTests
{
    [Fact]
    public async Task ManageScopes()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfAdminResourceStore(db);

        var scope = new Scope { Name = "api1", DisplayName = "API 1" };
        await store.AddScopeAsync(scope);

        var all = await store.GetAllScopesAsync();
        Assert.Single(all);
        Assert.Equal("api1", all[0].Name);

        await store.DeleteScopeAsync("api1");
        all = await store.GetAllScopesAsync();
        Assert.Empty(all);

        await TestDb.DestroyAsync(db);
    }

    [Fact]
    public async Task ManageIdentityScopes()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfAdminResourceStore(db);

        var scope = new IdentityScope
        {
            Name = "profile",
            DisplayName = "User Profile",
            ClaimTypes = ["name", "email"],
        };
        await store.AddIdentityScopeAsync(scope);

        var all = await store.GetAllIdentityScopesAsync();
        Assert.Single(all);
        Assert.Equal("profile", all[0].Name);
        Assert.Equal(2, all[0].ClaimTypes.Count);

        await TestDb.DestroyAsync(db);
    }

    [Fact]
    public async Task ManageResources()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfAdminResourceStore(db);

        var resource = new ProtectedResource
        {
            Name = "api",
            DisplayName = "My API",
            Scopes = ["api.read", "api.write"],
        };
        await store.AddResourceAsync(resource);

        var all = await store.GetAllResourcesAsync();
        Assert.Single(all);
        Assert.Equal("api", all[0].Name);
        Assert.Equal(2, all[0].Scopes.Count);

        await store.DeleteResourceAsync("api");
        all = await store.GetAllResourcesAsync();
        Assert.Empty(all);

        await TestDb.DestroyAsync(db);
    }
}

public sealed class EfServerSettingsStoreTests
{
    [Fact]
    public async Task SetAndGet()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfServerSettingsStore(db);

        await store.SetAsync("key1", "value1");
        var all = await store.GetAllAsync();
        Assert.Single(all);
        Assert.Equal("value1", all["key1"]);

        await TestDb.DestroyAsync(db);
    }

    [Fact]
    public async Task SetOverwritesExisting()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfServerSettingsStore(db);

        await store.SetAsync("key1", "original");
        await store.SetAsync("key1", "updated");

        var all = await store.GetAllAsync();
        Assert.Single(all);
        Assert.Equal("updated", all["key1"]);

        await TestDb.DestroyAsync(db);
    }

    [Fact]
    public async Task Delete()
    {
        await using var db = await TestDb.CreateAsync();
        var store = new EfServerSettingsStore(db);

        await store.SetAsync("key1", "value1");
        await store.DeleteAsync("key1");

        var all = await store.GetAllAsync();
        Assert.Empty(all);

        await TestDb.DestroyAsync(db);
    }
}
