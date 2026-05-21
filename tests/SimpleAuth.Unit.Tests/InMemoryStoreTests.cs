using Xunit;

namespace SimpleAuth;

public sealed class InMemoryStoreTests
{
    [Fact]
    public async Task AuthorizationCodeStore_ConsumesCodeOnce()
    {
        var store = new InMemoryAuthorizationCodeStore();
        var code = new AuthorizationCode
        {
            Code = "code-1",
            ClientId = "client",
            SubjectId = "subject",
            RedirectUri = "https://app.example/callback",
            CodeChallenge = "challenge",
            GrantedScopes = ["openid"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
        };

        await store.StoreAsync(code);

        AuthorizationCode? first = await store.ConsumeAsync("code-1");
        AuthorizationCode? second = await store.ConsumeAsync("code-1");

        Assert.NotNull(first);
        Assert.Null(second);
        Assert.True(first!.IsConsumed);
    }

    [Fact]
    public async Task JtiStore_RejectsReplays()
    {
        var store = new InMemoryJtiStore();
        DateTime expiry = DateTime.UtcNow.AddMinutes(5);

        bool first = await store.TryConsumeAsync("jti-1", expiry);
        bool second = await store.TryConsumeAsync("jti-1", expiry);

        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public async Task TokenStore_RevokesTokens()
    {
        var store = new InMemoryTokenStore();
        var token = new IssuedToken
        {
            Handle = "token-1",
            ClientId = "client",
            SubjectId = "subject",
            GrantedScopes = ["openid"],
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
        };

        await store.StoreAsync(token);
        Assert.NotNull(await store.FindByHandleAsync("token-1"));

        await store.RevokeAsync("token-1");
        Assert.Null(await store.FindByHandleAsync("token-1"));
    }
}
