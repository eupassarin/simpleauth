using Microsoft.EntityFrameworkCore;

namespace SimpleAuth.EntityFramework.Tests;

/// <summary>Test-only DbContext that derives from <see cref="SimpleAuthDbContext"/>.</summary>
public sealed class TestDbContext : SimpleAuthDbContext
{
    public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }
}

/// <summary>
/// Factory that creates isolated SQLite databases for each test.
/// Each call to <see cref="CreateAsync"/> returns a freshly-seeded context;
/// callers are responsible for disposal.
/// </summary>
public static class TestDb
{
    public static async Task<TestDbContext> CreateAsync()
    {
        DbContextOptions<TestDbContext> options = new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite($"Data Source=test_{Guid.NewGuid():N}.db")
            .Options;

        TestDbContext ctx = new(options);
        await ctx.Database.EnsureCreatedAsync();
        return ctx;
    }

    public static async Task DestroyAsync(TestDbContext ctx)
    {
        string? dbPath = ctx.Database.GetDbConnection().DataSource;
        await ctx.Database.EnsureDeletedAsync();
        await ctx.DisposeAsync();

        if (dbPath is not null && File.Exists(dbPath))
        {
            File.Delete(dbPath);
        }
    }
}
