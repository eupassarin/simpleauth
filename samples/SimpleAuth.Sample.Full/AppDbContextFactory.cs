using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SimpleAuth.Sample.Full;

/// <summary>
/// Allows the EF Core tooling (<c>dotnet ef migrations add</c>) to instantiate
/// <see cref="AppDbContext"/> at design time without running the application.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:AvoidUninstantiatedInternalClasses", Justification = "Instantiated by EF Core design-time tooling via reflection.")]
internal sealed class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        DbContextOptionsBuilder<AppDbContext> optionsBuilder = new();
        optionsBuilder.UseSqlite("Data Source=simpleauth.db");
        return new AppDbContext(optionsBuilder.Options);
    }
}
