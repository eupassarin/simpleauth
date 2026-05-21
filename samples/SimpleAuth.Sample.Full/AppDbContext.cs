using Microsoft.EntityFrameworkCore;
using SimpleAuth.EntityFramework;

namespace SimpleAuth.Sample.Full;

/// <summary>
/// Application DbContext — derives from <see cref="SimpleAuthDbContext"/> so that
/// all SimpleAuth tables are created alongside any application-specific tables.
/// </summary>
public sealed class AppDbContext : SimpleAuthDbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}
