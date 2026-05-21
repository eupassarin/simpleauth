# SimpleAuth.Storage.EntityFramework

EF Core 10 store implementations for SimpleAuth — supports SQL Server, PostgreSQL, SQLite, and any relational database provider.

## Installation

```bash
dotnet add package SimpleAuth.Storage.EntityFramework
```

## Purpose

Provides durable, transactional persistence for all SimpleAuth token and state stores using Entity Framework Core. Authorization codes, refresh tokens, access tokens, PAR entries, JTI records, user consents, and signing keys are persisted in your relational database.

## Setup

### 1. Create your DbContext

```csharp
using SimpleAuth.EntityFramework;

public class AppDbContext : SimpleAuthDbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}
```

### 2. Register EF + SimpleAuth

```csharp
// Register your DbContext with the provider of your choice
builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseSqlite("Data Source=simpleauth.db"));

// Option A: All 9 stores via EF (clients, resources, keys, tokens, etc.)
builder.Services.AddSimpleAuthEntityFramework<AppDbContext>();

// Option B: Only transactional stores (tokens, PAR, JTI, consent)
//           Keep clients/resources/keys in-memory for simplicity
builder.Services.AddSimpleAuthEntityFrameworkTransactionalStores<AppDbContext>();
```

### 3. Create migrations

```bash
dotnet ef migrations add Initial --project YourApp --context AppDbContext
```

### 4. Apply migrations on startup

```csharp
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.MigrateAsync(); // extension from SimpleAuth.EntityFramework
}
```

## Extension methods

| Method | Registers |
|---|---|
| `AddSimpleAuthEntityFramework<TContext>()` | All 9 stores (client, resource, signing key + 6 transactional) |
| `AddSimpleAuthEntityFrameworkTransactionalStores<TContext>()` | 6 transactional stores only (auth codes, refresh tokens, access tokens, PAR, JTI, consent) |
| `MigrateAsync(this SimpleAuthDbContext)` | Applies pending EF migrations |

## Tables created

| Table | Purpose |
|---|---|
| `sa_clients` | Registered OAuth clients |
| `sa_scopes` | API scopes |
| `sa_identity_scopes` | OIDC identity scopes |
| `sa_resources` | Protected resources |
| `sa_authorization_codes` | Authorization codes (consumed atomically) |
| `sa_refresh_tokens` | Refresh tokens with generation tracking |
| `sa_issued_tokens` | Reference access token records |
| `sa_par_entries` | Pushed Authorization Request entries |
| `sa_signing_keys` | Signing key material with lifecycle |
| `sa_jti_records` | JTI replay prevention records |
| `sa_user_consents` | User consent grants |

## Transactional guarantees

- **Authorization code consume** — `IsolationLevel.Serializable` transaction ensures one-time-use
- **PAR consume** — atomic delete with serializable isolation
- **Refresh token rotation** — old token revoked + new token persisted in one transaction
- **JTI replay detection** — unique PK constraint; duplicate insert = replay

## Supported providers

Any EF Core relational provider works:

```csharp
// SQLite
options.UseSqlite("Data Source=auth.db");

// PostgreSQL
options.UseNpgsql("Host=localhost;Database=auth;...");

// SQL Server
options.UseSqlServer("Server=.;Database=Auth;...");
```

## ⚠️ AOT note

This package is **not AOT-compatible** — EF Core uses runtime reflection for change tracking, migrations, and entity materialization. Use it alongside the AOT-safe core package; the EF stores run in the same process but don't affect AOT of the rest of the application.

## Dependencies

| Dependency | Version |
|---|---|
| `Microsoft.EntityFrameworkCore` | 10.0.x |
| `Microsoft.EntityFrameworkCore.Relational` | 10.0.x |
| `Microsoft.Extensions.DependencyInjection.Abstractions` | 10.0.x |
| `SimpleAuth.Storage.Abstractions` | (project reference) |

## License

MIT
