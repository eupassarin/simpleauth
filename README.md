# SimpleAuth

**OAuth 2.1 + OpenID Connect authorization server for .NET 10**

[![CI](https://github.com/eupassarin/SimpleAuth/actions/workflows/ci.yml/badge.svg)](https://github.com/eupassarin/SimpleAuth/actions/workflows/ci.yml)
[![CodeQL](https://github.com/eupassarin/SimpleAuth/actions/workflows/codeql.yml/badge.svg)](https://github.com/eupassarin/SimpleAuth/actions/workflows/codeql.yml)
[![NuGet](https://img.shields.io/nuget/v/SimpleAuth.Core.svg)](https://www.nuget.org/packages/SimpleAuth.Core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SimpleAuth is a lean, security-first OAuth 2.1 / OpenID Connect authorization server built for **Native AOT**, high performance, minimal memory footprint, and full spec compliance on .NET 10.

---

## ✨ Design principles

| Principle | How |
|---|---|
| **Native AOT first** | `System.Text.Json` source-generated serializers, zero runtime reflection in hot paths, trim-safe |
| **Minimal dependencies** | Core depends only on `Microsoft.IdentityModel.JsonWebTokens` — no MVC, no Razor, no EF |
| **Security by default** | PKCE mandatory, no implicit/ROPC grants, JTI replay protection, DPoP, open-redirect guard, rate limiting |
| **Spec compliant** | OAuth 2.1, OIDC Core, RFC 9126 (PAR), RFC 9449 (DPoP), RFC 7636 (PKCE), RFC 7009/7662 |
| **Simple startup** | One `AddSimpleAuth` call + one `MapSimpleAuth` call |
| **Extensible storage** | In-memory for dev, EF Core for production, or bring your own `IStore` implementation |

---

## 🚀 Quick start

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSimpleAuth(server =>
{
    server.Issuer = "https://auth.example.com";
    server.Keys.UseDevelopmentKey(); // EC P-256, dev only

    server.Store.UseInMemory(store =>
    {
        store.Clients.Add(new Client
        {
            ClientId = "myapp",
            ClientName = "My App",
            AllowedGrantTypes = [GrantType.AuthorizationCode],
            RedirectUris = ["https://myapp.example.com/callback"],
            AllowedScopes = ["openid", "profile"],
            RequirePkce = true,
        });
    });
});

var app = builder.Build();
app.MapSimpleAuth();
app.Run();
```

That's it. Discovery at `/.well-known/openid-configuration`, JWKS at `/.well-known/jwks.json`, token endpoint at `/connect/token`, authorize at `/connect/authorize`.

---

## 📦 Packages

| Package | Version | Description |
|---|---|---|
| [`SimpleAuth.Core`](src/SimpleAuth.Core) | ![NuGet](https://img.shields.io/nuget/v/SimpleAuth.Core.svg) | Authorization server — endpoints, JWT/JWK crypto, DI, rate limiting |
| [`SimpleAuth.Storage.Abstractions`](src/SimpleAuth.Storage.Abstractions) | ![NuGet](https://img.shields.io/nuget/v/SimpleAuth.Storage.Abstractions.svg) | Store interfaces — zero dependencies, AOT-safe |
| [`SimpleAuth.Storage.InMemory`](src/SimpleAuth.Storage.InMemory) | ![NuGet](https://img.shields.io/nuget/v/SimpleAuth.Storage.InMemory.svg) | In-memory stores for development and testing |
| [`SimpleAuth.Storage.EntityFramework`](src/SimpleAuth.Storage.EntityFramework) | ![NuGet](https://img.shields.io/nuget/v/SimpleAuth.Storage.EntityFramework.svg) | EF Core 10 stores — SQL Server, PostgreSQL, SQLite |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│  ASP.NET Core Minimal API pipeline                      │
├─────────────────────────────────────────────────────────┤
│  SimpleAuth.Core                                        │
│  ┌─────────────┐ ┌──────────┐ ┌─────────────────────┐  │
│  │ Endpoints   │ │ Crypto   │ │ Validation          │  │
│  │ • Token     │ │ • JWT    │ │ • PKCE              │  │
│  │ • Authorize │ │ • JWK    │ │ • Client auth       │  │
│  │ • PAR       │ │ • DPoP   │ │ • Redirect URI      │  │
│  │ • Revoke    │ │ • Keys   │ │ • Scope             │  │
│  │ • Introspect│ │          │ │                     │  │
│  │ • UserInfo  │ │          │ │                     │  │
│  │ • EndSession│ │          │ │                     │  │
│  │ • Discovery │ │          │ │                     │  │
│  └─────────────┘ └──────────┘ └─────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  SimpleAuth.Storage.Abstractions (interfaces)           │
│  IClientStore │ IResourceStore │ IAuthorizationCodeStore│
│  IRefreshTokenStore │ ITokenStore │ IParStore          │
│  ISigningKeyStore │ IJtiStore │ IConsentStore          │
├─────────────────────────────────────────────────────────┤
│  Storage Implementation (pick one)                      │
│  ┌──────────────┐         ┌────────────────────────┐   │
│  │  InMemory    │         │  EntityFramework       │   │
│  │  (dev/test)  │         │  (production)          │   │
│  └──────────────┘         └────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 🔐 Supported specifications

| Spec | Status |
|---|---|
| **OAuth 2.1** (draft-ietf-oauth-v2-1) | ✅ Authorization Code + PKCE, Client Credentials, Refresh Token |
| **OpenID Connect Core 1.0** | ✅ ID tokens, UserInfo, end-session |
| **RFC 8414** — Server Metadata | ✅ Discovery document |
| **RFC 7517 / 7518 / 7519** — JWK/JWA/JWT | ✅ EC (ES256/384) + RSA (RS256/384/PS256) |
| **RFC 7636** — PKCE | ✅ Mandatory for all clients (S256) |
| **RFC 7009** — Token Revocation | ✅ |
| **RFC 7662** — Token Introspection | ✅ |
| **RFC 9126** — Pushed Authorization Requests | ✅ PAR with atomic consume |
| **RFC 9449** — DPoP | ✅ Proof validation, JKT binding |

---

## ⚙️ Configuration

### Signing keys

```csharp
server.Keys.UseDevelopmentKey();       // EC P-256 (dev only, random per restart)
server.Keys.UseDevelopmentRsaKey();    // RSA-2048 (dev only)
// Production: provide your own ECDsa/RSA key via server.Keys.EcKey / server.Keys.RsaKey
```

### Rate limiting

```csharp
server.RateLimit.Enabled = true;           // default
server.RateLimit.TokenPermitLimit = 20;    // per IP, per minute
server.RateLimit.AuthorizePermitLimit = 30;
```

### PAR (Pushed Authorization Requests)

```csharp
server.Par.Enabled = true;     // default
server.Par.Required = false;   // set to true to reject non-PAR authorize requests
```

### Claims enrichment

```csharp
builder.Services.AddSingleton<IClaimsEnricher, MyClaimsEnricher>();
```

Implement `IClaimsEnricher` to inject custom claims into ID tokens and UserInfo responses.

---

## 💾 Storage

### In-memory (default)

Zero-config, thread-safe. Suitable for development, testing, and single-instance deployments with ephemeral state.

### Entity Framework Core

```csharp
builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlite("Data Source=auth.db"));

// Register all 9 EF stores:
builder.Services.AddSimpleAuthEntityFramework<AppDbContext>();

// Or keep clients/resources in-memory and persist only tokens:
builder.Services.AddSimpleAuthEntityFrameworkTransactionalStores<AppDbContext>();
```

See [`samples/SimpleAuth.Sample.Full`](samples/SimpleAuth.Sample.Full) for a complete EF + SQLite example with migrations.

### Custom stores

Implement the interfaces in `SimpleAuth.Storage.Abstractions` and register them in DI. The server resolves stores via `IServiceProvider` — last registration wins.

---

## 🧪 Testing

```bash
dotnet test
```

**67 tests** across 4 projects:
- `SimpleAuth.Unit.Tests` — 7 tests (crypto, PKCE, hashing)
- `SimpleAuth.Security.Tests` — 17 tests (security hardening, open-redirect, DPoP)
- `SimpleAuth.Integration.Tests` — 18 tests (full HTTP pipeline, all endpoints)
- `SimpleAuth.EntityFramework.Tests` — 25 tests (all EF store implementations)

---

## 🏭 CI/CD

| Workflow | Trigger | What it does |
|---|---|---|
| [`ci.yml`](.github/workflows/ci.yml) | Push/PR to `main`/`dev` | Build → Test → AOT smoke publish |
| [`release.yml`](.github/workflows/release.yml) | Version tags (`v*.*.*`) | Build → Test → Pack → Publish to NuGet + GitHub Packages |
| [`codeql.yml`](.github/workflows/codeql.yml) | Push/PR + weekly | CodeQL security + quality analysis |

### Publishing a release

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds, tests, packs, and publishes to nuget.org (requires `NUGET_API_KEY` secret).

---

## 📂 Project structure

```
simpleauth/
├── src/
│   ├── SimpleAuth.Core/                 # Authorization server
│   │   ├── Endpoints/                   # Token, Authorize, PAR, Revoke, Introspect, UserInfo
│   │   ├── Crypto/                      # JWT, JWK, DPoP, PKCE, key generation
│   │   ├── Configuration/               # Fluent config API
│   │   └── Serialization/               # System.Text.Json source generators
│   ├── SimpleAuth.Storage.Abstractions/ # Store interfaces (zero deps)
│   ├── SimpleAuth.Storage.InMemory/     # Thread-safe in-memory stores
│   └── SimpleAuth.Storage.EntityFramework/ # EF Core stores
├── tests/
│   ├── SimpleAuth.Unit.Tests/
│   ├── SimpleAuth.Security.Tests/
│   ├── SimpleAuth.Integration.Tests/
│   └── SimpleAuth.EntityFramework.Tests/
├── samples/
│   ├── SimpleAuth.Sample.Minimal/       # AOT-ready, ~40 lines
│   └── SimpleAuth.Sample.Full/          # EF Core + SQLite + migrations
├── .github/workflows/                   # CI, Release, CodeQL
├── Directory.Build.props                # Shared build settings
└── SimpleAuth.slnx                      # Solution file
```

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch from `main`
3. Make your changes — all analyzers + formatting run as errors
4. Run `dotnet test` — all 67 tests must pass
5. Submit a PR

The `.editorconfig` enforces file-scoped namespaces, expression bodies, collection expressions, and strict formatting.

---

## 📄 License

MIT — see [LICENSE](LICENSE).
