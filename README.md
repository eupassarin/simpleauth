<h1 align="center">🔐 SimpleAuth</h1>

<p align="center">
  <strong>OAuth 2.1 + OpenID Connect authorization server for .NET 10</strong><br/>
  Secure, fast, AOT-native, spec-compliant. Start a server in 15 lines of code.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-10-512BD4?style=flat-square&logo=dotnet" alt=".NET 10" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License" />
  <img src="https://img.shields.io/badge/AOT-Compatible-blueviolet?style=flat-square" alt="Native AOT" />
  <img src="https://img.shields.io/badge/Tests-174-brightgreen?style=flat-square" alt="174 tests" />
  <img src="https://img.shields.io/badge/OIDF%20Conformance-Passing-blue?style=flat-square" alt="OIDF Conformance" />
</p>

---

## What is SimpleAuth?

SimpleAuth is a complete **OAuth 2.1 / OpenID Connect** authorization server built from scratch for .NET 10. Designed as the simplest, most secure, and most performant option for authentication and authorization in the modern .NET ecosystem.

All cryptography is handled by `System.Security.Cryptography` and `Microsoft.IdentityModel.JsonWebTokens` — **no third-party crypto libraries**. The entire server is Native AOT compatible with zero reflection and source-generated JSON serialization.

---

## Quick Start

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSimpleAuth(server =>
{
    server.Issuer = "https://auth.example.com";
    server.Keys.UseDevelopmentKey();
    server.Store.UseInMemory(store =>
    {
        store.Clients.Add(new Client
        {
            ClientId = "myapp",
            AllowedGrantTypes = [GrantType.AuthorizationCode],
            RedirectUris = ["https://myapp.example/callback"],
            AllowedScopes = ["openid", "profile"],
        });
    });
});

var app = builder.Build();
app.MapSimpleAuth();
app.Run();
```

That's it. You now have a fully functional OAuth 2.1 + OpenID Connect server with PKCE, discovery, JWKS, token revocation, introspection, and more.

---

## Installation

```bash
# Core server (most common)
dotnet add package SimpleAuth.Core

# Entity Framework persistence (production)
dotnet add package SimpleAuth.Storage.EntityFramework
```

### Package Map

```
SimpleAuth.Core                     OAuth 2.1 + OIDC server (endpoints, crypto, DI)
├── SimpleAuth.Storage.Abstractions Interfaces & models (zero dependencies)
├── SimpleAuth.Storage.InMemory     In-memory stores (dev/test, included in Core)
│
SimpleAuth.Storage.EntityFramework  EF Core 10 persistence (PostgreSQL, SQLite, SQL Server)
```

---

## Features

### Endpoints (all automatic via `MapSimpleAuth()`)

| Endpoint | Path | Spec |
|---|---|---|
| Discovery | `/.well-known/openid-configuration` | RFC 8414 |
| JWKS | `/.well-known/jwks.json` | RFC 7517 |
| Authorization | `/connect/authorize` | OAuth 2.1 §4.1 |
| Token | `/connect/token` | OAuth 2.1 §4.1.3 |
| UserInfo | `/connect/userinfo` | OIDC Core §5.3 |
| Revocation | `/connect/revocation` | RFC 7009 |
| Introspection | `/connect/introspect` | RFC 7662 |
| End Session | `/connect/endsession` | OIDC RP-Initiated Logout |
| PAR | `/connect/par` | RFC 9126 |

### Supported Grants

| Grant | Description |
|---|---|
| Authorization Code + PKCE | OAuth 2.1 mandatory flow (S256 only) |
| Client Credentials | Machine-to-machine tokens |
| Refresh Token | Rotation with replay detection |

### OpenID Connect

| Feature | Description |
|---|---|
| ID Tokens | Signed JWTs with standard claims |
| UserInfo | Claims enrichment via `IClaimsEnricher` |
| Discovery | Full metadata document |
| `prompt=login` | Force re-authentication |
| `prompt=none` | Silent authentication check |
| `max_age` | Session freshness enforcement |
| `acr_values` | Authentication context reference |
| `claims` parameter | OIDC §5.5 — request specific claims |
| `response_mode=form_post` | Success and error responses via POST |
| End Session / Logout | RP-initiated with post-logout redirect |

### Security (beyond minimum requirements)

| Feature | Description |
|---|---|
| **PKCE required** | All clients, no exceptions. `plain` permanently rejected |
| **No Implicit Grant** | Removed by design (OAuth 2.1) |
| **No ROPC** | Removed by design (OAuth 2.1) |
| **DPoP** (RFC 9449) | Sender-constrained tokens with JKT binding |
| **Refresh token rotation** | One-time-use with generation-based replay detection |
| **JTI replay protection** | DPoP proofs verified against time-windowed store |
| **Rate limiting** | Per-IP on token and authorize endpoints |
| **Constant-time comparison** | All secrets, PKCE, DPoP ath — `FixedTimeEquals` |
| **PBKDF2 secret hashing** | 310K iterations, SHA-512 |
| **Authorization code reuse** | Revokes all tokens on replay (RFC 6749 §4.1.2) |
| **Issuer identification** | RFC 9207 `iss` in all redirect responses |
| **Cookie security** | `Secure=Always`, `HttpOnly`, `SameSite=Lax` |
| **Redirect URI validation** | Exact match, no wildcards |

---

## Configuration

### Signing Keys

```csharp
// Development (auto-generated, rotates on restart)
server.Keys.UseDevelopmentKey();        // EC P-256 (ES256)
server.Keys.UseDevelopmentRsaKey();     // RSA-2048 (RS256)

// Production (provide your own)
server.Keys.EcKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
server.Keys.Algorithm = "ES256";
server.Keys.KeyId = "prod-key-2026";
```

### Client Registration

```csharp
store.Clients.Add(new Client
{
    ClientId = "webapp",
    ClientName = "Web Application",
    AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],
    RedirectUris = ["https://app.example/callback"],
    PostLogoutRedirectUris = ["https://app.example/logged-out"],
    AllowedScopes = ["openid", "profile", "email", "api"],
    RequireClientSecret = false,     // public client (SPA/mobile)
    RequirePkce = true,              // always true for OAuth 2.1
    AccessTokenLifetime = TimeSpan.FromMinutes(15),
    RefreshTokenLifetime = TimeSpan.FromDays(30),
});
```

### Entity Framework (Production)

```csharp
builder.Services.AddSimpleAuth(server => { /* ... */ });
builder.Services.AddSimpleAuthEntityFramework(options =>
    options.UseNpgsql(connectionString));  // or UseSqlite, UseSqlServer
```

### Admin GUI (Blazor)

```csharp
builder.Services.AddSimpleAuth(server => { /* ... */ });
builder.Services.AddSimpleAuthEntityFramework(options =>
    options.UseNpgsql(connectionString));

builder.Services.AddSimpleAuthGui(gui =>
{
    gui.AdminUsername = "admin";
    gui.SetPassword("my-secure-password");
});

var app = builder.Build();
app.MapSimpleAuth();
app.MapSimpleAuthGui();
app.Run();
// Navigate to /admin to manage clients, scopes, tokens, keys, and settings.
```

> **Requires EF Core** — the admin GUI persists all changes to the database.
> In-memory stores do not support the admin panel.

### Claims Enrichment

```csharp
builder.Services.AddSingleton<IClaimsEnricher, MyClaimsEnricher>();

public class MyClaimsEnricher : IClaimsEnricher
{
    public ValueTask EnrichAsync(ClaimsEnrichmentContext context, CancellationToken ct)
    {
        if (context.GrantedScopes.Contains("profile"))
        {
            context.Claims.Add(new Claim("name", "Jane Doe"));
        }
        return ValueTask.CompletedTask;
    }
}
```

---

## Extension Points

| Extension | Interface / Pattern |
|---|---|
| Client storage | `IClientStore` |
| Token storage | `IAuthorizationCodeStore`, `ITokenStore`, `IRefreshTokenStore` |
| Key management | `ISigningKeyStore` |
| Claims enrichment | `IClaimsEnricher` |
| Resource/scope definitions | `IResourceStore` |
| User consent | `IConsentStore` |
| DPoP replay detection | `IJtiStore` |
| PAR storage | `IParStore` |
| Admin GUI | `AddSimpleAuthGui()` + `MapSimpleAuthGui()` |
| Login/consent UI | `InteractionConfiguration` (custom paths) |

All interfaces are in `SimpleAuth.Storage.Abstractions` — implement your own for any backend.

---

## Specs & RFCs

| Specification | Status |
|---|---|
| OAuth 2.1 (draft-ietf-oauth-v2-1) | ✅ Full |
| OpenID Connect Core 1.0 | ✅ Full |
| PKCE (RFC 7636) | ✅ Required |
| DPoP (RFC 9449) | ✅ Full |
| PAR (RFC 9126) | ✅ Full |
| Token Revocation (RFC 7009) | ✅ Full |
| Token Introspection (RFC 7662) | ✅ Full |
| Server Metadata (RFC 8414) | ✅ Full |
| Issuer Identification (RFC 9207) | ✅ Full |
| JWT Access Tokens (RFC 9068) | ✅ Full |
| Form Post Response Mode | ✅ Full |

---

## Documentation

| Document | Description |
|---|---|
| [Changelog](CHANGELOG.md) | Release history |
| [Contributing](CONTRIBUTING.md) | How to contribute |
| [Security](SECURITY.md) | Vulnerability reporting |
| [Conformance](samples/SimpleAuth.Sample.Conformance/README.md) | OIDF Conformance Suite deployment |
| [Samples](samples/README.md) | Example servers (minimal, interactive, EF, conformance) |

---

## Requirements

- **.NET 10** (single target: `net10.0`)
- No native or COM dependencies
- **No third-party cryptography** — all crypto via BCL + `Microsoft.IdentityModel`
- Native AOT publish supported (`dotnet publish -c Release`)
- Runs on Windows, macOS, and Linux (x64 and ARM64)

---

## License

[MIT](LICENSE) — use it anywhere, for anything, forever.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

---

## Sponsoring

If SimpleAuth is useful to you or your organisation, consider [sponsoring the project on GitHub](https://github.com/sponsors/eupassarin). Your support helps keep the library maintained, secure, and free for everyone.

---

<p align="center">
  <em>Built for developers who believe authorization servers should be simple.</em>
</p>
