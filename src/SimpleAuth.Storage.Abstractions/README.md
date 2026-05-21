# SimpleAuth.Storage.Abstractions

Store interfaces for SimpleAuth — **zero dependencies**, fully AOT-compatible.

## Installation

```bash
dotnet add package SimpleAuth.Storage.Abstractions
```

## Purpose

This package defines the storage contracts that the SimpleAuth authorization server uses. Implement these interfaces to plug in any persistence backend (Redis, MongoDB, DynamoDB, etc.).

## Interfaces

### Token stores

| Interface | Responsibility |
|---|---|
| `IAuthorizationCodeStore` | Store/consume authorization codes (atomic, one-time-use) |
| `IRefreshTokenStore` | Store/find/revoke/rotate refresh tokens |
| `ITokenStore` | Store/find/revoke issued access tokens (reference tokens) |
| `IParStore` | Store/consume PAR entries (atomic, one-time-use) |

### Configuration stores

| Interface | Responsibility |
|---|---|
| `IClientStore` | Read-only client lookup by `client_id` |
| `IResourceStore` | Read-only lookup of scopes, identity scopes, protected resources |

### Key & consent stores

| Interface | Responsibility |
|---|---|
| `ISigningKeyStore` | Signing key rotation — add, get primary, get active, remove expired |
| `IJtiStore` | JTI replay prevention — atomic consume with expiry |
| `IConsentStore` | User consent persistence — find, store, remove |

## Domain models

This package also defines the domain models:

- `Client` — registered OAuth client with credentials, grant types, scopes, URIs
- `AuthorizationCode` — issued code with PKCE challenge, scopes, redirect
- `RefreshToken` — rotating refresh token with generation tracking
- `IssuedToken` — reference access token record with optional DPoP JKT binding
- `ParEntry` — pushed authorization request parameters
- `SigningKeyInfo` — key material with lifecycle (retire/remove dates)
- `UserConsent` — granted scopes per subject/client pair
- `Scope`, `IdentityScope`, `ProtectedResource` — API and identity resources

## Implementing a custom store

```csharp
public class RedisAuthorizationCodeStore : IAuthorizationCodeStore
{
    public Task StoreAsync(AuthorizationCode code, CancellationToken ct = default)
    {
        // SET code:{handle} {json} EX {ttl}
    }

    public Task<AuthorizationCode?> ConsumeAsync(string codeHandle, CancellationToken ct = default)
    {
        // GETDEL code:{handle} — atomic consume
    }

    public Task RemoveAllAsync(string subjectId, string clientId, CancellationToken ct = default)
    {
        // Scan and delete by subject+client
    }
}
```

Register in DI after `AddSimpleAuth`:

```csharp
builder.Services.AddSingleton<IAuthorizationCodeStore, RedisAuthorizationCodeStore>();
```

The last registration wins — the server resolves stores via `IServiceProvider`.

## License

MIT
