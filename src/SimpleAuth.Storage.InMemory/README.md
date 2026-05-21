# SimpleAuth.Storage.InMemory

Thread-safe in-memory store implementations for SimpleAuth.

## Installation

```bash
dotnet add package SimpleAuth.Storage.InMemory
```

## Purpose

Provides `ConcurrentDictionary`-backed implementations of all SimpleAuth store interfaces. Suitable for:

- **Development** — zero-config, no database needed
- **Testing** — fast, deterministic, isolated
- **Single-instance deployments** — when state can be ephemeral (restarts lose data)

## What's included

| Store | Interface |
|---|---|
| `InMemoryClientStore` | `IClientStore` |
| `InMemoryResourceStore` | `IResourceStore` |
| `InMemoryAuthorizationCodeStore` | `IAuthorizationCodeStore` |
| `InMemoryRefreshTokenStore` | `IRefreshTokenStore` |
| `InMemoryTokenStore` | `ITokenStore` |
| `InMemoryParStore` | `IParStore` |
| `InMemorySigningKeyStore` | `ISigningKeyStore` |
| `InMemoryJtiStore` | `IJtiStore` |
| `InMemoryConsentStore` | `IConsentStore` |

## Usage

The in-memory stores are the default when using `AddSimpleAuth`:

```csharp
builder.Services.AddSimpleAuth(server =>
{
    server.Issuer = "https://localhost:5001";
    server.Keys.UseDevelopmentKey();

    server.Store.UseInMemory(store =>
    {
        store.Clients.Add(new Client { ... });
        store.Scopes.Add(new Scope { ... });
    });
});
```

All stores are registered as singletons and are thread-safe via `ConcurrentDictionary`.

## AOT compatibility

This package is fully Native AOT compatible — no reflection, no dynamic code generation.

## License

MIT
