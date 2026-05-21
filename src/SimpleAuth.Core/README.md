# SimpleAuth.Core

The core authorization server package — endpoints, JWT/JWK crypto, configuration, validation, and DI registration.

## Installation

```bash
dotnet add package SimpleAuth.Core
```

## What's included

- **Token endpoint** (`POST /connect/token`) — authorization_code, client_credentials, refresh_token grants
- **Authorize endpoint** (`GET /connect/authorize`) — with mandatory PKCE (S256)
- **PAR endpoint** (`POST /connect/par`) — Pushed Authorization Requests (RFC 9126)
- **Revocation endpoint** (`POST /connect/revocation`) — RFC 7009
- **Introspection endpoint** (`POST /connect/introspect`) — RFC 7662
- **UserInfo endpoint** (`GET /connect/userinfo`) — OIDC Core
- **End-session endpoint** (`GET /connect/endsession`) — OIDC session management
- **Discovery** (`GET /.well-known/openid-configuration`) — RFC 8414
- **JWKS** (`GET /.well-known/jwks.json`) — RFC 7517

## Usage

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
            ClientId = "my-app",
            AllowedGrantTypes = [GrantType.AuthorizationCode],
            RedirectUris = ["https://app.example.com/callback"],
            AllowedScopes = ["openid", "profile"],
            RequirePkce = true,
        });
    });

    // Optional: PAR configuration
    server.Par.Enabled = true;
    server.Par.Required = false;

    // Optional: Rate limiting
    server.RateLimit.Enabled = true;
    server.RateLimit.TokenPermitLimit = 20;
});

var app = builder.Build();
app.MapSimpleAuth();
app.Run();
```

## Native AOT

This package is **fully AOT-compatible**. All JSON serialization uses `System.Text.Json` source generators. No runtime reflection in hot paths.

```bash
dotnet publish -c Release -r linux-x64 --self-contained -p:PublishAot=true
```

## Dependencies

| Dependency | Why |
|---|---|
| `Microsoft.IdentityModel.JsonWebTokens` | JWT creation and validation (no reinventing the wheel for token handling) |
| `SimpleAuth.Storage.Abstractions` | Store interfaces |
| `SimpleAuth.Storage.InMemory` | Default in-memory stores |

## Security features

- PKCE mandatory for all authorization code flows (S256 only)
- No implicit grant, no ROPC grant
- DPoP proof validation (RFC 9449) — proof-of-possession tokens
- JTI replay protection for `private_key_jwt` assertions
- Open-redirect protection on redirect_uri validation
- Per-IP rate limiting on token and authorize endpoints
- Configurable signing key rotation

## Claims enrichment

Implement `IClaimsEnricher` to inject custom identity claims:

```csharp
public class MyClaimsEnricher : IClaimsEnricher
{
    public async ValueTask EnrichAsync(ClaimsEnrichmentContext context, CancellationToken ct)
    {
        // Fetch claims from your database, LDAP, etc.
        context.Claims.Add(new Claim("role", "admin"));
    }
}

builder.Services.AddSingleton<IClaimsEnricher, MyClaimsEnricher>();
```

## License

MIT
