# SimpleAuth Samples

Working examples demonstrating how to use SimpleAuth in different scenarios.

## Samples

### [`SimpleAuth.Sample.Minimal`](SimpleAuth.Sample.Minimal/)

**Minimal OAuth 2.1 + OIDC server in ~40 lines.**

- AOT-compatible
- In-memory stores only
- Machine-to-machine client (client_credentials)
- Browser client (authorization_code + PKCE)
- Custom `IClaimsEnricher` example
- Protected API endpoint

```bash
cd samples/SimpleAuth.Sample.Minimal
dotnet run
# Discovery: https://localhost:5001/.well-known/openid-configuration
```

### [`SimpleAuth.Sample.Full`](SimpleAuth.Sample.Full/)

**Production-style setup with EF Core + SQLite persistence.**

- SQLite database for token persistence
- In-memory clients and scopes (static config)
- EF transactional stores (auth codes, refresh tokens, PAR, JTI, consent)
- Auto-migrate on startup
- Custom claims enricher
- `IDesignTimeDbContextFactory` for `dotnet ef migrations`

```bash
cd samples/SimpleAuth.Sample.Full
dotnet run
# Discovery: https://localhost:5001/.well-known/openid-configuration
# Database: simpleauth.db (created automatically)
```

## Testing with curl

```bash
# Client credentials token request
curl -X POST https://localhost:5001/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=m2m-client&client_secret=super-secret&scope=api"

# Discovery document
curl https://localhost:5001/.well-known/openid-configuration | jq .

# JWKS
curl https://localhost:5001/.well-known/jwks.json | jq .
```

## Creating your own

1. Create a new ASP.NET Core project:
   ```bash
   dotnet new web -n MyAuthServer
   cd MyAuthServer
   ```

2. Add the SimpleAuth package:
   ```bash
   dotnet add package SimpleAuth.Core
   ```

3. Configure in `Program.cs` — see the minimal sample for the pattern.
