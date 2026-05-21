<p align="center">
  <h1 align="center">🔐 SimpleAuth</h1>
  <p align="center">
    <strong>OAuth 2.1 + OpenID Connect authorization server for .NET 10</strong>
  </p>
  <p align="center">
    Native AOT • Zero reflection • Minimal dependencies • Spec compliant • Security first
  </p>
</p>

<p align="center">
  <a href="https://github.com/eupassarin/SimpleAuth/actions/workflows/ci.yml"><img src="https://github.com/eupassarin/SimpleAuth/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/eupassarin/SimpleAuth/actions/workflows/codeql.yml"><img src="https://github.com/eupassarin/SimpleAuth/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://www.nuget.org/packages/SimpleAuth.Core"><img src="https://img.shields.io/nuget/v/SimpleAuth.Core.svg" alt="NuGet"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License"></a>
</p>

---

## O que é o SimpleAuth?

SimpleAuth é um servidor de autorização **OAuth 2.1 / OpenID Connect** completo e de código aberto, construído do zero para **.NET 10**. Projetado para ser a alternativa mais simples, segura e performática para quem precisa de autenticação e autorização no ecossistema .NET moderno.

```csharp
// Um servidor OAuth 2.1 + OIDC completo em 15 linhas:
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
            ClientName = "My App",
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

**Endpoints disponíveis automaticamente:**

| Endpoint | Path |
|---|---|
| Discovery (Metadata) | `/.well-known/openid-configuration` |
| JWKS (Public Keys) | `/.well-known/jwks.json` |
| Authorization | `/connect/authorize` |
| Token | `/connect/token` |
| UserInfo | `/connect/userinfo` |
| Revocation | `/connect/revocation` |
| Introspection | `/connect/introspect` |
| End Session (Logout) | `/connect/endsession` |
| Pushed Authorization Request | `/connect/par` |

---

## ✨ Por que SimpleAuth?

| | SimpleAuth | Outras soluções |
|---|---|---|
| **AOT nativo** | ✅ Primeiro objetivo de design — zero reflection, source-gen JSON | ❌ A maioria usa reflection pesado |
| **Dependências** | 1 pacote (`Microsoft.IdentityModel.JsonWebTokens`) | Dezenas de dependências |
| **Startup** | 2 chamadas: `AddSimpleAuth()` + `MapSimpleAuth()` | Configuração complexa com múltiplas classes |
| **Memória** | ~6K LOC, structs, stackalloc, pools | Centenas de milhares de linhas |
| **Segurança** | PKCE obrigatório, sem implicit/ROPC, DPoP, rate limiting | Features opcionais de segurança |
| **Spec compliance** | OAuth 2.1 (sem legado), RFCs modernos | Compatibilidade com specs antigas |

---

## 🏗️ Arquitetura

```
┌──────────────────────────────────────────────────────────────────────┐
│                  ASP.NET Core Minimal API Pipeline                    │
├──────────────────────────────────────────────────────────────────────┤
│                         SimpleAuth.Core                                │
│  ┌──────────────────┐  ┌────────────────┐  ┌──────────────────────┐  │
│  │    Endpoints      │  │     Crypto     │  │    Infrastructure    │  │
│  │                   │  │                │  │                      │  │
│  │  • /authorize     │  │  • JwtService  │  │  • Rate Limiter      │  │
│  │  • /token         │  │  • DPoP Valid. │  │  • CORS              │  │
│  │  • /par           │  │  • PKCE Valid. │  │  • Claims Enrichment │  │
│  │  • /revocation    │  │  • Key Mgmt    │  │  • Token Validation  │  │
│  │  • /introspect    │  │  • Secret Hash │  │  • Client Auth       │  │
│  │  • /userinfo      │  │  • Key Gen     │  │  • Scope Validation  │  │
│  │  • /endsession    │  │               │  │                      │  │
│  │  • /discovery     │  │               │  │                      │  │
│  │  • /jwks          │  │               │  │                      │  │
│  └──────────────────┘  └────────────────┘  └──────────────────────┘  │
├──────────────────────────────────────────────────────────────────────┤
│              SimpleAuth.Storage.Abstractions (interfaces)              │
│  IClientStore • IResourceStore • IAuthorizationCodeStore              │
│  IRefreshTokenStore • ITokenStore • IParStore • IJtiStore             │
│  ISigningKeyStore • IConsentStore                                     │
├──────────────────────────────────────────────────────────────────────┤
│            Implementação de Storage (escolha uma)                      │
│  ┌────────────────────────┐         ┌──────────────────────────────┐ │
│  │  InMemory              │         │  Entity Framework Core       │ │
│  │  • Thread-safe (locks) │         │  • SQL Server / PostgreSQL   │ │
│  │  • Zero config         │         │  • SQLite                    │ │
│  │  • Dev & testes         │         │  • Transações serializáveis  │ │
│  └────────────────────────┘         └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Pacotes NuGet

| Pacote | Descrição | Deps externas |
|---|---|---|
| **`SimpleAuth.Core`** | Servidor completo — endpoints, crypto, DI, rate limiting | `Microsoft.IdentityModel.JsonWebTokens` |
| **`SimpleAuth.Storage.Abstractions`** | Interfaces e modelos — AOT-safe | Nenhuma |
| **`SimpleAuth.Storage.InMemory`** | Stores em memória — dev/test | Nenhuma |
| **`SimpleAuth.Storage.EntityFramework`** | Stores EF Core 10 — produção | `Microsoft.EntityFrameworkCore` |

---

## 🔐 Especificações suportadas

### OAuth 2.1 & OpenID Connect

| Spec | RFC / Draft | Status | Detalhes |
|---|---|---|---|
| **OAuth 2.1** | draft-ietf-oauth-v2-1 | ✅ | Authorization Code + PKCE, Client Credentials, Refresh Token |
| **OpenID Connect Core 1.0** | — | ✅ | ID Tokens, UserInfo, End Session, Claims Enrichment |
| **PKCE** | RFC 7636 | ✅ | Obrigatório para todos os clients, apenas S256 |
| **Token Revocation** | RFC 7009 | ✅ | Silent 200 per spec, suporta access + refresh |
| **Token Introspection** | RFC 7662 | ✅ | Suporta JWT e reference tokens |
| **Pushed Authorization Requests** | RFC 9126 | ✅ | Single-use, atomic consume, configurable lifetime |
| **DPoP** | RFC 9449 | ✅ | Proof validation, JKT binding, ath verification, refresh binding |
| **Server Metadata** | RFC 8414 | ✅ | Discovery document completo |
| **JWK/JWA/JWT** | RFC 7517/7518/7519 | ✅ | EC (ES256/384/521) + RSA (RS256/384/PS256) |

### Segurança (além do mínimo exigido)

| Feature | Descrição |
|---|---|
| **PKCE obrigatório** | Todos os clients, sem exceção. `plain` permanentemente rejeitado |
| **Sem Implicit Grant** | Removido por design (OAuth 2.1 depreca) |
| **Sem ROPC** | Removido por design (OAuth 2.1 depreca) |
| **DPoP sender-constraint** | Tokens vinculados à chave do client |
| **Refresh token rotation** | One-time-use com detecção de replay por geração |
| **JTI replay protection** | DPoP proofs e client assertions verificados contra store |
| **Rate limiting por IP** | Token e authorize endpoints protegidos |
| **Constant-time comparisons** | PKCE, DPoP ath, secrets — `CryptographicOperations.FixedTimeEquals` |
| **Open redirect protection** | redirect_uri validado antes de qualquer redirect |
| **Post-logout redirect validation** | Verificado contra URIs registrados do client |
| **Credential expiration** | Secrets com data de expiração são rejeitados automaticamente |
| **Private key rejection** | DPoP proofs com material de chave privada são rejeitados |
| **Token ownership opacity** | Revocation retorna 200 mesmo para tokens de outros clients |
| **EC curve validation** | Apenas P-256, P-384, P-521 aceitas |

---

## ⚙️ Configuração completa

### Signing Keys

```csharp
server.Keys.UseDevelopmentKey();       // EC P-256 (dev only, nova a cada restart)
server.Keys.UseDevelopmentRsaKey();    // RSA-2048 (dev only)

// Produção: forneça sua própria chave
server.Keys.EcKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
server.Keys.Algorithm = "ES256";
server.Keys.KeyId = "my-production-key-2024";
```

### Client Configuration

```csharp
store.Clients.Add(new Client
{
    // Identidade
    ClientId = "webapp",
    ClientName = "Web Application",
    Enabled = true,

    // Grants permitidos
    AllowedGrantTypes = [GrantType.AuthorizationCode, GrantType.RefreshToken],

    // URIs registrados (match exato, sem wildcards)
    RedirectUris = ["https://app.example/callback"],
    PostLogoutRedirectUris = ["https://app.example/logged-out"],
    AllowedCorsOrigins = ["https://app.example"],

    // Autenticação
    RequireClientSecret = false,        // public client
    RequirePkce = true,                 // obrigatório
    TokenEndpointAuthMethod = AuthMethod.None,

    // Ou para confidential clients:
    // RequireClientSecret = true,
    // ClientCredentials = [new ClientCredential { Type = "SharedSecret", Value = SecretHasher.Hash("secret") }],
    // TokenEndpointAuthMethod = AuthMethod.ClientSecretBasic,

    // Scopes
    AllowedScopes = ["openid", "profile", "email", "offline_access", "api"],
    AllowOfflineAccess = true,

    // Token lifetimes
    AccessTokenLifetime = TimeSpan.FromHours(1),
    RefreshTokenLifetime = TimeSpan.FromDays(30),
    IdentityTokenLifetime = TimeSpan.FromMinutes(5),
    AuthorizationCodeLifetime = TimeSpan.FromMinutes(5),

    // Token behavior
    AccessTokenType = AccessTokenType.Jwt,           // ou Reference
    RefreshTokenUsage = TokenUsage.OneTimeOnly,       // rotação obrigatória
    RefreshTokenExpiration = TokenExpiration.Absolute, // ou Sliding

    // Claims estáticos
    Claims = [new ClientClaim { Type = "tenant", Value = "acme" }],
});
```

### Rate Limiting

```csharp
server.RateLimit.Enabled = true;              // default: true
server.RateLimit.TokenPermitLimit = 20;       // requests/min/IP no /connect/token
server.RateLimit.AuthorizePermitLimit = 30;   // requests/min/IP no /connect/authorize
server.RateLimit.TokenWindow = TimeSpan.FromMinutes(1);
server.RateLimit.AuthorizeWindow = TimeSpan.FromMinutes(1);
```

### PAR (Pushed Authorization Requests)

```csharp
server.Par.Enabled = true;    // default: true
server.Par.Required = false;  // true = rejeita requests diretos ao /authorize
```

### Discovery Document

```csharp
server.Discovery.IncludeAuthorizationEndpoint = true;    // default
server.Discovery.IncludeUserInfoEndpoint = true;         // default
server.Discovery.IncludeIntrospectionEndpoint = true;    // advertise no discovery
server.Discovery.IncludeRevocationEndpoint = true;       // advertise no discovery
```

### Claims Enrichment

```csharp
// Registre quantos IClaimsEnricher quiser — todos serão chamados em ordem:
builder.Services.AddSingleton<IClaimsEnricher, DatabaseClaimsEnricher>();
builder.Services.AddSingleton<IClaimsEnricher, LdapClaimsEnricher>();
```

```csharp
public class DatabaseClaimsEnricher : IClaimsEnricher
{
    public async ValueTask EnrichAsync(ClaimsEnrichmentContext context, CancellationToken ct)
    {
        // context.SubjectId — o usuário autenticado
        // context.ClientId — o client que está pedindo
        // context.GrantedScopes — scopes aprovados
        // context.Claims — adicione claims aqui

        if (context.GrantedScopes.Contains("profile"))
        {
            var user = await _db.Users.FindAsync(context.SubjectId, ct);
            context.Claims.Add(new Claim("name", user.Name));
            context.Claims.Add(new Claim("picture", user.AvatarUrl));
        }
    }
}
```

---

## 💾 Storage

### In-Memory (padrão)

Configuração zero. Thread-safe com locks. Ideal para:
- Desenvolvimento local
- Testes automatizados
- Single-instance deployments com estado efêmero

```csharp
server.Store.UseInMemory(store => { /* seed data */ });
```

### Entity Framework Core (produção)

Suporta SQL Server, PostgreSQL, SQLite, e qualquer provider EF Core 10.

```csharp
// 1. Configure o DbContext
builder.Services.AddDbContext<SimpleAuthDbContext>(o =>
    o.UseNpgsql(builder.Configuration.GetConnectionString("Auth")));

// 2. Registre todos os 9 stores EF:
builder.Services.AddSimpleAuthEntityFramework<SimpleAuthDbContext>();

// Ou mantenha clients/resources in-memory e persista apenas tokens:
builder.Services.AddSimpleAuthEntityFrameworkTransactionalStores<SimpleAuthDbContext>();
```

**Tabelas criadas:**
| Tabela | Conteúdo |
|---|---|
| `AuthorizationCodes` | Códigos de autorização (single-use, PKCE) |
| `RefreshTokens` | Refresh tokens com rotação e DPoP binding |
| `IssuedTokens` | Reference access tokens (revogáveis) |
| `ParEntries` | Pushed Authorization Requests |
| `SigningKeys` | Material criptográfico para rotação de chaves |
| `JtiRecords` | JTIs consumidos (replay protection) |
| `UserConsents` | Decisões de consentimento do usuário |
| `Scopes` | API scopes |
| `IdentityScopes` | Identity scopes (openid, profile, email) |
| `ProtectedResources` | APIs protegidas |

### Custom Storage

Implemente as interfaces em `SimpleAuth.Storage.Abstractions`:

```csharp
public interface IClientStore
{
    ValueTask<Client?> FindByClientIdAsync(string clientId, CancellationToken ct);
}

public interface IRefreshTokenStore
{
    Task StoreAsync(RefreshToken token, CancellationToken ct);
    Task<RefreshToken?> FindByHandleAsync(string handle, CancellationToken ct);
    Task ReplaceAsync(string oldHandle, RefreshToken newToken, CancellationToken ct);
    Task RevokeAsync(string handle, CancellationToken ct);
    Task RevokeAllAsync(string subjectId, string clientId, CancellationToken ct);
}

// + ITokenStore, IAuthorizationCodeStore, IParStore,
//   ISigningKeyStore, IJtiStore, IConsentStore, IResourceStore
```

Registre suas implementações no DI — last registration wins:
```csharp
builder.Services.AddSingleton<IClientStore, MyRedisClientStore>();
```

---

## 🧪 Testes

```bash
dotnet test
```

**165 testes** em 5 projetos:

| Projeto | Testes | O que testa |
|---|---|---|
| `SimpleAuth.Unit.Tests` | 7 | Crypto, PKCE, hashing, key generation |
| `SimpleAuth.Security.Tests` | 17 | Open redirect, DPoP, replay, refresh rotation, PAR |
| `SimpleAuth.Integration.Tests` | 18 | Pipeline HTTP completo, todos os endpoints |
| `SimpleAuth.EntityFramework.Tests` | 25 | Todos os stores EF (SQLite in-memory) |
| `SimpleAuth.Conformance.Tests` | 98 | OpenID Foundation Conformance Suite |

### Conformance Tests (baseados na OpenID Foundation)

| Módulo | Testes | Cobertura |
|---|---|---|
| Discovery | 17 | Metadata campos obrigatórios, JWKS, key privacy |
| ID Token | 13 | JWT structure, claims (iss/sub/aud/exp/iat), kid, nonce |
| Authorization Endpoint | 11 | PKCE enforcement, response_type, redirect_uri, code uniqueness |
| Token Endpoint | 14 | client_credentials, auth_code, error format, client auth methods |
| UserInfo | 8 | Bearer validation, sub match, scope-based claims, POST |
| Refresh Token | 8 | Rotation, replay detection, offline_access, client binding |
| Revocation & Introspection | 10 | RFC 7009 revocation, RFC 7662 introspection |
| DPoP & PAR | 12 | RFC 9449 proofs, RFC 9126 PAR one-time-use |

---

## 🚀 Exemplos

### Exemplo 1: Token client_credentials (M2M)

```bash
# Obter access token
curl -X POST https://auth.example/connect/token \
  -u "m2m-client:super-secret" \
  -d "grant_type=client_credentials&scope=api"
```

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api"
}
```

### Exemplo 2: Authorization Code + PKCE (SPA/Mobile)

```bash
# 1. Gerar PKCE
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-43)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | base64 | tr -d '=' | tr '+/' '-_')

# 2. Redirect o usuário para /authorize
open "https://auth.example/connect/authorize?\
response_type=code&\
client_id=webapp&\
redirect_uri=https://app.example/callback&\
scope=openid%20profile%20offline_access&\
code_challenge=$CODE_CHALLENGE&\
code_challenge_method=S256&\
state=random-state&\
nonce=random-nonce"

# 3. Trocar o code por tokens
curl -X POST https://auth.example/connect/token \
  -d "grant_type=authorization_code" \
  -d "client_id=webapp" \
  -d "code=AUTHORIZATION_CODE_RECEIVED" \
  -d "redirect_uri=https://app.example/callback" \
  -d "code_verifier=$CODE_VERIFIER"
```

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJFUzI1NiIs...",
  "refresh_token": "rt_a1b2c3d4e5f6...",
  "scope": "openid profile offline_access"
}
```

### Exemplo 3: Refresh Token

```bash
curl -X POST https://auth.example/connect/token \
  -d "grant_type=refresh_token" \
  -d "client_id=webapp" \
  -d "refresh_token=rt_a1b2c3d4e5f6..."
```

### Exemplo 4: PAR (Pushed Authorization Request)

```bash
# 1. Push the request
curl -X POST https://auth.example/connect/par \
  -u "webapp:secret" \
  -d "response_type=code" \
  -d "client_id=webapp" \
  -d "redirect_uri=https://app.example/callback" \
  -d "scope=openid" \
  -d "code_challenge=$CODE_CHALLENGE" \
  -d "code_challenge_method=S256"

# Response: { "request_uri": "urn:ietf:params:oauth:request-uri:abc123", "expires_in": 60 }

# 2. Redirect com request_uri (parâmetros já estão no server)
open "https://auth.example/connect/authorize?client_id=webapp&request_uri=urn:ietf:params:oauth:request-uri:abc123"
```

### Exemplo 5: Introspection

```bash
curl -X POST https://auth.example/connect/introspect \
  -u "resource-server:resource-secret" \
  -d "token=eyJhbGciOiJFUzI1NiIs..."
```

```json
{
  "active": true,
  "sub": "user123",
  "client_id": "webapp",
  "scope": "openid profile",
  "exp": 1716321600,
  "iat": 1716318000,
  "iss": "https://auth.example"
}
```

---

## 🏭 CI/CD

| Workflow | Trigger | O que faz |
|---|---|---|
| **ci.yml** | Push/PR → `main`/`dev` | Build → Test (165 tests) → AOT smoke publish |
| **release.yml** | Tag `v*.*.*` | Build → Test → Pack → Publish NuGet + GitHub Packages |
| **codeql.yml** | Push/PR + semanal | CodeQL security analysis |

### Publicar uma release

```bash
git tag v0.1.0
git push origin v0.1.0
# → Automaticamente: build, test, pack, publish no nuget.org
```

---

## 📂 Estrutura do projeto

```
simpleauth/                              ~6.900 LOC (src) + ~4.000 LOC (tests)
├── src/
│   ├── SimpleAuth.Core/                 # Servidor de autorização
│   │   ├── Endpoints/                   # 9 endpoints do protocolo
│   │   │   ├── DiscoveryEndpoint.cs     # Discovery + JWKS + Authorization
│   │   │   ├── TokenEndpoint.cs         # Token grants (code, credentials, refresh)
│   │   │   ├── ProtocolEndpoints.cs     # Revocation, Introspection, UserInfo, EndSession
│   │   │   └── PushedAuthorizationEndpoint.cs  # PAR (RFC 9126)
│   │   ├── Crypto/                      # Criptografia
│   │   │   ├── JwtService.cs            # Emissão de JWT (ID token + access token)
│   │   │   ├── DPopProofValidator.cs    # Validação DPoP (RFC 9449)
│   │   │   ├── PkceValidator.cs         # PKCE S256 (RFC 7636)
│   │   │   ├── SecretHasher.cs          # SHA-256 + constant-time verify
│   │   │   └── SigningKeyGenerator.cs   # Geração EC/RSA
│   │   ├── Configuration/              # API fluente de configuração
│   │   ├── Serialization/              # System.Text.Json source generators (AOT)
│   │   ├── SimpleAuthExtensions.cs     # AddSimpleAuth() + MapSimpleAuth()
│   │   └── SimpleAuthMiddleware.cs     # Routing + rate limiting
│   ├── SimpleAuth.Storage.Abstractions/ # Interfaces (zero deps)
│   │   ├── Client.cs                   # Modelo Client (30+ propriedades)
│   │   ├── Tokens.cs                   # AuthorizationCode, RefreshToken, IssuedToken, PAR
│   │   ├── ValueObjects.cs             # ClientCredential, ResourceCredential, ClientClaim
│   │   ├── Resources.cs               # Scope, IdentityScope, ProtectedResource
│   │   ├── Enums.cs                    # TokenUsage, TokenExpiration, AccessTokenType
│   │   └── I*Store.cs                  # 9 interfaces de store
│   ├── SimpleAuth.Storage.InMemory/    # ConcurrentDictionary + lock stores
│   └── SimpleAuth.Storage.EntityFramework/  # EF Core 10 stores
│       ├── Entities/                   # EF entities (mapeamento DB)
│       ├── Stores/                     # Implementações dos 9 stores
│       └── SimpleAuthDbContext.cs      # DbContext com OnModelCreating
├── tests/
│   ├── SimpleAuth.Unit.Tests/          # 7 testes de unidade
│   ├── SimpleAuth.Security.Tests/      # 17 testes de segurança
│   ├── SimpleAuth.Integration.Tests/   # 18 testes de integração (TestServer)
│   ├── SimpleAuth.EntityFramework.Tests/ # 25 testes EF (SQLite)
│   └── SimpleAuth.Conformance.Tests/   # 98 testes OIDC conformance
├── samples/
│   ├── SimpleAuth.Sample.Minimal/      # ~40 linhas, AOT-ready
│   └── SimpleAuth.Sample.Full/         # EF Core + SQLite + migrations
├── .github/workflows/                  # CI, Release, CodeQL
├── Directory.Build.props               # TreatWarningsAsErrors, AOT analyzers
├── global.json                         # .NET 10 SDK
└── SimpleAuth.slnx                     # Solution
```

---

## 🔧 Native AOT

SimpleAuth é **totalmente compatível com Native AOT**:

- ✅ `System.Text.Json` source generators (`[JsonSerializable]`) para todos os modelos
- ✅ Zero reflection em hot paths
- ✅ `IsAotCompatible = true` + `EnableTrimAnalyzer = true` nos projetos src/
- ✅ AOT smoke test no CI (publica o sample com `PublishAot = true`)
- ✅ Sem dynamic code generation
- ✅ `stackalloc` para hashes e base64url (zero heap allocation em crypto)

```bash
# Publicar como native AOT:
dotnet publish samples/SimpleAuth.Sample.Minimal -c Release -r linux-x64 --self-contained
# Resultado: binário único, ~15MB, startup < 50ms
```

---

## 🤝 Contribuindo

1. Fork o repositório
2. Crie uma branch a partir de `main`
3. Faça suas alterações — **todos os analyzers + formatting rodam como erros**
4. Execute `dotnet test` — **todos os 165 testes devem passar**
5. Submeta um PR

### Requisitos de código

- `.editorconfig` enforça: file-scoped namespaces, expression bodies, collection expressions
- `TreatWarningsAsErrors = true` — zero warnings permitidos
- `AnalysisMode = All` — todos os analyzers CA/IDE habilitados
- `EnforceCodeStyleInBuild = true` — formatting é build error

---

## 📊 Números

| Métrica | Valor |
|---|---|
| LOC (src) | ~6.900 |
| LOC (tests) | ~4.000 |
| Arquivos fonte | 35 |
| Testes | 165 |
| Dependências externas (Core) | 1 |
| Endpoints | 9 |
| RFCs implementadas | 9 |
| Pacotes NuGet | 4 |
| Build warnings | 0 |

---

## 📄 Licença

MIT — veja [LICENSE](LICENSE).
