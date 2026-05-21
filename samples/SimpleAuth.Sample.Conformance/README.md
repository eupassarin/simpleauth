# SimpleAuth — OpenID Foundation Conformance Suite Deployment

Este sample configura o SimpleAuth especificamente para executar contra a
[OpenID Foundation Conformance Suite](https://www.certification.openid.net/).

## 🚀 Quick Start (Local)

```bash
cd samples/SimpleAuth.Sample.Conformance
dotnet run
# Server em https://localhost:5001
```

## 🐳 Deploy com Docker

```bash
# Build
docker build -t simpleauth-conformance -f samples/SimpleAuth.Sample.Conformance/Dockerfile .

# Run (ajuste SIMPLEAUTH_ISSUER para sua URL pública)
docker run -p 8080:8080 \
  -e SIMPLEAUTH_ISSUER=https://your-domain.com \
  -e SIMPLEAUTH_CONFORMANCE_BASE=https://www.certification.openid.net \
  simpleauth-conformance
```

## ☁️ Deploy em Cloud (opções)

### Railway
```bash
railway init
railway up
# Configure SIMPLEAUTH_ISSUER=https://<app>.up.railway.app
```

### Fly.io
```bash
fly launch --name simpleauth-conformance
fly secrets set SIMPLEAUTH_ISSUER=https://simpleauth-conformance.fly.dev
fly deploy
```

### Azure Container Apps
```bash
az containerapp up \
  --name simpleauth-conformance \
  --source . \
  --env-vars SIMPLEAUTH_ISSUER=https://simpleauth-conformance.<region>.azurecontainerapps.io
```

## 📋 Como Executar os Testes de Conformidade

### Passo 1: Deploy público

O servidor precisa ser acessível pela internet (a conformance suite em
`certification.openid.net` faz requests HTTP ao seu servidor).

### Passo 2: Criar Test Plan

1. Acesse [certification.openid.net](https://www.certification.openid.net/)
2. Login com Google ou GitLab
3. Clique **"Create a new test plan"**
4. Selecione o perfil:

| Perfil | Descrição |
|--------|-----------|
| **oidcc-basic-certification-test-plan** | Basic OP (Authorization Code) |
| **oidcc-config-certification-test-plan** | Config OP (Discovery) |
| **oidcc-formpost-basic-certification-test-plan** | Form Post Basic OP |

### Passo 3: Configurar o Plan

Preencha o formulário com:

```yaml
Server metadata URL:     https://your-domain.com/.well-known/openid-configuration
Client ID:               simpleauth-basic
Client Secret:           conformance-secret-basic
Second Client ID:        simpleauth-second
Second Client Secret:    conformance-secret-second
```

Para testes com `client_secret_post`:
```yaml
Client ID:               simpleauth-post
Client Secret:           conformance-secret-post
```

### Passo 4: Executar Testes

1. Clique **"Run All"** no test plan
2. Quando o teste solicitar login do usuário:
   - O browser será redirecionado para `/account/login`
   - Digite `test-user` como username
   - Clique "Sign In"
3. O teste continuará automaticamente

### Passo 5: Verificar Resultados

Todos os testes devem mostrar ✅ **PASSED**.

## 🔑 Clientes Pré-registrados

| Client ID | Secret | Auth Method | Uso |
|-----------|--------|-------------|-----|
| `simpleauth-basic` | `conformance-secret-basic` | client_secret_basic | Testes Basic OP |
| `simpleauth-post` | `conformance-secret-post` | client_secret_post | Testes com POST auth |
| `simpleauth-public` | — | none | Testes com public client |
| `simpleauth-second` | `conformance-secret-second` | client_secret_basic | Segundo client (multi-client tests) |

## 👤 Test User

| Campo | Valor |
|-------|-------|
| Subject (sub) | `test-user` |
| Name | `Test User` |
| Email | `test@simpleauth.dev` |
| Phone | `+1-555-0100` |
| Address | `123 Test St, Testville, TS 12345, BR` |

## 🎯 Perfis de Certificação Suportados

| Perfil | Status |
|--------|--------|
| **Basic OP** (Authorization Code + PKCE) | ✅ Pronto |
| **Config OP** (Discovery metadata) | ✅ Pronto |
| **Form Post OP** (response_mode=form_post) | ✅ Pronto |
| Dynamic OP (client registration) | ❌ Não suportado |
| Implicit OP | ❌ N/A (OAuth 2.1 não suporta implicit) |
| Hybrid OP | ❌ N/A (OAuth 2.1 não suporta hybrid) |

## ⚙️ Variáveis de Ambiente

| Variável | Descrição | Default |
|----------|-----------|---------|
| `SIMPLEAUTH_ISSUER` | Issuer URL (deve ser a URL pública) | `https://localhost:5001` |
| `SIMPLEAUTH_TEST_USER_SUB` | Subject do test user | `test-user` |
| `SIMPLEAUTH_TEST_USER_NAME` | Nome do test user | `Test User` |
| `SIMPLEAUTH_TEST_USER_EMAIL` | Email do test user | `test@simpleauth.dev` |
| `SIMPLEAUTH_CONFORMANCE_BASE` | Base URL da conformance suite | `https://www.certification.openid.net` |

## 🔒 Redirect URIs registrados

Os clientes aceitam redirect URIs no formato:
```
{CONFORMANCE_BASE}/test/a/{plan-alias}/callback
{CONFORMANCE_BASE}/test/a/{plan-alias}/post_logout_redirect
```

Se a conformance suite usar um alias diferente de `simpleauth`, `simpleauth-basic`,
`simpleauth-post`, `simpleauth-public`, ou `simpleauth-second`, você pode:

1. Adicionar o redirect URI ao appsettings.json, ou
2. Criar um novo client programmaticamente ajustando os RedirectUris

## 📝 Notas sobre Certificação

- **Custo**: $700/deployment (membro OIDF) ou $3,500 (não-membro). Projetos open-source podem ter certificação gratuita.
- **Membros OIDF**: Podem certificar para múltiplos perfis com uma única taxa.
- **Certificações não expiram** — a data da certificação é registrada.
- **Open Source Policy**: Verifique [openid.net/certification/open-source-project-certification-policy/](https://openid.net/certification/open-source-project-certification-policy/)
