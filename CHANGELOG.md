# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-22

### Added

- **OAuth 2.1 Authorization Code Flow** with mandatory PKCE (S256)
- **OpenID Connect Core 1.0** — ID tokens, UserInfo endpoint, discovery
- **Token Endpoint** — authorization_code, client_credentials, refresh_token grants
- **Discovery & JWKS** — `/.well-known/openid-configuration` and `/.well-known/jwks.json`
- **Pushed Authorization Requests (PAR)** — RFC 9126
- **DPoP** — RFC 9449 proof-of-possession tokens with JTI replay detection
- **Token Revocation & Introspection** — RFC 7009, RFC 7662
- **RFC 9207** — Authorization Server Issuer Identification in responses
- **Form Post Response Mode** — OAuth 2.0 Form Post for both success and error responses
- **OIDC `claims` Request Parameter** — §5.5 support for requesting specific claims
- **`prompt=login`** — Force re-authentication per OIDC §3.1.2.6
- **`prompt=none`** — Silent authentication check per OIDC §3.1.2.6
- **`max_age`** — Session max age enforcement per OIDC §3.1.2.1
- **`acr_values`** — Authentication context class reference support
- **Reference tokens** — Opaque tokens with server-side storage and introspection
- **JWT access tokens** — Self-contained tokens for stateless validation
- **Client authentication** — `client_secret_basic`, `client_secret_post`, `none` (public)
- **PBKDF2 secret hashing** — 310,000 iterations, SHA-512, constant-time comparison
- **Rate limiting** — Configurable per-endpoint rate limiter
- **Built-in login & consent UI** — Minimal pages for development/testing
- **Native AOT compatible** — No reflection, source-generated JSON, trim-safe
- **Storage providers** — In-memory (default) and Entity Framework Core (PostgreSQL/SQLite/etc.)
- **174 automated tests** — Unit, integration, conformance, security, and EF tests
- **OIDF Conformance Suite** — Passing basic certification profile tests
- **CI/CD** — GitHub Actions with build, test, CodeQL, and NuGet release

### Security

- Cookie `SecurePolicy.Always` — session cookies require HTTPS
- Strict `IsLocalUrl` validation — rejects backslash and control character attacks
- Consent page validates `client_id` against store — prevents UI spoofing
- Authorization code single-use with token revocation on reuse (RFC 6749 §4.1.2)
- PKCE required by default for all clients (OAuth 2.1 mandate)
- DPoP JTI replay protection with time-windowed cache
- Timing-safe secret comparison throughout

[0.1.0]: https://github.com/eupassarin/SimpleAuth/releases/tag/v0.1.0
