# Contributing to SimpleAuth

Thank you for your interest in contributing! This document provides guidelines for contributing to SimpleAuth.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/SimpleAuth.git`
3. Create a branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `dotnet test`
6. Push and create a Pull Request

## Development Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Any IDE (VS Code, Rider, Visual Studio)

## Building

```bash
dotnet build
dotnet test
```

## Code Style

- The project uses `.editorconfig` for formatting — your IDE should pick it up automatically
- `TreatWarningsAsErrors` is enabled — all warnings must be resolved
- Use `EnforceCodeStyleInBuild` — formatting is checked at build time
- Prefer `stackalloc` and `Span<T>` over heap allocations in hot paths
- No reflection — the project targets Native AOT compatibility
- Use source-generated JSON serialization (`System.Text.Json` source generators)

## Pull Request Process

1. Ensure your changes build without errors or warnings
2. Add or update tests as appropriate
3. Update documentation if your changes affect public APIs
4. Keep PRs focused — one feature or fix per PR
5. Write clear commit messages following [Conventional Commits](https://www.conventionalcommits.org/)

## Commit Messages

We follow conventional commits:

```
feat: add support for claims parameter (OIDC §5.5)
fix: prevent prompt=login redirect loop
docs: update README with new endpoints
test: add integration tests for DPoP binding
chore: update CI to .NET 10 RC2
```

## Testing

- **Unit tests** — `tests/SimpleAuth.Unit.Tests/`
- **Integration tests** — `tests/SimpleAuth.Integration.Tests/`
- **Conformance tests** — `tests/SimpleAuth.Conformance.Tests/`
- **Security tests** — `tests/SimpleAuth.Security.Tests/`
- **EF tests** — `tests/SimpleAuth.EntityFramework.Tests/`

All tests must pass before merging.

## Security

If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md). Do NOT open a public issue for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
