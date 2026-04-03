# Contributing to Power Manage Server

## Prerequisites

- Go 1.25+
- PostgreSQL (or Podman for testcontainers)
- [sqlc](https://sqlc.dev/) for query generation

## Getting Started

This repo is part of a Go workspace. Clone all four repos (`sdk`, `server`, `agent`, `web`) into the same parent directory.

```bash
# Build
go build ./cmd/control
go build ./cmd/gateway

# Run tests
go test ./...

# Regenerate sqlc queries (after editing internal/store/queries/*.sql)
cd internal/store && sqlc generate
```

Database migrations live in `internal/store/migrations/` (Goose, embedded). See `CLAUDE.md` for the full build command reference.

## Workflow

1. Create a branch from `main`.
2. Make your changes with conventional commit messages:
   - `feat:` new feature
   - `fix:` bug fix
   - `chore:` maintenance
   - `docs:` documentation
   - `refactor:` code restructuring
   - `perf:` performance improvement
   - `test:` test additions/changes
3. Open a pull request. CodeRabbit reviews automatically.
4. Ensure CI passes before requesting review.

## Code Style

- Follow existing patterns in the codebase.
- Always handle errors -- never silently ignore them.
- Wrap PL/pgSQL functions in `-- +goose StatementBegin` / `-- +goose StatementEnd` in migrations.

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
