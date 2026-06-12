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

## Guardrails (architectural fitness functions)

`internal/archtest/` holds build-failing invariant tests. They run in the
normal `go test ./...` path, so you may hit one before you expect a review
comment. Current guards:

- **`TestNoDynamicSQL`** — DB query/exec args must be a string literal or a
  named string constant. Build queries with sqlc or parameterized literals;
  never `fmt.Sprintf`/concatenate SQL.
- **`TestSecretComparesAreConstantTime`** — compare secrets/MACs/tokens/
  signatures/fingerprints with `subtle.ConstantTimeCompare`/`hmac.Equal`,
  never `==`/`bytes.Equal`.
- **`TestProjectionTablesWrittenOnlyByProjectors`** — request handlers append
  events; they must not write `*_projection` tables directly.
- **`TestNoUnabstractedTimeNow`** — no direct `time.Now()` calls in runtime
  code. Read the clock through an injected `now func() time.Time` seam
  (defaulting to `time.Now`) and call `t.now()`, so time-dependent logic is
  testable with a fixed clock.

Each guard ships a documented, no-stale-guarded allowlist for genuine
exceptions. **Prefer fixing the code over adding an allowlist entry**; an
entry is a reviewed decision needing a justification of *why the flagged shape
is safe here*. See [`docs/adr/0002-architectural-fitness-functions.md`](../docs/adr/0002-architectural-fitness-functions.md).

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
