# Contributing to the Power Manage server

## Build and test

```bash
go build ./cmd/control
go test ./...
```

Tests run against real SQLite database files, one isolated file per test —
there are no database mocks. The full gate is `scripts/verify.sh` (formatting,
vet, static analysis, the complete test suite, and docref).

## Generated code

Regenerate sqlc output only through the pinned commands:

```bash
make sqlc-generate
make sqlc-check
```

Never edit generated files by hand; CI verifies zero drift between the SQL
sources and the committed output.

## Verification expectations

Changes at a trust boundary must cover malformed, unauthenticated,
unauthorized, cross-owner, replay, cancellation, and persistence-failure
paths. State changes must roll back when audit persistence fails. Secret
values must not reach logs, errors, traces, audit payloads, or diagnostics.

Bug fixes require a regression test that fails on the buggy version. Scoped
non-owner access returns NotFound, never PermissionDenied. IDs are ULIDs.
Validation runs before authentication; authorization happens at the handler.

## Architecture guards

`internal/architecture/` contains tests that fail the build if removed
subsystems reappear as runtime dependencies: external databases, queues,
caches, event stores, projectors, external indexers, payload signing on the
direct agent stream, and CRL distribution. The server is one process with
embedded SQLite by design — treat those guards as the architecture contract,
not as obstacles.

## Documentation

Prose about code is anchored with [docref](deploy/QUICKSTART.md) claims;
`docref check` must pass, and hashes are generated with `docref claim`, never
typed by hand. Anchor new behavioral claims when you write them, not as a
cleanup pass.

## Repository layout

- `cmd/control/` — server executable
- `internal/controlrpc/`, `internal/searchrpc/` — explicit RPC handlers
- `internal/auth/` — authentication, authorization, and scope enforcement
- `internal/ca/`, `internal/mtls/` — device PKI and direct mTLS
- `internal/store/` — SQLite schema, queries, transactions, and the audited
  write primitive
- `internal/scim/`, `internal/idp/` — SCIM and OIDC
- `internal/connection/` — active direct-agent connections
- `internal/architecture/` — the architecture guards
- `deploy/` — reference deployment
