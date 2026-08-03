# Power Manage server

This repository contains the control implementation being consolidated to the
workspace target in
`../DESIGN_2026_07_31/00_TARGET_DESIGN.md`. That file is the sole system
design authority.

## Implementation state

Control is one process that owns the public RPC API, direct agent mTLS
listener, identity and authorization, CRUD state, durable dispatch, SQLite FTS5
search, artifacts, and audit.

Gateway, Valkey, Asynq, event-store, projector, external-indexer, CRL
distribution, local-password/TOTP, and application-frame-signing code has been
removed. Architecture guards fail if any of it returns.

The datastore port has landed: control embeds SQLite in WAL mode with
`synchronous=FULL`, and search runs on FTS5. That port deliberately came after
the server was consolidated onto CRUD, a dedicated audit log, database-backed
jobs, and full-text search, so the engine swap did not change RPC or observable
search semantics. PostgreSQL is gone and must not return.

## Product boundaries

- The named protobuf RPCs remain the product contract except for the 14
  Gateway-only removals listed in the target.
- Agents initiate one direct outbound mTLS stream to control.
<!-- docref: begin src=internal/scim/users_write.go#Handler.provisionSubject:3b57e30f,internal/idp/linker.go#Linker.createUser:0b0b13c3,internal/identity/users.go#Handlers.EraseJITUser:6cc8f91a -->
- Human identity uses SCIM lifecycle management or optional per-provider OIDC
  JIT for homelabs. There is no manual user creation; JIT-created subjects have
  an explicit, provenance-gated erasure RPC. Bootstrap-admin is a one-time host
  authorization path.
<!-- docref: end -->
- Mutations and their audit operation/effect rows commit together.
- Device work is a durable database delivery plus an in-process wakeup and
  periodic database sweep.
- Search is SQLite FTS5 with an application-owned bounded fuzzy matcher.
- Classified agent/control fields use recipient-bound X25519 sealing.

## Repository layout

- `cmd/control/` — server executable
- `internal/controlrpc/`, `internal/searchrpc/` — explicit RPC handlers
- `internal/auth/` — authentication, authorization, and scope enforcement
- `internal/ca/`, `internal/mtls/` — device PKI and direct mTLS
- `internal/store/` — SQLite schema, queries, transactions, and the audited
  write primitive
- `internal/scim/`, `internal/idp/` — SCIM and OIDC
- `internal/connection/` — active direct-agent connections
- `internal/architecture/` — guards that fail if removed subsystems return
- `deploy/` — reference deployment

## Development

Build and test:

```bash
go build ./cmd/control
go test ./...
```

Regenerate sqlc output only through the pinned command:

```bash
make sqlc-generate
make sqlc-check
```

Do not edit generated files manually. Tests run against real SQLite database
files, one isolated file per test.

## Required verification

Changes at a trust boundary must cover malformed, unauthenticated,
unauthorized, cross-owner, replay, cancellation, and persistence-failure
paths. State changes must roll back when audit persistence fails. Secret values
must not reach logs, errors, traces, audit payloads, or diagnostics.

The final gate rejects runtime dependencies on Gateway, Valkey, Asynq,
event-store/projector state, external indexing, payload signing, CRL
distribution, and PostgreSQL.

## License

AGPL-3.0. See [LICENSE](LICENSE).
