# Power Manage server

This repository contains the control implementation being consolidated to the
workspace target in
`../DESIGN_2026_07_31/00_TARGET_DESIGN.md`. That file is the sole system
design authority.

## Consolidation state

The target control is one process that owns the public RPC API, direct agent
mTLS listener, identity and authorization, CRUD state, durable dispatch,
PostgreSQL full-text search, artifacts, and audit.

Legacy Gateway, Valkey, Asynq, event-store, projector, external-indexer, CRL
distribution, local-password/TOTP, and application-frame-signing code is
migration input scheduled for removal. Do not extend it.

PostgreSQL remains intentionally during consolidation. The final datastore
phase ports the stable CRUD/search implementation to SQLite and FTS5.

## Product boundaries

- The named protobuf RPCs remain the product contract except for the 14
  Gateway-only removals listed in the target.
- Agents initiate one direct outbound mTLS stream to control.
- Human identity is OIDC plus SCIM; bootstrap-admin is a one-time host
  authorization path.
- Mutations and their audit operation/effect rows commit together.
- Device work is a durable database delivery plus an in-process wakeup and
  periodic database sweep.
- Search is PostgreSQL FTS during consolidation.
- Classified agent/control fields use recipient-bound X25519 sealing.

## Repository layout

- `cmd/control/` — target server executable
- `internal/api/` — explicit RPC handlers
- `internal/auth/` — authentication, authorization, and scope enforcement
- `internal/ca/`, `internal/mtls/` — device PKI and direct mTLS
- `internal/store/` — PostgreSQL schema, queries, transactions, and
  consolidation work
- `internal/scim/`, `internal/idp/` — SCIM and OIDC
- `internal/connection/` — active direct-agent connections
- `deploy/` — reference deployment

Directories for retiring subsystems may still exist while the cleanup branch
is in progress. Their presence does not make them part of the target.

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

Do not edit generated files manually. Integration tests use real PostgreSQL
through testcontainers during consolidation.

## Required verification

Changes at a trust boundary must cover malformed, unauthenticated,
unauthorized, cross-owner, replay, cancellation, and persistence-failure
paths. State changes must roll back when audit persistence fails. Secret values
must not reach logs, errors, traces, audit payloads, or diagnostics.

The final consolidation gate rejects runtime dependencies on Gateway, Valkey,
Asynq, event-store/projector state, external indexing, payload signing, and CRL
distribution.

## License

AGPL-3.0. See [LICENSE](LICENSE).
