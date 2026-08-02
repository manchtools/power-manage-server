# Control server

`control` is the single target server process. The workspace architecture
authority is
`../../../DESIGN_2026_07_31/00_TARGET_DESIGN.md`.

## Responsibilities

- public Connect-RPC API for the web and automation clients;
- dedicated direct-agent mTLS listener;
- OIDC, SCIM, RBAC, and scoped authorization;
- CRUD state and transactional audit operation/effect rows;
- database-backed scheduling and durable delivery;
- PostgreSQL full-text search during consolidation;
- certificate issuance, renewal, and indexed revocation;
- artifact metadata and filesystem ownership; and
<!-- docref: begin src=internal/controlruntime/runtime.go#health:550d4ab3,internal/controlruntime/runtime.go#readinessHandler:679b3b18,cmd/control/backup_status.go#runBackupStatus:41ed4e6c -->
- health and readiness endpoints, plus the host-facing `backup-status` command.
<!-- docref: end -->

There is no target Gateway, Valkey, Asynq worker, event projector, separate
indexer, local password/TOTP service, or application-frame signer.

## Startup

Control must fail readiness when the schema is not current, required keys or CA
material are unusable, artifact paths are not writable, or the agent listener
cannot enforce revocation.

Ordinary settings belong in a documented configuration file. Deployment
secrets may use narrow environment or file overrides. Do not add one
environment variable per ordinary option.

Initial administration uses the host-authorized `bootstrap-admin` command to
produce a single-use, short-lived URL. Configure OIDC/SCIM immediately; there
is no local administrator password.

## Database sequence

Use PostgreSQL for the consolidation. Convert state to CRUD, audit to dedicated
append-only tables, work to database jobs, and search to PostgreSQL FTS first.
Do not mix those changes with the SQLite port.

After semantics and verification are stable, port to SQLite WAL with
`synchronous=FULL` and replace PostgreSQL FTS with FTS5.

## Development

```bash
go build ./cmd/control
go test ./...
make sqlc-generate
make sqlc-check
```

Generated sqlc and protobuf outputs are never edited by hand.

Trust-boundary tests must cover validation before authentication,
authorization and scope rejection, transaction rollback on audit failure,
certificate revocation, delivery replay, and secret exclusion.
