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
- SQLite FTS5 full-text search;
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

## Database

Control embeds SQLite in WAL mode with `synchronous=FULL` and owns the file
named by `database_path`. Search runs on FTS5.

That datastore port deliberately came last: state was first converted to CRUD,
audit to dedicated append-only tables, work to database jobs, and search to
full-text search, so swapping the engine did not change RPC or observable
search semantics. PostgreSQL is removed and guarded against return.

## Development

```bash
go build ./cmd/control
go test ./...
make sqlc-generate
make sqlc-check
```

Generated sqlc and protobuf outputs are never edited by hand.

<!-- docref: begin src=internal/store/sqlite_scale_test.go#TestSQLiteScale_MixedWorkloadAtTenThousandAgents:cbcd232a -->
Run the explicit SQLite 10,000-agent gate with:

```bash
POWER_MANAGE_RUN_SCALE_TEST=1 go test ./internal/store \
  -run '^TestSQLiteScale_MixedWorkloadAtTenThousandAgents$' -count=1 -v -timeout 10m
```

It is intentionally skipped by the ordinary unit-test gate and logs one
`SQLITE_SCALE_RESULT` JSON record.
<!-- docref: end -->

Trust-boundary tests must cover validation before authentication,
authorization and scope rejection, transaction rollback on audit failure,
certificate revocation, delivery replay, and secret exclusion.
