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

<!-- docref: begin src=cmd/control/main.go#parseCommand:9ba09808,cmd/control/config.go#configEnvironment:f192d94c,cmd/control/config.go#readEnvironment:88fc4d61,cmd/control/config.go#parseList:02da4e62 -->
Configuration is entirely environmental: every option is its own documented
`POWER_MANAGE_`-prefixed variable. There is no configuration file and no
`-config` flag, and the only accepted arguments are the `bootstrap-admin` and
`backup-status` subcommands. The `configEnvironment` declarations in
`config.go` are the authoritative option list — each field's tag names its
variable and its type selects the parser — and startup fails closed on any
`POWER_MANAGE_` variable that is not declared there, so a misspelling stops the
process by name instead of silently leaving its option at the default. List
options are comma-separated and reject an empty entry; malformed booleans and
durations name their variable and fail startup.
<!-- docref: end -->

<!-- docref: begin src=cmd/control/main.go#run:065ded94,internal/ca/ca.go#CA.SetTrustBundle:3b932aea -->
`POWER_MANAGE_CA_TRUST_BUNDLE_FILE` optionally names the startup-only PEM trust
bundle used for agent-client certificate verification. It must contain the
active CA from `POWER_MANAGE_CA_CERT_FILE`; changing either file requires a
control restart.
<!-- docref: end -->

<!-- docref: begin src=cmd/control/config.go#loadSecret:b9678c7e,cmd/control/config.go#readSecretFile:60ffa83b,cmd/control/config.go#loadEd25519PrivateKey:3cc11345 -->
Private keys are file-referenced only: `POWER_MANAGE_SESSION_SIGNING_KEY_FILE`
must name one PEM-encoded Ed25519 PKCS#8 key. The two symmetric secrets accept
either form — exactly one of `POWER_MANAGE_ENCRYPTION_KEY` or
`POWER_MANAGE_ENCRYPTION_KEY_FILE`, and exactly one of
`POWER_MANAGE_SEALING_KEY` or `POWER_MANAGE_SEALING_KEY_FILE`. Naming both of a
pair is a configuration mistake rather than a precedence question and fails
startup, as does naming neither. A referenced secret file must be a small
regular file that is not group/world accessible. Configuration errors report
variable names only; secret values are never echoed.
<!-- docref: end -->

For the values the reference deployment renders, see `../../deploy/QUICKSTART.md`.

Initial administration uses the host-authorized `bootstrap-admin` command to
produce a single-use, short-lived URL. Configure OIDC/SCIM immediately; there
is no local administrator password.

## Database

Control embeds SQLite in WAL mode with `synchronous=FULL` and owns the file
named by `POWER_MANAGE_DATABASE_PATH`. Search runs on FTS5.

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
