# Power Manage server quickstart

<!-- docref: begin src=deploy/compose.yml#@deployment-services:5fb8f238 -->
The stack has exactly two services: Traefik and one control process with an
embedded SQLite database. The authoritative system design is
`../../DESIGN_2026_07_31/00_TARGET_DESIGN.md`.
<!-- docref: end -->

## Prepare

Copy `.env.example` to `.env`, edit the three required public values, then run
`./setup.sh`.

<!-- docref: begin src=deploy/setup.sh#@generated-material:6c6a5264 -->
`setup.sh` creates the internal Ed25519 CA, the control certificate, the
encryption, session and sealing keys, and `config/control.json` with a 90-day
audit-retention policy and the SQLite `database_path`. Existing complete
keypairs are retained, which permits a pre-provisioned CA. Partial or unusable
material fails closed. Generated secret files are mode 0600 and are never
printed.
<!-- docref: end -->

<!-- docref: begin src=deploy/traefik/dynamic/routes.yml#@agent-route:2b16b515,cmd/control/httpserver.go#serveAgent:0543d07f,cmd/control/httpserver.go#buildAgentServer:ccd04d34,internal/agentstream/identity.go#MTLSMiddleware:f1b23680 -->
The public and agent hostnames must differ. Traefik terminates browser/API TLS
for `CONTROL_DOMAIN`. For `AGENT_DOMAIN`, it passes TLS through and adds PROXY
protocol v2 on an isolated network; control itself authenticates the device
certificate and checks revocation.
<!-- docref: end -->

<!-- docref: begin src=deploy/traefik/dynamic/routes.yml#@public-backend-tls:965c0116,deploy/traefik/traefik.yml#@safe-access-log:e383937a -->
Traefik also authenticates control's internal TLS certificate against the
deployment CA, so browser/API traffic stays encrypted after public TLS
termination. Its JSON access log omits the URI-bearing `RequestPath` and
`RequestLine` fields; method, host, status, timing, router, service, and client
metadata remain available without recording query-string credentials.
<!-- docref: end -->

## Start

Run `docker compose up -d --wait`, then inspect the result with
`docker compose ps`.

<!-- docref: begin src=cmd/control/bootstrap_admin.go#runBootstrapAdmin:aa979b40,internal/identity/bootstrap.go#Bootstrapper.setupURL:417b204e -->
Create a host-authorized, single-use administrator setup URL:

Run `docker compose exec control control bootstrap-admin`.

The bearer token is placed in the URL fragment, which browsers do not send to
control or Traefik access logs.
<!-- docref: end -->

Use that session to configure OIDC and SCIM. There is no local password or TOTP
administrator.

## Operate

Use `./deploy.sh` for an update, `docker compose logs -f control` for logs, and
`docker compose down` to stop the stack.

Artifacts and backups live under `data/artifacts` and `data/backups`. The
SQLite database lives under `data/control`; ACME state lives under
`data/traefik`.

<!-- docref: begin src=internal/maintenance/service.go#Service.RetainAudit:c0aefcae,cmd/control/config.go#Config.AuditRetention:0e4ab606 -->
Control writes integrity-sealed audit anchors and archive-before-delete chain
prefixes to `backup_path`; `audit_retention` defaults to 90 days. Mount or
replicate that path off-host, and back up the database, artifacts, `certs`, and
`secrets` as one deployment unit.
<!-- docref: end -->

<!-- docref: begin src=cmd/control/config.go#Config.WebhookURL:341af9cf,internal/maintenance/service.go#Service.InspectSecurity:223fcf91,internal/maintenance/service.go#Service.InspectBackup:d8c2e6fd -->
Set the optional `webhook_url` to an HTTPS endpoint to receive generic security
and backup-lag notifications. The payload contains only the event name and
occurrence time; control has no email or provider-specific notification
integration.
<!-- docref: end -->

<!-- docref: begin src=deploy/backup.sh#@sqlite-backup:76ef1013,cmd/control/backup_status.go#runBackupStatus:41ed4e6c -->
Run `./backup.sh` from a host timer at least daily. It takes an online SQLite
`.backup`, then verifies the copy with `integrity_check` and `foreign_key_check`
before atomically publishing `backup-status.json`. It retains seven backups by
default and never touches readiness. Inspect the latest success and current lag
with `docker compose exec control control backup-status`; `backup_max_lag`
defaults to 26 hours.
<!-- docref: end -->

<!-- docref: begin src=internal/store/reads.go#ListDueDeliveries:bbaaa8a0,internal/store/search.go#Search:3244914e -->
Pending dispatch is ordinary SQLite state. Search uses SQLite FTS5. There is no
broker, projector rebuild, dynamic proxy provider, or auxiliary search process
to operate.
<!-- docref: end -->
