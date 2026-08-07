# Power Manage server quickstart

<!-- docref: begin src=deploy/compose.yml#@deployment-services:a9ac8ed8 -->
The stack has exactly two services: Traefik and one control process with an
embedded SQLite database. Compose gives control no arguments and passes it the
rendered `config/control.env` as the container's environment file. The
authoritative system design is
`../../DESIGN_2026_07_31/00_TARGET_DESIGN.md`.
<!-- docref: end -->

## Prepare

Copy `.env.example` to `.env`, set the three required public values
(`CONTROL_DOMAIN`, `AGENT_DOMAIN`, and `ACME_EMAIL`), then give the audit
archive its own storage and run `./setup.sh`. `.env` carries only those values
and `IMAGE_TAG`; it is Compose's own environment file, not control's
configuration.

### Storage for the audit archive

<!-- docref: begin src=deploy/setup.sh#@archive-isolation:b4ebb270,cmd/control/config.go#validateArchiveIsolation:ae89185b,cmd/control/devauth_stub.go#archiveIsolationRelaxed:8de98d35 -->
`data/backups` must be on a different filesystem from the SQLite database under
`data/control`. Mount a second disk, an NFS or NAS export, or any
remote-backed volume there:

```
mkdir -p data && ln -s /srv/power-manage-archive data/backups
```

A symlink works as well as a mount point: Compose bind-mounts whatever the path
resolves to, so control sees that storage rather than the deploy tree's
filesystem. If a previous run already created the empty directory, `rmdir
data/backups` before linking.

This is a requirement, not a recommendation. The archive holds the anchors and
archived chain prefixes that prove the audit log was not rewritten, so control
compares the two filesystems at startup and refuses to run when they match —
there is no configuration variable that turns the check off. `setup.sh` applies
the same comparison first, naming both paths, so a deployment that cannot boot
is never rendered in the first place.
<!-- docref: end -->

`install.sh` runs `setup.sh` for you and therefore stops at the same point.
Provide the archive storage under the install directory it created, then run
`./setup.sh && ./deploy.sh` there.

Control is configured entirely by `POWER_MANAGE_`-prefixed environment
variables and reads no configuration file. `setup.sh` renders every one of them
into `config/control.env`, and that file is where ordinary settings such as the
log level or the retention windows are edited. `setup.sh` re-renders it on
every run, including through `./deploy.sh`, so re-apply local edits afterwards.

<!-- docref: begin src=deploy/setup.sh#@generated-material:2e53db95 -->
`setup.sh` creates the internal Ed25519 CA, the control certificate, the
encryption, session and sealing keys, and `config/control.env` with a 90-day
audit-retention policy and the SQLite `POWER_MANAGE_DATABASE_PATH`. It first
refuses, before generating any key material, when `data/backups` shares a
filesystem with `data/control`, because control refuses to start on such a
configuration. Existing complete keypairs are retained, which permits a
pre-provisioned CA. Partial or unusable material fails closed. Generated secret
files and `config/control.env` are mode 0600, verified before the script
reports success, and no secret value is ever printed.
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

Artifacts live under `data/artifacts`, and the audit archive and SQLite backups
under `data/backups` — the separate storage prepared above. The SQLite database
lives under `data/control`; ACME state lives under `data/traefik`. Never
consolidate `data/backups` back onto the database's filesystem: control will
refuse to start after the next restart.

<!-- docref: begin src=internal/maintenance/service.go#Service.RetainAudit:8584f810,cmd/control/config.go#Config.AuditRetention:0e4ab606 -->
Control writes integrity-sealed audit anchors and archive-before-delete chain
prefixes to `POWER_MANAGE_BACKUP_PATH`, and re-verifies every archived prefix
against its recorded checkpoint digest before retention deletes anything more;
`POWER_MANAGE_AUDIT_RETENTION` defaults to 90 days. That path must be a
filesystem of its own, which control enforces at startup; replicating it
off-host is the stronger form of the same property and remains yours to
arrange. Back up the database, artifacts, `certs`, and `secrets` as one
deployment unit.
<!-- docref: end -->

<!-- docref: begin src=cmd/control/config.go#Config.WebhookURL:341af9cf,internal/maintenance/service.go#Service.InspectSecurity:223fcf91,internal/maintenance/service.go#Service.InspectBackup:d8c2e6fd -->
Set the optional `POWER_MANAGE_WEBHOOK_URL` to an HTTPS endpoint to receive
generic security
and backup-lag notifications. The payload contains only the event name and
occurrence time; control has no email or provider-specific notification
integration.
<!-- docref: end -->

<!-- docref: begin src=deploy/backup.sh#@sqlite-backup:99bc90ed,cmd/control/backup_status.go#runBackupStatus:41ed4e6c -->
Run `./backup.sh` from a host timer at least daily. It takes an online SQLite
`.backup`, then verifies the copy with `integrity_check` and `foreign_key_check`
before atomically publishing `backup-status.json`. It retains seven backups by
default and never touches readiness. Inspect the latest success and current lag
with `docker compose exec control control backup-status`;
`POWER_MANAGE_BACKUP_MAX_LAG` defaults to 26 hours.
<!-- docref: end -->

<!-- docref: begin src=internal/store/reads.go#ListDueDeliveries:bbaaa8a0,internal/store/search.go#Search:3244914e -->
Pending dispatch is ordinary SQLite state. Search uses SQLite FTS5. There is no
broker, projector rebuild, dynamic proxy provider, or auxiliary search process
to operate.
<!-- docref: end -->
