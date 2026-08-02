# Power Manage server quickstart

<!-- docref: begin src=deploy/compose.yml#@deployment-services:c8bd2e6c -->
The consolidation stack has exactly three services: Traefik, one control
process, and PostgreSQL. The authoritative system design is
`../../DESIGN_2026_07_31/00_TARGET_DESIGN.md`.
<!-- docref: end -->

## Prepare

Copy `.env.example` to `.env`, edit the three required public values, then run
`./setup.sh`.

<!-- docref: begin src=deploy/setup.sh#@generated-material:c04bb228 -->
`setup.sh` creates the internal Ed25519 CA, the control and datastore
certificates, the session and sealing keys, the PostgreSQL password, and
`config/control.json` with a 90-day audit-retention policy. Existing complete
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

<!-- docref: begin src=cmd/control/bootstrap_admin.go#runBootstrapAdmin:c20952b3,internal/identity/bootstrap.go#Bootstrapper.setupURL:417b204e -->
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

Artifacts and backups live under `data/artifacts` and `data/backups`.
PostgreSQL data lives under `data/postgres`; ACME state lives under
`data/traefik`.

<!-- docref: begin src=internal/maintenance/service.go#Service.RetainAudit:c0aefcae,cmd/control/config.go#Config.AuditRetention:0e4ab606 -->
Control writes integrity-sealed audit anchors and archive-before-delete chain
prefixes to `backup_path`; `audit_retention` defaults to 90 days. Mount or
replicate that path off-host, and back up the database, artifacts, `certs`, and
`secrets` as one deployment unit.
<!-- docref: end -->

<!-- docref: begin src=internal/store/reads.go#ListDueDeliveries:081847c0,internal/store/search.go#Search:12db8002 -->
Pending dispatch is ordinary PostgreSQL state. Search uses PostgreSQL FTS.
There is no broker, projector rebuild, dynamic proxy provider, or auxiliary
search process to operate.
<!-- docref: end -->
