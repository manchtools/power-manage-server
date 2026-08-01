# Power Manage server quickstart

<!-- docref: begin src=deploy/compose.yml#@deployment-services:b4fee0cc -->
The consolidation stack has exactly three services: Traefik, one control
process, and PostgreSQL. The authoritative system design is
`../../DESIGN_2026_07_31/00_TARGET_DESIGN.md`.
<!-- docref: end -->

## Prepare

Copy `.env.example` to `.env`, edit the three required public values, then run
`./setup.sh`.

<!-- docref: begin src=deploy/setup.sh#@generated-material:f8d53515 -->
`setup.sh` creates the internal Ed25519 CA, the control and datastore
certificates, the session and sealing keys, the PostgreSQL password, and
`config/control.json`. Existing complete keypairs are retained, which permits a
pre-provisioned CA. Partial or unusable material fails closed. Generated secret
files are mode 0600 and are never printed.
<!-- docref: end -->

<!-- docref: begin src=deploy/traefik/dynamic/routes.yml#@agent-route:2b16b515,cmd/control/httpserver.go#serveAgent:0543d07f,cmd/control/httpserver.go#buildAgentServer:ccd04d34,internal/agentstream/identity.go#MTLSMiddleware:f1b23680 -->
The public and agent hostnames must differ. Traefik terminates browser/API TLS
for `CONTROL_DOMAIN`. For `AGENT_DOMAIN`, it passes TLS through and adds PROXY
protocol v2 on an isolated network; control itself authenticates the device
certificate and checks revocation.
<!-- docref: end -->

## Start

Run `docker compose up -d --wait`, then inspect the result with
`docker compose ps`.

<!-- docref: begin src=cmd/control/bootstrap_admin.go#runBootstrapAdmin:c20952b3 -->
Create a host-authorized, single-use administrator setup URL:

Run `docker compose exec control control bootstrap-admin`.
<!-- docref: end -->

Use that session to configure OIDC and SCIM. There is no local password or TOTP
administrator.

## Operate

Use `./deploy.sh` for an update, `docker compose logs -f control` for logs, and
`docker compose down` to stop the stack.

Artifacts and backups live under `data/artifacts` and `data/backups`.
PostgreSQL data lives under `data/postgres`; ACME state lives under
`data/traefik`. Back these paths and the `certs` and `secrets` directories up as
one deployment unit.

<!-- docref: begin src=internal/store/reads.go#ListDueDeliveries:081847c0,internal/store/search.go#Search:8542ac77 -->
Pending dispatch is ordinary PostgreSQL state. Search uses PostgreSQL FTS.
There is no broker, projector rebuild, dynamic proxy provider, or auxiliary
search process to operate.
<!-- docref: end -->
