# Power Manage server quickstart

This guide describes the approved consolidation deployment. The sole system
design authority is
`../../DESIGN_2026_07_31/00_TARGET_DESIGN.md`.

## Stack

- Traefik
- one control process
- PostgreSQL
- explicit artifact and backup mounts

Do not deploy Gateway, Valkey, Asynq, or a separate indexer. PostgreSQL remains
until the final SQLite/FTS5 port.

## Network

Traefik exposes:

- HTTPS/L7 routing to control's browser/API listener; and
- SNI TCP passthrough to control's dedicated agent mTLS listener.

If PROXY protocol v2 is enabled, its control listener must be reachable only
from an allowlisted isolated Traefik network.

## Setup

Use the branch's deployment tooling to:

1. create or import the CA;
2. generate deployment secrets without printing them;
3. configure the API and agent routes;
4. initialize PostgreSQL;
5. validate key and mount permissions; and
6. generate a one-time bootstrap-admin URL.

Configure OIDC and SCIM through that bootstrap session. There is no local
password or TOTP administrator.

## Readiness

Before enrolling devices, confirm:

- control reports the current schema;
- keys and CA material are usable;
- artifact and backup paths are writable;
- certificate revocation lookup works on the agent listener; and
- backup age and replication lag are visible.

## Agent enrollment

Create an enrollment token, install the agent, and point it at the control
endpoint. The agent generates its identity key locally and connects outbound
through Traefik directly to control.

## Troubleshooting

Inspect Traefik, control, PostgreSQL, and the agent journal. Pending dispatch is
database state; there is no queue service or projector to rebuild.
