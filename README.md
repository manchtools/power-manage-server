# Power Manage Server

The server side of Power Manage, providing the API, web UI, agent registration, and real-time agent communication. It consists of two binaries that share a PostgreSQL database:

- **[Control Server](cmd/control/)** — API for the web UI, user management, agent registration (token validation + certificate signing)
- **[Gateway Server](cmd/gateway/)** — Bidirectional streaming endpoint for agents, dispatches actions in real time

## Architecture

```
                          ┌──────────────────────┐
    Web UI / CLI ────────▶│   Control Server     │
    (JWT auth)            │   :8081              │
                          │                      │
                          │  - Connect-RPC API   │
                          │  - Agent registration │
                          │  - Certificate signing│
                          └──────────┬───────────┘
                                     │
                                     ▼
                          ┌──────────────────────┐
                          │     PostgreSQL       │
                          │                      │
                          │  - Event store       │
                          │  - Projections       │
                          │  - LISTEN/NOTIFY     │
                          └──────────┬───────────┘
                                     │
                                     ▼
                          ┌──────────────────────┐
    Agents ──────────────▶│   Gateway Server     │
    (mTLS)                │   :8080              │
                          │                      │
                          │  - Streaming RPC     │
                          │  - Action dispatch   │
                          │  - Status collection │
                          └──────────────────────┘
```

## Event Sourcing

All state changes are recorded as immutable events in a single `events` table. PostgreSQL trigger functions project events into read-optimized `*_projection` tables automatically. Queries read from projections, never from the event store directly.

Inter-service communication uses PostgreSQL `LISTEN/NOTIFY` — when the Control Server dispatches an action, the Gateway picks it up instantly and streams it to the connected agent.

See the [Control Server README](cmd/control/) for details on the event model, API endpoints, and authorization policies.

## Internal Packages

| Package | Purpose |
|---------|---------|
| `internal/api` | Control Server RPC handlers (actions, devices, users, tokens, assignments, registration) |
| `internal/auth` | JWT authentication, OPA authorization, rate limiting, cookie management |
| `internal/ca` | Internal CA for signing agent certificates and action payloads |
| `internal/config` | Configuration loading |
| `internal/connection` | Gateway connection manager — tracks connected agents, routes messages |
| `internal/control` | Control Server background event processor |
| `internal/handler` | Gateway RPC handlers (agent streaming) |
| `internal/mtls` | mTLS setup, extracts device identity from client certificates |
| `internal/store` | PostgreSQL event store, migrations, sqlc queries, LISTEN/NOTIFY |

## Database

- **Migrations**: `internal/store/migrations/` (Goose, embedded at compile time)
- **Queries**: `internal/store/queries/*.sql` (sqlc annotations)
- **Generated code**: `internal/store/generated/` (do not edit — run `sqlc generate` in `internal/store/`)
- **Config**: `internal/store/sqlc.yaml` (pgx/v5 driver)

## Building

```bash
# Both binaries
CGO_ENABLED=0 go build -ldflags="-s -w" -o control ./cmd/control
CGO_ENABLED=0 go build -ldflags="-s -w" -o gateway ./cmd/gateway

# With version injection
CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=2026.2.0" -o control ./cmd/control
CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=2026.2.0" -o gateway ./cmd/gateway
```

## Running Locally

Requires a running PostgreSQL instance. See the [self-hosting guide](../docs/self-hosting.md) for Docker/Podman Compose deployment.

```bash
# Control server
./control \
  -addr=:8081 \
  -db="postgres://user:pass@localhost:5432/powermanage?sslmode=disable" \
  -jwt-secret="$(openssl rand -base64 48)" \
  -ca-cert=certs/ca.crt \
  -ca-key=certs/ca.key \
  -gateway-url=http://localhost:8080

# Gateway server
./gateway \
  -addr=:8080 \
  -db="postgres://user:pass@localhost:5432/powermanage?sslmode=disable"
```

## Regenerating Code

```bash
# After editing SQL queries
cd internal/store && sqlc generate

# After editing proto definitions (in the SDK repo)
cd ../../sdk && make generate
```

## License

AGPL-3.0 — see [LICENSE](LICENSE).
