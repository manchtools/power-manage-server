# Gateway Server

The Gateway Server handles real-time bidirectional communication with Power Manage agents. It provides a Connect-RPC streaming API for agent connections and receives action dispatches via Asynq (Valkey-backed task queue). The Gateway has no direct database connection — all state mutations are forwarded to the Control Server.

## Architecture

```
                            ┌─────────────────────┐
                            │   Control Server    │
                            │  (InternalService)  │
                            └──────────┬──────────┘
                                       │
                        ┌──────────────┼──────────────┐
                        │ Connect-RPC  │  Asynq tasks │
                        │ (credentials)│  (events)    │
                        ▼              ▼              │
              ┌─────────────────────────────┐         │
              │          Valkey             │         │
              │  device:* → Gateway         │         │
              │  control:inbox → Control    │         │
              └──────────────┬──────────────┘         │
                             │                        │
              ┌──────────────┼────────────────────────┘
              │              │
              ▼              ▼
    ┌──────────────────────────────┐
    │       Gateway Server        │
    │  (mTLS, stateless)          │
    │                              │
    │  - Per-device Asynq workers │
    │  - Connect-RPC proxy        │
    └─────────────┬────────────────┘
                  │
    ┌─────────────┴─────────────┐
    │  Agent   Agent   Agent    │
    └───────────────────────────┘
```

The Gateway Server:
1. Accepts agent connections via Connect-RPC streaming (agents register with the Control Server first)
2. Authenticates agents using mTLS certificates (issued by the Control Server during registration)
3. Starts a per-device Asynq worker on agent connect, stops it on disconnect
4. Receives action dispatches from Valkey task queues (`device:<id>`)
5. Forwards agent events (heartbeats, action results) to the `control:inbox` queue
6. Proxies credential-bearing operations (LUKS keys, LPS passwords) to the Control Server via Connect-RPC

## Configuration

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-tls-cert` | (required) | Server certificate path |
| `-tls-key` | (required) | Server private key path |
| `-tls-ca` | (required) | CA certificate for client validation |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_LISTEN_ADDR` | `:8080` | Listen address for the agent mTLS listener |
| `GATEWAY_WEB_LISTEN_ADDR` | (empty) | Listen address for the TTY WebSocket listener (cleartext HTTP — public TLS is terminated at Traefik; empty disables the terminal feature) |
| `GATEWAY_VALKEY_ADDR` | `localhost:6379` | Valkey/Redis address for Asynq task queue |
| `GATEWAY_VALKEY_PASSWORD` | (empty) | Valkey/Redis password |
| `GATEWAY_VALKEY_DB` | `0` | Valkey/Redis database number |
| `GATEWAY_CONTROL_URL` | `https://control:8082` | Control Server InternalService URL for the mTLS Connect-RPC proxy |
| `GATEWAY_ID` | (auto-ULID) | Stable gateway identifier; auto-generated per process when empty (required for replica scaling) |
| `GATEWAY_INTERNAL_URL` | (empty) | mTLS URL the control server uses for admin fan-out RPCs |
| `GATEWAY_HEARTBEAT_INTERVAL` | `30s` | Heartbeat cadence sent to every agent (Go duration, 5s..5m) |
| `GATEWAY_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |

> **rc3 migration:** the previously unprefixed `VALKEY_ADDR` / `VALKEY_PASSWORD` / `VALKEY_DB` / `LOG_LEVEL` knobs now live under the `GATEWAY_*` namespace. The old names are no longer read.

#### Traefik self-registration (Redis KV)

When enabled, each gateway replica publishes its own routing entries into Traefik's Redis KV provider. This removes the need for per-replica Traefik labels in compose and lets `docker compose up --scale gateway=N` (or k8s replica sets) add instances with zero operator touch per replica. The shared mTLS TCP router is load-balanced across all replicas; each replica owns a `/gw/<id>` path on the TTY host for session-specific routing.

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_TRAEFIK_SELF_REGISTER` | `true` | Enable self-registration. Set to `false` to migrate back to static Traefik labels. |
| `GATEWAY_TRAEFIK_ROOT_KEY` | `traefik` | Matches Traefik's `--providers.redis.rootkey`. |
| `GATEWAY_TRAEFIK_MTLS_HOST` | `$GATEWAY_DOMAIN` | Public `HostSNI` for agent mTLS, e.g. `gateway.example.com`. Falls back to `GATEWAY_DOMAIN` — most deployments only set that one env var. |
| `GATEWAY_TRAEFIK_MTLS_BACKEND` | auto | Internal `host:port` for this replica's mTLS listener. Auto-derived from the replica's routable IPv4 on the shared Docker/k8s network + `GATEWAY_LISTEN_ADDR` when empty. |
| `GATEWAY_TRAEFIK_MTLS_ENTRYPOINT` | `websecure` | Traefik entrypoint the TCP passthrough router binds to. Shared with control's HTTP routers — Traefik's SNI dispatch separates passthrough traffic (gateway subdomain) from HTTP termination (control subdomain), so no dedicated mTLS port is required. |
| `GATEWAY_TRAEFIK_TTY_HOST` | `$GATEWAY_TTY_DOMAIN` | Public `Host` for TTY, e.g. `tty.example.com`. Falls back to `GATEWAY_TTY_DOMAIN`. Empty means the TTY router is not registered (single-domain deployments use `GATEWAY_DOMAIN` for both). |
| `GATEWAY_TRAEFIK_TTY_BACKEND` | auto | Internal URL for this replica's TTY listener. Auto-derived from the replica's routable IPv4 + `GATEWAY_WEB_LISTEN_ADDR` when empty. |
| `GATEWAY_TRAEFIK_TTY_ENTRYPOINT` | `websecure` | Traefik entrypoint the TTY router binds to. |
| `GATEWAY_TRAEFIK_TTY_CERT_RESOLVER` | `letsencrypt` | Cert resolver for the per-replica TTY HTTP router. Must match a `--certificatesresolvers.<name>.*` entry in Traefik's static config. Set empty only for bring-your-own-cert deployments that ship a default cert matching `GATEWAY_TRAEFIK_TTY_HOST` — otherwise browsers reject the default self-signed cert Traefik serves for Redis-KV routers. |

The backend auto-derivation uses the gateway replica's own IPv4 address on the shared container network (via `net.InterfaceAddrs()`), **not** `os.Hostname()` — a container's default hostname is its 12-char ID, which is not registered in Docker's embedded DNS, so publishing it as a Traefik backend leaves Traefik unable to resolve the replica and quietly falls back to the HTTP router (which serves the wrong cert).

All Traefik keys share the registry TTL (45 s default) and are refreshed on the same cadence as the gateway terminal-URL entry. Graceful shutdown revokes only per-replica keys; shared router keys expire naturally when the last replica stops. See `server/deploy/compose.yml` for the matching Traefik command flags.

## Setup

### Prerequisites

1. **Valkey/Redis** — shared with the Control Server for Asynq task queues
2. **Control Server** — must be running and reachable for InternalService RPC

3. **TLS Certificates**:
   - CA certificate (same as Control Server)
   - Server certificate signed by the CA
   - Server private key

### Generating Server Certificates

```bash
# Generate server key
openssl genrsa -out server.key 2048

# Generate server CSR
openssl req -new -key server.key -out server.csr \
  -subj "/CN=gateway.power-manage.local"

# Sign with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:gateway.power-manage.local,DNS:localhost,IP:127.0.0.1")
```

### Running Locally

Local development uses the same TLS shape as deployed environments:

```bash
export GATEWAY_VALKEY_ADDR=localhost:6379
export GATEWAY_VALKEY_PASSWORD=your-password
export GATEWAY_CONTROL_URL=https://localhost:8082
export LOG_LEVEL=debug

go run ./server/cmd/gateway \
  -tls-cert=/certs/server.crt \
  -tls-key=/certs/server.key \
  -tls-ca=/certs/ca.crt
```

### Running With mTLS

```bash
export GATEWAY_VALKEY_ADDR=valkey:6379
export GATEWAY_VALKEY_PASSWORD=your-password
export GATEWAY_CONTROL_URL=https://control:8082

go run ./server/cmd/gateway \
  -tls-cert=/certs/server.crt \
  -tls-key=/certs/server.key \
  -tls-ca=/certs/ca.crt
```

### Running with Podman Compose

```bash
# Start all services (includes mTLS gateway on :8080)
podman-compose up -d
```

## Agent Service API

The Gateway exposes a Connect-RPC service for agent communication.

### Service Definition

```protobuf
service AgentService {
  // Bidirectional stream for agent-server communication
  rpc Stream(stream AgentMessage) returns (stream ServerMessage);
}
```

**Note:** Agent registration is handled by the Control Server (see [Control Server README](../control/README.md)). Agents first register with the Control Server to obtain mTLS certificates and the gateway URL, then connect to the Gateway for streaming communication.

The Gateway also exposes a unary RPC for LUKS token validation:

```protobuf
rpc ValidateLuksToken(ValidateLuksTokenRequest) returns (ValidateLuksTokenResponse);
```

This is called by the agent CLI `luks set-passphrase` subcommand to validate a one-time token before accepting a user-defined passphrase.

### Streaming Protocol

After registration, agents connect via the `Stream` RPC:

#### Agent → Server Messages

| Message | Description |
|---------|-------------|
| `Hello` | Initial handshake with device info (device ID, agent version, hostname, auth token, architecture) |
| `Heartbeat` | Periodic health/metrics report (uptime, CPU, memory, disk) |
| `ActionResult` | Result of an executed action |
| `OSQueryResult` | Result of an OS query |
| `LogQueryResult` | Result of a remote journalctl log query |
| `GetLuksKeyRequest` | Request current LUKS managed passphrase for an action |
| `StoreLuksKeyRequest` | Store a new LUKS managed passphrase on the server |
| `RevokeLuksDeviceKeyResult` | Report result of a device-bound key revocation |

#### Server → Agent Messages

| Message | Description |
|---------|-------------|
| `Welcome` | Response to Hello with server version. Auto-update fields (`latest_agent_version`, `update_url`, `update_checksum`) are optional — only populated when auto-update is enabled and a matching release exists for the agent's architecture. |
| `ActionDispatch` | Action to execute |
| `OSQuery` | OS query to run |
| `LogQuery` | Remote journalctl log query (unit, lines, priority, grep filter) |
| `GetLuksKeyResponse` | Response with current LUKS managed passphrase |
| `StoreLuksKeyResponse` | Confirmation that a LUKS passphrase was stored |
| `RevokeLuksDeviceKey` | Instruction to revoke the device-bound key in LUKS slot 7 |
| `Error` | Error message |

### Connection Flow

```
Agent                              Gateway
  │                                   │
  │──── Hello ────────────────────────▶│
  │                                   │
  │◀─── Welcome ──────────────────────│
  │                                   │
  │──── Heartbeat ────────────────────▶│ (every 30s)
  │                                   │
  │◀─── ActionDispatch ───────────────│ (from Control via Asynq)
  │                                   │
  │──── ActionResult ─────────────────▶│
  │                                   │
  │──── GetLuksKeyRequest ───────────▶│ (LUKS action needs server key)
  │                                   │
  │◀─── GetLuksKeyResponse ──────────│
  │                                   │
  │──── StoreLuksKeyRequest ─────────▶│ (after key rotation)
  │                                   │
  │◀─── StoreLuksKeyResponse ────────│ (confirms receipt before old key removal)
  │                                   │
  │◀─── LogQuery ────────────────────│ (remote journalctl query)
  │                                   │
  │──── LogQueryResult ──────────────▶│
  │                                   │
```

## Asynq Task Queues

The Gateway uses Asynq (Valkey-backed) task queues for communication with the Control Server. This replaces the previous PostgreSQL LISTEN/NOTIFY mechanism and eliminates the Gateway's database dependency.

### Control → Gateway (device queues)

Each connected device has its own Asynq queue (`device:<id>`) with a per-device worker (concurrency 1):

| Task Type | Description |
|-----------|-------------|
| `action:dispatch` | Dispatch an action to the agent |
| `osquery:dispatch` | Send an OS query to the agent |
| `inventory:request` | Request device inventory refresh |
| `log:query` | Send a remote journalctl log query to the agent |
| `luks:revoke_device_key` | Instruct agent to revoke device-bound LUKS key |

### Gateway → Control (control:inbox queue)

Agent events are forwarded to the `control:inbox` queue for the Control Server to process:

| Task Type | Description |
|-----------|-------------|
| `device:hello` | Agent connected and sent Hello |
| `device:heartbeat` | Agent sent a heartbeat with metrics |
| `execution:result` | Agent completed an action (success or failure) |
| `execution:output_chunk` | Streaming output from an action |
| `osquery:result` | OS query result from agent |
| `log:result` | Log query result from agent |
| `inventory:update` | Device inventory update |
| `security:alert` | Security alert from agent |
| `luks:revoke_device_key_result` | Result of device-bound key revocation |

### Gateway → Control (Connect-RPC proxy)

Credential-bearing operations are proxied via Connect-RPC (`InternalService`) to avoid plaintext secrets in Valkey:

| RPC | Description |
|-----|-------------|
| `ProxySyncActions` | Resolve all assigned actions for a device |
| `ProxyValidateLuksToken` | Validate a one-time LUKS token |
| `ProxyGetLuksKey` | Retrieve and decrypt a LUKS key |
| `ProxyStoreLuksKey` | Encrypt and store a new LUKS key |
| `ProxyStoreLpsPasswords` | Encrypt and store LPS password rotations |
| `GetAutoUpdateInfo` | Get latest agent release info (version, URL, checksum) for Welcome message |

## Health Endpoints

### Health Check

```bash
curl http://localhost:8080/health
# Returns: {"status":"healthy","agents":5}
```

The health endpoint returns the number of connected agents.

### Ready Check

```bash
curl http://localhost:8080/ready
# Returns: ok
```

## Action Types

The Gateway forwards these action types from Control Server to agents:

| Type | Description | Parameters |
|------|-------------|------------|
| `PACKAGE` | Package management | name, version, allow_downgrade, pin |
| `APP_IMAGE` | AppImage installation | url, checksum_sha256, install_path |
| `DEB` | .deb installation | url, checksum_sha256, install_path |
| `RPM` | .rpm installation | url, checksum_sha256, install_path |
| `SHELL` | Shell script execution | script, interpreter, run_as_root, working_directory, environment |
| `SYSTEMD` | Systemd unit management | unit_name, desired_state, enable, unit_content |
| `FILE` | File management | path, content, owner, group, mode |
| `LUKS` | LUKS disk encryption | preshared_key, rotation_interval_days, min_words, device_bound_key_type |

## OS Query Support

The Gateway supports osquery-compatible queries:

```protobuf
message OSQuery {
  string query_id = 1;
  string table = 2;
  repeated string columns = 3;
  repeated OSQueryCondition where = 4;
  int32 limit = 5;
}
```

### Supported Tables

- `os_version` - OS information
- `system_info` - Hardware information
- `kernel_info` - Kernel version
- `uptime` - System uptime
- `users` - System users
- `processes` - Running processes
- `packages` - Installed packages
- `deb_packages` - Debian packages
- `rpm_packages` - RPM packages
- `systemd_units` - Systemd services
- `listening_ports` - Open ports
- `mounts` - Mounted filesystems
- `memory_info` - Memory usage

## Security

### mTLS Authentication

In production mode, the Gateway requires mutual TLS with `RequireAndVerifyClientCert` (TLS 1.3 minimum):

1. Gateway presents its server certificate
2. Agent **must** present its device certificate (issued during registration) — connections without a client certificate are rejected
3. Gateway validates agent certificate against CA
4. Device ID is extracted from the certificate Common Name

### Certificate Validation

- Certificates must be signed by the configured CA
- Expired certificates are rejected
- The device ID in the certificate CN must match the Hello message
- Agents automatically renew certificates at 80% of their lifetime via the Control Server's `RenewCertificate` RPC

## Scaling

Multiple Gateway instances can run simultaneously:

- Each Gateway starts per-device Asynq workers for its connected agents
- Agents connect to any available Gateway (via load balancer)
- Asynq delivers tasks to the Gateway whose worker is processing the device queue
- Use sticky sessions or agent-affinity for long-lived connections

### Load Balancer Configuration

When running multiple Gateways behind a load balancer:

1. Use TCP/TLS passthrough (not HTTP termination) for mTLS
2. Enable sticky sessions based on source IP
3. Set appropriate idle timeouts (connections are long-lived)

## Troubleshooting

### Debug Logging

```bash
GATEWAY_LOG_LEVEL=debug ./gateway -tls -tls-cert=... -tls-key=... -tls-ca=...
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "TLS enabled but missing required flags" | Missing -tls-cert, -tls-key, or -tls-ca | Provide all three certificate paths |
| Agent connection refused | mTLS cert validation failed | Verify agent certificate is signed by the same CA |
| Actions not dispatched | Asynq worker not started for device | Check device ID matches between certificate and Hello |
| "failed to connect to valkey" | Valkey not reachable | Check `GATEWAY_VALKEY_ADDR` and `GATEWAY_VALKEY_PASSWORD` |
| Credential operations failing | Control Server not reachable | Check `GATEWAY_CONTROL_URL` |

## Development

### Building

```bash
go build -o gateway ./server/cmd/gateway
```

### Running Tests

```bash
go test ./server/internal/handler/...
go test ./server/internal/connection/...
```

### Local Development Stack

```bash
# Start Valkey and Control Server
podman-compose up -d valkey control

# Run gateway in dev mode
export GATEWAY_VALKEY_ADDR=localhost:6379
export GATEWAY_VALKEY_PASSWORD=your-password
export GATEWAY_CONTROL_URL=https://localhost:8082
export LOG_LEVEL=debug

go run ./server/cmd/gateway \
  -tls-cert=/certs/gateway.crt \
  -tls-key=/certs/gateway.key \
  -tls-ca=/certs/ca.crt
```
