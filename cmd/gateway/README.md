# Gateway Server

The Gateway Server handles real-time bidirectional communication with Power Manage agents. It provides a Connect-RPC streaming API for agent connections and receives action dispatches from PostgreSQL LISTEN/NOTIFY.

## Architecture

```
                            ┌─────────────────────┐
                            │   Control Server    │
                            │  (dispatches via    │
                            │   PostgreSQL)       │
                            └──────────┬──────────┘
                                       │
                                       ▼
                            ┌─────────────────────┐
                            │     PostgreSQL      │
                            │  LISTEN/NOTIFY      │
                            │  pg_notify()        │
                            └──────────┬──────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
    ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
    │    Gateway      │     │    Gateway      │     │    Gateway      │
    │    Server       │     │    Server       │     │    Server       │
    │  (mTLS/h2c)     │     │  (mTLS/h2c)     │     │  (mTLS/h2c)     │
    └────────┬────────┘     └────────┬────────┘     └────────┬────────┘
             │                       │                       │
    ┌────────┴────────┐     ┌────────┴────────┐     ┌────────┴────────┐
    │  Agent   Agent  │     │  Agent   Agent  │     │  Agent   Agent  │
    └─────────────────┘     └─────────────────┘     └─────────────────┘
```

The Gateway Server:
1. Accepts agent connections via Connect-RPC streaming (agents register with the Control Server first)
2. Authenticates agents using mTLS certificates (issued by the Control Server during registration)
3. Subscribes to PostgreSQL LISTEN/NOTIFY for action dispatching
4. Routes incoming actions to the appropriate connected agent
5. Records agent events (heartbeats, action results) to the event store

## Configuration

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | Listen address |
| `-database-url` | (required) | PostgreSQL connection URL |
| `-log-level` | `info` | Log level (debug, info, warn, error) |
| `-tls` | `false` | Enable mTLS mode |
| `-tls-cert` | (required if -tls) | Server certificate path |
| `-tls-key` | (required if -tls) | Server private key path |
| `-tls-ca` | (required if -tls) | CA certificate for client validation |

## Setup

### Prerequisites

1. **PostgreSQL 18+** - the same database used by the Control Server

2. **TLS Certificates** (for production mTLS mode):
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

### Running in Development Mode (h2c)

For local development without TLS:

```bash
go run ./server/cmd/gateway \
  -addr=:8080 \
  -database-url="postgres://powermanage:powermanage@localhost:5432/powermanage?sslmode=disable" \
  -log-level=debug
```

This runs in HTTP/2 cleartext (h2c) mode - **not suitable for production**.

### Running in Production Mode (mTLS)

```bash
go run ./server/cmd/gateway \
  -addr=:8080 \
  -database-url="postgres://powermanage:powermanage@localhost:5432/powermanage?sslmode=require" \
  -tls \
  -tls-cert=/certs/server.crt \
  -tls-key=/certs/server.key \
  -tls-ca=/certs/ca.crt \
  -log-level=info
```

### Running with Podman Compose

```bash
# Start all services (includes mTLS gateway on :8080)
podman-compose up -d

# Or with the dev profile (includes h2c gateway on :8082)
podman-compose --profile dev up -d
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

### Streaming Protocol

After registration, agents connect via the `Stream` RPC:

#### Agent → Server Messages

| Message | Description |
|---------|-------------|
| `Hello` | Initial handshake with device info |
| `Heartbeat` | Periodic health/metrics report (uptime, CPU, memory, disk) |
| `ActionResult` | Result of an executed action |
| `OSQueryResult` | Result of an OS query |

#### Server → Agent Messages

| Message | Description |
|---------|-------------|
| `Welcome` | Response to Hello with server info |
| `ActionDispatch` | Action to execute |
| `OSQuery` | OS query to run |
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
  │◀─── ActionDispatch ───────────────│ (from Control via pg_notify)
  │                                   │
  │──── ActionResult ─────────────────▶│
  │                                   │
```

## PostgreSQL LISTEN/NOTIFY

The Gateway subscribes to PostgreSQL notification channels for real-time action dispatching:

### Channel Naming

Each agent has its own channel: `agent_{device_id}`

When the Control Server dispatches an action, the database trigger sends a notification:

```sql
-- Triggered automatically when ExecutionCreated event is inserted
pg_notify('agent_01HWXYZ...', '{
  "type": "action_dispatch",
  "execution_id": "01HWABC...",
  "action_type": 1,
  "desired_state": 1,
  "params": {...},
  "timeout_seconds": 300
}');
```

### Event Recording

The Gateway records events directly to the PostgreSQL event store:

| Event | Description |
|-------|-------------|
| `DeviceHeartbeat` | Agent sent a heartbeat with metrics |
| `ExecutionStarted` | Agent started executing an action |
| `ExecutionCompleted` | Action completed successfully |
| `ExecutionFailed` | Action failed with an error |

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

In production mode, the Gateway requires mutual TLS:

1. Gateway presents its server certificate
2. Agent presents its device certificate (issued during registration)
3. Gateway validates agent certificate against CA
4. Device ID is extracted from the certificate Common Name

### Certificate Validation

- Certificates must be signed by the configured CA
- Expired certificates are rejected
- The device ID in the certificate CN must match the Hello message

## Scaling

Multiple Gateway instances can run simultaneously:

- Each Gateway subscribes to PostgreSQL LISTEN channels
- Agents connect to any available Gateway (via load balancer)
- Actions are delivered to the Gateway with the connected agent
- Use sticky sessions or agent-affinity for long-lived connections

### Load Balancer Configuration

When running multiple Gateways behind a load balancer:

1. Use TCP/TLS passthrough (not HTTP termination) for mTLS
2. Enable sticky sessions based on source IP
3. Set appropriate idle timeouts (connections are long-lived)

## Troubleshooting

### Debug Logging

```bash
./gateway -log-level=debug -database-url="..."
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "TLS enabled but missing required flags" | Missing -tls-cert, -tls-key, or -tls-ca | Provide all three certificate paths |
| Agent connection refused | mTLS cert validation failed | Verify agent certificate is signed by the same CA |
| "database-url is required" | Missing database URL | Provide PostgreSQL connection URL |
| Actions not dispatched | Agent not listening to correct channel | Check device ID matches between certificate and Hello |
| High latency | Network or database issues | Check PostgreSQL connectivity and performance |

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
# Start PostgreSQL
podman-compose up -d postgres

# Run gateway in dev mode
go run ./server/cmd/gateway \
  -database-url="postgres://powermanage:powermanage@localhost:5432/powermanage?sslmode=disable" \
  -log-level=debug
```
