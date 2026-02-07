# Control Server

The Control Server is the central management API for Power Manage. It provides a Connect-RPC/gRPC API for managing users, devices, registration tokens, action definitions, and action executions.

## Architecture

The Control Server uses a **CQRS/Event Sourcing** architecture:

- **Event Store**: All state changes are recorded as immutable events in PostgreSQL
- **Projections**: Read models are automatically updated via database triggers
- **LISTEN/NOTIFY**: Real-time notifications for UI updates and agent dispatching

```
┌─────────────────────┐     ┌─────────────────────┐
│   Control Server    │───▶│     PostgreSQL      │
│  (Connect-RPC API)  │     │   - events table    │
└─────────────────────┘     │   - projections     │
         │                  │   - triggers        │
         │                  └─────────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────────┐     ┌─────────────────────┐
│   UI / CLI Client   │     │   pg_notify()       │
│   (JWT Auth)        │     │   → Gateway         │
└─────────────────────┘     │   → UI WebSocket    │
                            └─────────────────────┘
```

## Configuration

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:8081` | Listen address |
| `-database-url` | (required) | PostgreSQL connection URL |
| `-jwt-secret` | (auto-generated) | JWT signing secret |
| `-ca-cert` | `/certs/ca.crt` | CA certificate path |
| `-ca-key` | `/certs/ca.key` | CA private key path |
| `-cert-validity` | `8760h` (1 year) | Certificate validity duration |
| `-log-level` | `info` | Log level (debug, info, warn, error) |
| `-log-format` | `text` | Log format (text, json) |
| `-gateway-url` | (required) | Gateway URL returned to agents during registration |
| `-admin-email` | (optional) | Initial admin user email |
| `-admin-password` | (optional) | Initial admin user password |
| `-dynamic-group-eval-interval` | `1h` | Interval for evaluating queued dynamic groups (min 30m, max 8h, 0 to disable) |

### Environment Variables

Environment variables override command-line flags:

| Variable | Description |
|----------|-------------|
| `CONTROL_LISTEN_ADDR` | Listen address |
| `CONTROL_DATABASE_URL` | PostgreSQL connection URL |
| `CONTROL_JWT_SECRET` | JWT signing secret |
| `CONTROL_CA_CERT` | CA certificate path |
| `CONTROL_CA_KEY` | CA private key path |
| `CONTROL_GATEWAY_URL` | Gateway URL returned to agents during registration |
| `CONTROL_ADMIN_EMAIL` | Initial admin user email |
| `CONTROL_ADMIN_PASSWORD` | Initial admin user password |
| `CONTROL_DYNAMIC_GROUP_EVAL_INTERVAL` | Interval for evaluating queued dynamic groups (e.g., `30m`, `1h`, `4h`) |

## Setup

### Prerequisites

1. **PostgreSQL 18+** with the database created:
   ```bash
   createdb powermanage
   ```

2. **CA Certificate and Key** for signing agent certificates:
   ```bash
   # Generate CA key
   openssl genrsa -out ca.key 4096

   # Generate CA certificate
   openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
     -subj "/CN=Power Manage CA"
   ```

### Running Locally

```bash
# Run with environment variables
export CONTROL_DATABASE_URL="postgres://powermanage:powermanage@localhost:5432/powermanage?sslmode=disable"
export CONTROL_JWT_SECRET="your-secret-key"
export CONTROL_CA_CERT="./dev/certs/ca.crt"
export CONTROL_CA_KEY="./dev/certs/ca.key"
export CONTROL_GATEWAY_URL="https://gateway.example.com:8080"
export CONTROL_ADMIN_EMAIL="admin@localhost.com"
export CONTROL_ADMIN_PASSWORD="admin"

go run ./server/cmd/control
```

### Running with Podman Compose

```bash
# Start all services
podman-compose up -d

# Control server will be available at http://localhost:8081
```

## API Reference

The Control Server exposes a Connect-RPC API that can be consumed using:
- Connect protocol (HTTP/1.1 + HTTP/2)
- gRPC protocol
- gRPC-Web protocol

### Authentication

All endpoints except `Login` and `Register` require a JWT Bearer token:

```bash
# Login to get a token
curl -X POST http://localhost:8081/pm.v1.ControlService/Login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@localhost.com", "password": "administrator"}'

# Use the token for subsequent requests
curl http://localhost:8081/pm.v1.ControlService/ListUsers \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Endpoints

#### Authentication

| Method | Description |
|--------|-------------|
| `Login` | Authenticate with email/password, returns JWT tokens |
| `RefreshToken` | Exchange refresh token for new access token |
| `GetCurrentUser` | Get the currently authenticated user |
| `Register` | Register an agent device (token-based, no JWT required) |

#### Users

| Method | Description | Access |
|--------|-------------|--------|
| `CreateUser` | Create a new user | admin only |
| `GetUser` | Get user by ID | admin or self |
| `ListUsers` | List all users with pagination | admin only |
| `UpdateUserEmail` | Update a user's email | admin only |
| `UpdateUserPassword` | Update password | admin or self |
| `UpdateUserRole` | Change user role | admin only |
| `SetUserDisabled` | Enable/disable a user | admin only |
| `DeleteUser` | Delete a user | admin only |

#### Devices

| Method | Description | Access |
|--------|-------------|--------|
| `ListDevices` | List registered devices | admin or user (assigned only) |
| `GetDevice` | Get device by ID | admin or user (assigned only) |
| `SetDeviceLabel` | Set a label on a device | admin only |
| `RemoveDeviceLabel` | Remove a label from a device | admin only |
| `AssignDevice` | Assign device to a user | admin only |
| `UnassignDevice` | Remove device assignment | admin only |
| `DeleteDevice` | Delete a device | admin only |

#### Registration Tokens

Users can create one-time registration tokens for self-service device registration. User-created tokens are automatically one-time use with a maximum validity of 7 days. Devices registered with a user's token are automatically assigned to that user.

| Method | Description | Access |
|--------|-------------|--------|
| `CreateToken` | Create a registration token | admin or user |
| `GetToken` | Get token by ID | admin only |
| `ListTokens` | List tokens with pagination | admin only |
| `RenameToken` | Rename a token | admin only |
| `SetTokenDisabled` | Enable/disable a token | admin only |
| `DeleteToken` | Delete a token | admin only |

**Note:** User-created tokens are always one-time use and expire within 7 days. Admins have full control over token configuration.

#### Action Definitions

Reusable action templates that can be dispatched to devices.

| Method | Description | Access |
|--------|-------------|--------|
| `CreateDefinition` | Create an action definition | admin only |
| `GetDefinition` | Get definition by ID | admin or device |
| `ListDefinitions` | List definitions with filtering | admin or device |
| `RenameDefinition` | Rename a definition | admin only |
| `UpdateDefinitionDescription` | Update description | admin only |
| `DeleteDefinition` | Delete a definition | admin only |

#### Action Dispatch & Execution

| Method | Description | Access |
|--------|-------------|--------|
| `DispatchAction` | Dispatch action to a single device | admin only |
| `DispatchToMultiple` | Dispatch action to multiple devices | admin only |
| `GetExecution` | Get execution status by ID | admin or device (own) |
| `ListExecutions` | List executions with filtering | admin only |

## Action Types

The Control Server supports various action types:

| Type | Description |
|------|-------------|
| `PACKAGE` | Package management (apt/dnf/pacman) |
| `APP_IMAGE` | AppImage installation |
| `DEB` | Direct .deb package installation |
| `RPM` | Direct .rpm package installation |
| `SHELL` | Shell script execution |
| `SYSTEMD` | Systemd unit management |
| `FILE` | File management |

### Example: Dispatch a Package Installation

```bash
curl -X POST http://localhost:8081/pm.v1.ControlService/DispatchAction \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "01HWXYZ...",
    "inline_action": {
      "type": "ACTION_TYPE_PACKAGE",
      "desired_state": "DESIRED_STATE_PRESENT",
      "package": {
        "name": "htop"
      },
      "timeout_seconds": 300
    }
  }'
```

## Dynamic Device Groups

Device groups can be configured with dynamic membership rules. Instead of manually adding devices to a group, you can define a query that automatically includes devices matching certain label criteria.

### Query Language

The dynamic group query language uses a verbose, human-readable syntax similar to Microsoft's dynamic group rules. Queries evaluate device labels to determine membership.

#### Basic Syntax

```
(device.labels.<key> <operator> "<value>")
```

Or using the shorter form:

```
(labels.<key> <operator> "<value>")
```

#### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match (case-insensitive) | `device.labels.environment equals "production"` |
| `notEquals` | Does not match | `device.labels.environment notEquals "development"` |
| `contains` | Substring match | `device.labels.hostname contains "web"` |
| `notContains` | Does not contain substring | `device.labels.hostname notContains "test"` |
| `startsWith` | Starts with value | `device.labels.hostname startsWith "srv-"` |
| `endsWith` | Ends with value | `device.labels.hostname endsWith ".local"` |
| `greaterThan` | Numeric/string comparison | `device.labels.priority greaterThan "5"` |
| `lessThan` | Numeric/string comparison | `device.labels.priority lessThan "10"` |
| `greaterThanOrEquals` | Numeric/string comparison | `device.labels.version greaterThanOrEquals "2.0"` |
| `lessThanOrEquals` | Numeric/string comparison | `device.labels.version lessThanOrEquals "3.0"` |
| `exists` | Label key exists | `device.labels.managed exists` |
| `notExists` | Label key does not exist | `device.labels.deprecated notExists` |
| `in` | Value in comma-separated list | `device.labels.role in "web,api,worker"` |
| `notIn` | Value not in list | `device.labels.environment notIn "dev,test"` |

#### Logical Operators

Combine conditions using logical operators:

| Operator | Description |
|----------|-------------|
| `and` | Both conditions must be true |
| `or` | Either condition must be true |
| `not` | Negates the following condition |

#### Grouping with Parentheses

Use parentheses to group conditions and control evaluation order:

```
(device.labels.environment equals "production") and (device.labels.role equals "web")
```

### Examples

**All production servers:**
```
device.labels.environment equals "production"
```

**All web or API servers in production:**
```
(device.labels.environment equals "production") and (device.labels.role in "web,api")
```

**Servers with high priority that are not deprecated:**
```
(device.labels.priority greaterThan "5") and (device.labels.deprecated notExists)
```

**Linux servers in any environment except development:**
```
(device.labels.os equals "linux") and (device.labels.environment notEquals "development")
```

**Servers in the platform team's namespace:**
```
(device.labels.team equals "platform") or (device.labels.namespace startsWith "platform-")
```

**Complex query with multiple conditions:**
```
((device.labels.environment equals "production") or (device.labels.environment equals "staging")) and (device.labels.managed exists) and not (device.labels.maintenance equals "true")
```

### API Usage

#### Create a Dynamic Group

```bash
curl -X POST http://localhost:8081/pm.v1.ControlService/CreateDeviceGroup \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Web Servers",
    "description": "All web servers in production",
    "is_dynamic": true,
    "dynamic_query": "(device.labels.environment equals \"production\") and (device.labels.role equals \"web\")"
  }'
```

#### Validate a Query

Before creating a group, you can validate the query syntax:

```bash
curl -X POST http://localhost:8081/pm.v1.ControlService/ValidateDynamicQuery \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "(device.labels.environment equals \"production\")"
  }'
```

Response:
```json
{
  "valid": true,
  "error": "",
  "matching_device_count": 15
}
```

#### Update a Group's Query

```bash
curl -X POST http://localhost:8081/pm.v1.ControlService/UpdateDeviceGroupQuery \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "01HWXYZ...",
    "is_dynamic": true,
    "dynamic_query": "(device.labels.environment equals \"staging\")"
  }'
```

### Behavior

- **Automatic queueing**: When device labels change, dynamic groups are automatically queued for re-evaluation
- **Periodic evaluation**: Queued groups are evaluated at the configured interval (default: 1 hour, configurable via `CONTROL_DYNAMIC_GROUP_EVAL_INTERVAL`)
- **Manual members ignored**: Dynamic groups ignore manual add/remove member operations
- **Converting groups**: You can convert a static group to dynamic (and vice versa) using `UpdateDeviceGroupQuery`
- **Query validation**: Invalid queries are rejected at creation/update time with descriptive error messages

## Event Sourcing

All state changes are stored as immutable events in the `events` table:

| Stream Type | Events |
|-------------|--------|
| `user` | UserCreated, UserEmailChanged, UserPasswordChanged, UserRoleChanged, UserDisabled, UserEnabled, UserLoggedIn, UserDeleted |
| `device` | DeviceRegistered, DeviceHeartbeat, DeviceLabelSet, DeviceLabelRemoved, DeviceAssigned, DeviceUnassigned, DeviceDeleted |
| `token` | TokenCreated, TokenRenamed, TokenDisabled, TokenEnabled, TokenUsed, TokenDeleted |
| `definition` | DefinitionCreated, DefinitionRenamed, DefinitionDescriptionUpdated, DefinitionDeleted |
| `execution` | ExecutionCreated, ExecutionDispatched, ExecutionStarted, ExecutionCompleted, ExecutionFailed, ExecutionTimedOut |

### Querying Event History

```sql
-- View all events for a user
SELECT occurred_at, event_type, data, actor_type, actor_id
FROM events
WHERE stream_type = 'user' AND stream_id = 'USER_ID'
ORDER BY stream_version;

-- View all actions by a specific admin
SELECT * FROM events
WHERE actor_type = 'user' AND actor_id = 'ADMIN_ID'
ORDER BY occurred_at DESC;
```

### Time Travel

Query state at any point in time:

```sql
SELECT get_stream_at('device', 'DEVICE_ID', '2024-01-15 12:00:00+00');
```

### Rebuilding Projections

If projections need to be rebuilt:

```sql
-- Rebuild all projections
SELECT rebuild_all_projections();

-- Or rebuild individual projections
SELECT rebuild_users_projection();
SELECT rebuild_devices_projection();
```

## Health Check

The server exposes a health endpoint:

```bash
curl http://localhost:8081/health
# Returns: ok
```

## Security & Permissions

### Hybrid Authorization Model

The Control Server uses a **hybrid authorization model** combining:

1. **OPA (Open Policy Agent)** for action-level permissions
   - Determines if a user/device can call a specific API endpoint
   - Policies defined in `server/internal/auth/policies/authz.rego`

2. **PostgreSQL Row-Level Security (RLS)** for data-level filtering
   - Automatically filters query results based on user identity
   - Defense in depth - protects data even if application code has bugs

### Permission Matrix

| Resource | Admin | User | Device |
|----------|-------|------|--------|
| **Users** | Full access | Self only | None |
| **Devices** | Full access | Assigned only | Self only |
| **Tokens** | Full access | Create only | None |
| **Definitions** | Full access | None | Read only |
| **Executions** | Full access | None | Own only |

### Self-Service Device Registration

Users can register their own devices without admin involvement:

1. **Create a registration token** (user creates a one-time token, valid for max 7 days):
   ```bash
   curl -X POST http://localhost:8081/pm.v1.ControlService/CreateToken \
     -H "Authorization: Bearer <user_token>" \
     -H "Content-Type: application/json" \
     -d '{"name": "My Laptop"}'
   ```
   Response includes the token value (shown only once). Token is automatically one-time use and expires in 7 days.

2. **Register the device** using the `power-manage://` URI scheme:
   ```bash
   # Using URI (for desktop integration / clickable links)
   power-manage-agent 'power-manage://control.example.com:8081?token=abc123'

   # Or using traditional flags
   power-manage-agent -server=https://control.example.com:8081 -token=abc123
   ```

   The agent registers with the **Control Server**, which validates the token, signs the agent's certificate, and returns the gateway URL for streaming connections.

3. **Device is auto-assigned** to the token owner - the user can immediately see and manage their device.

4. **Agent connects to the Gateway** using the gateway URL and mTLS certificates received during registration.

#### URI Scheme Format

```
power-manage://server:port?token=xxx[&skip-verify=true][&tls=false]
```

| Parameter | Description |
|-----------|-------------|
| `server:port` | Control server address |
| `token` | Registration token (required) |
| `skip-verify` | Skip TLS verification (development only) |
| `tls=false` | Use HTTP instead of HTTPS |

### Device Assignment

Devices can be assigned to users, allowing users to view only their assigned devices:

```bash
# Assign a device to a user (admin only)
curl -X POST http://localhost:8081/pm.v1.ControlService/AssignDevice \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"device_id": "01HWXYZ...", "user_id": "01HWABC..."}'

# Unassign a device (admin only)
curl -X POST http://localhost:8081/pm.v1.ControlService/UnassignDevice \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"device_id": "01HWXYZ..."}'
```

### Row-Level Security Policies

RLS is enabled on all projection tables:

| Table | Policy |
|-------|--------|
| `users_projection` | Admin sees all; users see self only |
| `devices_projection` | Admin sees all; users see assigned; devices see self |
| `tokens_projection` | Admin only |
| `definitions_projection` | Admin and devices only |
| `executions_projection` | Admin sees all; devices see own |

### Security Best Practices

1. **JWT Secret**: Always set a strong `CONTROL_JWT_SECRET` in production
2. **Database**: Use SSL for PostgreSQL connections in production
3. **CA Key**: Protect the CA private key - it signs all agent certificates
4. **Admin Credentials**: Change default admin credentials immediately
5. **Network**: Consider running behind a reverse proxy with TLS termination
6. **RLS**: The database enforces permissions even if application code is compromised

## Development

### Building

```bash
go build -o control ./server/cmd/control
```

### Running Tests

```bash
go test ./server/...
```

### Database Migrations

Migrations are applied automatically on startup using Goose. Migration files are in `server/internal/store/migrations/`.
