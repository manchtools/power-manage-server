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
| `CONTROL_SCIM_BASE_URL` | Base URL for SCIM v2 endpoints (e.g., `https://control.example.com:8081`) |
| `CONTROL_ENCRYPTION_KEY` | AES-256 encryption key for identity provider client secrets (hex-encoded, 32 bytes) |

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

| Method | Description | Permission |
|--------|-------------|------------|
| `CreateUser` | Create a new user | `CreateUser` |
| `GetUser` | Get user by ID | `GetUser` or `GetUser:self` |
| `ListUsers` | List all users with pagination | `ListUsers` |
| `UpdateUserEmail` | Update a user's email | `UpdateUserEmail` or `UpdateUserEmail:self` |
| `UpdateUserPassword` | Update password | `UpdateUserPassword` or `UpdateUserPassword:self` |
| `SetUserDisabled` | Enable/disable a user | `SetUserDisabled` |
| `DeleteUser` | Delete a user | `DeleteUser` |

#### Devices

| Method | Description | Permission |
|--------|-------------|------------|
| `ListDevices` | List registered devices | `ListDevices` or `ListDevices:assigned` |
| `GetDevice` | Get device by ID | `GetDevice` or `GetDevice:assigned` |
| `SetDeviceLabel` | Set a label on a device | `SetDeviceLabel` |
| `RemoveDeviceLabel` | Remove a label from a device | `RemoveDeviceLabel` |
| `AssignDevice` | Assign device to a user | `AssignDevice` |
| `UnassignDevice` | Remove device assignment | `UnassignDevice` |
| `SetDeviceSyncInterval` | Set device sync interval | `SetDeviceSyncInterval` |
| `DeleteDevice` | Delete a device | `DeleteDevice` |

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

#### LUKS (Disk Encryption)

| Method | Description | Permission |
|--------|-------------|------------|
| `GetDeviceLuksKeys` | Get current and historical LUKS keys for a device | `GetDeviceLuksKeys` |
| `CreateLuksToken` | Create a one-time token for setting a user-defined passphrase | `CreateLuksToken` |
| `RevokeLuksDeviceKey` | Revoke the device-bound key in LUKS slot 7 | `RevokeLuksDeviceKey` |

#### TOTP Two-Factor Authentication

| Method | Description | Permission |
|--------|-------------|------------|
| `SetupTOTP` | Generate TOTP secret and QR code URI | `SetupTOTP` |
| `VerifyTOTP` | Verify TOTP code to complete enrollment, returns backup codes | `VerifyTOTP` |
| `DisableTOTP` | Disable TOTP 2FA | `DisableTOTP` |
| `GetTOTPStatus` | Check TOTP enrollment status | `GetTOTPStatus` |
| `RegenerateBackupCodes` | Generate new backup codes | `RegenerateBackupCodes` |

#### Roles

| Method | Description | Permission |
|--------|-------------|------------|
| `CreateRole` | Create a custom role with permissions | `CreateRole` |
| `GetRole` | Fetch role by ID | `GetRole` |
| `ListRoles` | List all roles | `ListRoles` |
| `UpdateRole` | Update role name, description, or permissions | `UpdateRole` |
| `DeleteRole` | Delete a role | `DeleteRole` |
| `AssignRoleToUser` | Assign a role to a user | `AssignRoleToUser` |
| `RevokeRoleFromUser` | Revoke a role from a user | `RevokeRoleFromUser` |
| `ListPermissions` | List all available permissions | `ListPermissions` |

#### User Groups

| Method | Description | Permission |
|--------|-------------|------------|
| `CreateUserGroup` | Create a user group | `CreateUserGroup` |
| `GetUserGroup` | Fetch group with members and roles | `GetUserGroup` |
| `ListUserGroups` | List all user groups | `ListUserGroups` |
| `UpdateUserGroup` | Update group name or description | `UpdateUserGroup` |
| `DeleteUserGroup` | Delete a user group | `DeleteUserGroup` |
| `AddUserToGroup` | Add a user to a group | `AddUserToGroup` |
| `RemoveUserFromGroup` | Remove a user from a group | `RemoveUserFromGroup` |
| `AssignRoleToUserGroup` | Assign a role to a group (all members inherit) | `AssignRoleToUserGroup` |
| `RevokeRoleFromUserGroup` | Revoke a role from a group | `RevokeRoleFromUserGroup` |
| `ListUserGroupsForUser` | List groups a user belongs to | `ListUserGroupsForUser` |

#### Identity Providers (SSO)

| Method | Description | Permission |
|--------|-------------|------------|
| `CreateIdentityProvider` | Create OIDC identity provider | `CreateIdentityProvider` |
| `GetIdentityProvider` | Fetch provider by ID | `GetIdentityProvider` |
| `ListIdentityProviders` | List configured providers | `ListIdentityProviders` |
| `UpdateIdentityProvider` | Update provider settings | `UpdateIdentityProvider` |
| `DeleteIdentityProvider` | Delete an identity provider | `DeleteIdentityProvider` |
| `EnableSCIM` | Enable SCIM provisioning, returns bearer token | `EnableSCIM` |
| `DisableSCIM` | Disable SCIM provisioning | `DisableSCIM` |
| `RotateSCIMToken` | Rotate SCIM bearer token | `RotateSCIMToken` |

#### Identity Links

| Method | Description | Permission |
|--------|-------------|------------|
| `ListIdentityLinks` | List own linked external identities | `ListIdentityLinks` |
| `UnlinkIdentity` | Remove a linked identity | `UnlinkIdentity` |

#### SCIM v2 Provisioning (REST, not Connect-RPC)

SCIM endpoints are mounted at `/scim/v2/{provider-slug}/` and use Bearer token authentication (not JWT). They follow the SCIM v2 RFC 7643/7644 specification.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ServiceProviderConfig` | GET | SCIM service provider configuration |
| `/Schemas` | GET | Supported SCIM schemas |
| `/ResourceTypes` | GET | Available resource types |
| `/Users` | GET, POST | List/create users |
| `/Users/{id}` | GET, PUT, PATCH, DELETE | Get/replace/patch/delete user |
| `/Groups` | GET, POST | List/create groups |
| `/Groups/{id}` | GET, PUT, PATCH, DELETE | Get/replace/patch/delete group |

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
| `LUKS` | LUKS disk encryption management |

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
| `user` | UserCreated, UserEmailChanged, UserPasswordChanged, UserDisabled, UserEnabled, UserLoggedIn, UserDeleted, UserTOTPEnabled, UserTOTPDisabled, UserBackupCodesRegenerated, IdentityLinked, IdentityUnlinked |
| `device` | DeviceRegistered, DeviceHeartbeat, DeviceLabelSet, DeviceLabelRemoved, DeviceAssigned, DeviceUnassigned, DeviceDeleted |
| `token` | TokenCreated, TokenRenamed, TokenDisabled, TokenEnabled, TokenUsed, TokenDeleted |
| `definition` | DefinitionCreated, DefinitionRenamed, DefinitionDescriptionUpdated, DefinitionDeleted |
| `execution` | ExecutionCreated, ExecutionDispatched, ExecutionStarted, ExecutionCompleted, ExecutionFailed, ExecutionTimedOut |
| `luks_key` | LuksKeyRotated, LuksDeviceKeyRevoked, LuksDeviceKeyRevocationFailed, LuksDeviceKeyRevocationDispatched |
| `role` | RoleCreated, RoleUpdated, RoleDeleted, RoleAssignedToUser, RoleRevokedFromUser |
| `user_group` | UserGroupCreated, UserGroupUpdated, UserGroupDeleted, UserGroupMemberAdded, UserGroupMemberRemoved, RoleAssignedToUserGroup, RoleRevokedFromUserGroup |
| `identity_provider` | IdentityProviderCreated, IdentityProviderUpdated, IdentityProviderDeleted, IdentityProviderSCIMEnabled, IdentityProviderSCIMDisabled, IdentityProviderSCIMTokenRotated |
| `scim_group_mapping` | SCIMGroupMapped, SCIMGroupUnmapped, SCIMGroupMappingUpdated |

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

### Dynamic RBAC Authorization Model

The Control Server uses **dynamic role-based access control** with:

1. **Custom Roles** — Administrators define roles as collections of permissions (e.g., "Help Desk" = `GetUser`, `SetUserDisabled`, `ListDevices`). Permissions support scoped variants like `GetUser:self` (own profile only) and `ListDevices:assigned` (assigned devices only).

2. **User Groups** — Users can be organized into groups. Roles assigned to a group are inherited by all members. Permissions are additive — a user's effective permissions are the union of all directly assigned roles and group-inherited roles.

3. **Built-in Roles** — `Admin` (all permissions) and `User` (self-service permissions) are created automatically but can be customized.

4. **OPA (Open Policy Agent)** for action-level permissions
   - Evaluates every RPC call against the user's effective permission set
   - Policies defined in `server/internal/auth/policies/authz.rego`

5. **PostgreSQL Row-Level Security (RLS)** for data-level filtering
   - Automatically filters query results based on user identity
   - Defense in depth - protects data even if application code has bugs

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
