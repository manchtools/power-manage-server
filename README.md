# Power Manage Server

The server side of Power Manage, providing the API, web UI, agent registration, and real-time agent communication. It consists of two binaries:

- **[Control Server](cmd/control/)** — API for the web UI, user management, agent registration (token validation + certificate signing), PostgreSQL event store
- **[Gateway Server](cmd/gateway/)** — Bidirectional streaming endpoint for agents, dispatches actions in real time (stateless, no database)
- **[Indexer](cmd/indexer/)** — Full-text search indexer, reads from PostgreSQL and writes to Valkey RediSearch

## Architecture

```
                          ┌──────────────────────┐
    Web UI / CLI ────────▶│   Control Server     │
    (JWT auth)            │   :8081              │
                          │                      │
                          │  - Connect-RPC API   │
                          │  - Agent registration │
                          │  - Certificate signing│
                          │  - InternalService   │
                          └───┬──────────────┬───┘
                              │              │
                              ▼              ▼
                   ┌──────────────┐  ┌──────────────┐
                   │  PostgreSQL  │  │    Valkey     │
                   │              │  │              │
                   │ - Event store│  │ - Asynq tasks│
                   │ - Projections│  │ - device:*   │
                   └──────┬───────┘  │ - control:*  │
                          │          │ - search idx │
                          ▼          └──┬────────┬──┘
                   ┌──────────────┐     │        │
                   │   Indexer    │─────┘        │
                   │  (search)   │              │
                   └──────────────┘              ▼
                          ┌──────────────────────┐
    Agents ──────────────▶│   Gateway Server     │
    (mTLS)                │   :8080              │
                          │                      │
                          │  - Streaming RPC     │
                          │  - Asynq workers     │
                          │  - Connect-RPC proxy │
                          └──────────────────────┘
```

## Event Sourcing

All state changes are recorded as immutable events in a single `events` table. PostgreSQL trigger functions project events into read-optimized `*_projection` tables automatically. Queries read from projections, never from the event store directly.

Inter-service communication uses **Asynq** (Valkey-backed task queue) — when the Control Server dispatches an action, it enqueues an Asynq task to the device's queue (`device:<id>`). The Gateway runs per-device Asynq workers that pick up tasks and stream them to connected agents. Agent responses flow back via the `control:inbox` queue. Credential-bearing operations (LUKS keys, LPS passwords) are proxied via Connect-RPC (`InternalService`) to avoid plaintext secrets in the queue.

See the [Control Server README](cmd/control/) for details on the event model, API endpoints, and authorization policies.

## Internal Packages

| Package | Purpose |
|---------|---------|
| `internal/api` | Control Server RPC handlers (actions, devices, users, tokens, assignments, roles, user groups, identity providers, SCIM, TOTP, compliance, etc.) |
| `internal/auth` | JWT authentication, OPA authorization, TOTP 2FA, rate limiting, cookie management, self-scope enforcement |
| `internal/ca` | Internal CA for signing agent certificates, certificate renewal verification, action payloads, and CA rotation via trust bundles |
| `internal/config` | Configuration loading (gateway) |
| `internal/connection` | Gateway connection manager — tracks connected agents, routes messages |
| `internal/control` | Asynq inbox worker — processes gateway-to-control task queue (`control:inbox`) |
| `internal/crypto` | AES-GCM encryption for secrets (identity provider client secrets, LUKS keys, LPS passwords) |
| `internal/gateway` | Per-device Asynq workers and task handlers for control-to-gateway dispatch |
| `internal/handler` | Gateway RPC handlers (agent streaming, Connect-RPC proxy to control) |
| `internal/idp` | OIDC identity provider SSO (authorization code flow, token exchange, user linking) |
| `internal/middleware` | HTTP middleware (request ID injection, security headers, logging) |
| `internal/mtls` | mTLS setup (`RequireAndVerifyClientCert`, TLS 1.3), extracts device identity from client certificates |
| `internal/resolution` | Assignment resolution engine (user/user_group/device/device_group targets) |
| `internal/scim` | SCIM v2 provisioning server (REST endpoints for user/group sync from external IdPs) |
| `internal/search` | Full-text search indexer using Valkey RediSearch — FT index management, Asynq reindex workers, cascade updates |
| `internal/store` | PostgreSQL event store, migrations, sqlc queries |
| `internal/taskqueue` | Asynq task queue client, task type constants, payload structs |
| `internal/testutil` | Test helpers — PostgreSQL testcontainers, test entity factories, auth context injection |

## API Reference

The Control Server exposes a Connect-RPC API (`pm.v1.ControlService`) with 136 RPC methods. The Gateway Server exposes `pm.v1.AgentService` with 3 methods.

### Authentication (4 RPCs)

| Method | Description |
|--------|-------------|
| `Login` | Authenticate with email/password, returns JWT access + refresh tokens. Sets httpOnly cookies. |
| `RefreshToken` | Exchange refresh token for new token pair (with rotation). Reads from cookie or request body. |
| `Logout` | Revoke refresh token and clear cookies. |
| `GetCurrentUser` | Return the authenticated user's profile from JWT claims. |

### Users (8 RPCs)

| Method | Description |
|--------|-------------|
| `CreateUser` | Create user with email and password. |
| `GetUser` | Fetch user by ID. Users with `GetUser:self` can view their own profile; `GetUser` grants access to any user. |
| `ListUsers` | Paginated list of all users. |
| `UpdateUserEmail` | Change a user's email address. Supports `:self` scoped permission. |
| `UpdateUserPassword` | Change password. Self-update requires current password; privileged users can reset without it. |
| `SetUserDisabled` | Enable or disable a user account. |
| `DeleteUser` | Soft-delete a user. |

### Devices (10 RPCs)

| Method | Description |
|--------|-------------|
| `ListDevices` | Paginated device list with optional status filter (online/offline). Supports `my_devices_only` flag for users to see only their assigned devices. |
| `GetDevice` | Fetch device by ID. Online status based on 5-minute heartbeat threshold. |
| `SetDeviceLabel` | Add or update a key-value label on a device. |
| `RemoveDeviceLabel` | Remove a label by key. |
| `AssignDevice` | Assign a device to one or more users. Devices support multi-user assignment. |
| `UnassignDevice` | Remove a specific user's assignment from a device. |
| `SetDeviceSyncInterval` | Configure how often the agent syncs (0-1440 minutes). |
| `DeleteDevice` | Remove a device. Admin-only. |
| `GetDeviceLpsPasswords` | Retrieve current and historical LPS (Local Password Solution) passwords. |

### Registration Tokens (6 RPCs)

| Method | Description |
|--------|-------------|
| `CreateToken` | Generate a 256-bit registration token (SHA256 hash stored). Admins configure one-time/reusable, max uses, expiry. Non-admins get one-time tokens with 7-day expiry. |
| `GetToken` | Fetch token metadata by ID (plaintext value never returned after creation). |
| `ListTokens` | Paginated list. Non-admins see only their own tokens. |
| `RenameToken` | Change token display name. |
| `SetTokenDisabled` | Enable or disable a token. |
| `DeleteToken` | Remove a token. |

### Actions (7 RPCs)

Manages action definitions. Supports 16 action types:

**Package management**: `PACKAGE`, `UPDATE`, `REPOSITORY`, `APP_IMAGE`, `DEB`, `RPM`, `FLATPAK`
**System**: `SHELL`, `SYSTEMD`, `FILE`, `DIRECTORY`
**Identity**: `USER`, `GROUP`, `SSH`, `SSHD`, `SUDO`, `LPS`
**Security**: `LUKS`

| Method | Description |
|--------|-------------|
| `CreateAction` | Create an action with type-specific parameters. Actions are signed by the CA for agent verification. |
| `GetAction` | Fetch action by ID. |
| `ListActions` | Paginated list with optional type filter. |
| `RenameAction` | Change action name. |
| `UpdateActionDescription` | Update action description text. |
| `UpdateActionParams` | Modify type-specific parameters. |
| `DeleteAction` | Remove an action. |

### Action Dispatch (9 RPCs)

| Method | Description |
|--------|-------------|
| `DispatchAction` | Send an action to a specific device. Creates an execution record. |
| `DispatchToMultiple` | Send an action to multiple devices at once. |
| `DispatchAssignedActions` | Trigger all assigned actions for a device. |
| `DispatchActionSet` | Dispatch all actions in a set to a device. |
| `DispatchDefinition` | Dispatch all action sets in a definition to a device. |
| `DispatchToGroup` | Dispatch an action to all devices in a group. |
| `DispatchInstantAction` | Dispatch an ephemeral action (e.g., reboot) without storing it. |
| `GetExecution` | Fetch execution status and results by ID. |
| `ListExecutions` | Paginated execution history with device/action filters. |

### Action Sets (8 RPCs)

Ordered collections of actions that can be dispatched together.

| Method | Description |
|--------|-------------|
| `CreateActionSet` | Create a named action set. |
| `GetActionSet` | Fetch set with its ordered member actions. |
| `ListActionSets` | Paginated list. |
| `RenameActionSet` | Change set name. |
| `UpdateActionSetDescription` | Update description. |
| `DeleteActionSet` | Remove set. |
| `AddActionToSet` | Add an action as a member. |
| `RemoveActionFromSet` | Remove a member action. |
| `ReorderActionInSet` | Change the sort order of a member. |

### Definitions (8 RPCs)

Ordered collections of action sets forming a complete configuration policy.

| Method | Description |
|--------|-------------|
| `CreateDefinition` | Create a named definition. |
| `GetDefinition` | Fetch definition with its ordered action sets. |
| `ListDefinitions` | Paginated list. |
| `RenameDefinition` | Change name. |
| `UpdateDefinitionDescription` | Update description. |
| `DeleteDefinition` | Remove definition. |
| `AddActionSetToDefinition` | Add an action set as a member. |
| `RemoveActionSetFromDefinition` | Remove a member. |
| `ReorderActionSetInDefinition` | Change sort order. |

### Device Groups (12 RPCs)

Static groups with manual membership or dynamic groups with a query language.

| Method | Description |
|--------|-------------|
| `CreateDeviceGroup` | Create a static or dynamic group. Dynamic groups use a query like `(device.labels.environment equals "production")`. |
| `GetDeviceGroup` | Fetch group with member device IDs. |
| `ListDeviceGroups` | Paginated list. |
| `ListDeviceGroupsForDevice` | List all groups a device belongs to (static and dynamic). |
| `RenameDeviceGroup` | Change name. |
| `UpdateDeviceGroupDescription` | Update description. |
| `UpdateDeviceGroupQuery` | Change the dynamic query expression. |
| `DeleteDeviceGroup` | Remove group. |
| `AddDeviceToGroup` | Add a device to a static group. |
| `RemoveDeviceFromGroup` | Remove a device from a group. |
| `ValidateDynamicQuery` | Validate query syntax and return matching device count. |
| `EvaluateDynamicGroup` | Manually trigger re-evaluation of dynamic group membership. |
| `SetDeviceGroupSyncInterval` | Set sync interval for all devices in the group. |

### Assignments (5 RPCs)

Link sources (actions, action sets, definitions, compliance policies) to targets (devices, device groups, users, user groups) with an assignment mode. Batch support: `CreateAssignment` and `DeleteAssignment` accept multiple assignments per call.

| Method | Description |
|--------|-------------|
| `CreateAssignment` | Create source-to-target assignments. Sources: action, action set, definition, compliance policy. Targets: device, device group, user, user group. Modes: `REQUIRED` (always applied), `AVAILABLE` (user opt-in), `EXCLUDED`. Supports batch (multiple assignments per request). Idempotent. |
| `DeleteAssignment` | Remove assignments. Supports batch. |
| `ListAssignments` | Paginated list with optional filters. |
| `GetDeviceAssignments` | Resolve all effective actions and compliance policies for a device (expands groups, definitions, sets, and user/user_group targets). |
| `GetUserAssignments` | Resolve all assignments targeting a user or their user groups. |

### User Selections (2 RPCs)

Allow users to opt in or out of `AVAILABLE`-mode assignments on their devices.

| Method | Description |
|--------|-------------|
| `SetUserSelection` | Accept or reject an available assignment for a device. |
| `ListAvailableActions` | List available-mode items for a device with current selection state. |

### TOTP Two-Factor Authentication (5 RPCs)

| Method | Description |
|--------|-------------|
| `SetupTOTP` | Generate TOTP secret and QR code URI for enrollment. |
| `VerifyTOTP` | Verify a TOTP code to complete 2FA enrollment. Returns backup codes. |
| `DisableTOTP` | Disable TOTP 2FA for a user. |
| `GetTOTPStatus` | Check whether TOTP is enabled for the current user. |
| `RegenerateBackupCodes` | Generate new backup codes (invalidates previous codes). |

### Roles (8 RPCs)

Dynamic role-based access control with per-permission granularity.

| Method | Description |
|--------|-------------|
| `CreateRole` | Create a custom role with a set of permissions. |
| `GetRole` | Fetch role by ID with its permission list. |
| `ListRoles` | Paginated list of all roles. |
| `UpdateRole` | Update role name, description, or permissions. |
| `DeleteRole` | Remove a role. |
| `AssignRoleToUser` | Assign a role to a user. |
| `RevokeRoleFromUser` | Revoke a role from a user. |
| `ListPermissions` | List all available permissions with descriptions. |

### User Groups (10 RPCs)

| Method | Description |
|--------|-------------|
| `CreateUserGroup` | Create a user group. |
| `GetUserGroup` | Fetch user group with members and roles. |
| `ListUserGroups` | Paginated list of all user groups. |
| `UpdateUserGroup` | Update user group name or description. |
| `DeleteUserGroup` | Remove a user group. |
| `AddUserToGroup` | Add a user to a group. |
| `RemoveUserFromGroup` | Remove a user from a group. |
| `AssignRoleToUserGroup` | Assign a role to a user group (all members inherit permissions). |
| `RevokeRoleFromUserGroup` | Revoke a role from a user group. |
| `ListUserGroupsForUser` | List all groups a user belongs to. |

### Identity Providers (8 RPCs)

OIDC identity provider management for SSO authentication.

| Method | Description |
|--------|-------------|
| `CreateIdentityProvider` | Create an OIDC identity provider (Google, Okta, Azure AD, etc.). |
| `GetIdentityProvider` | Fetch provider by ID. |
| `ListIdentityProviders` | Paginated list of configured providers. |
| `UpdateIdentityProvider` | Update provider settings (name, scopes, auto-create, group mapping, etc.). |
| `DeleteIdentityProvider` | Remove an identity provider. |
| `EnableSCIM` | Enable SCIM v2 provisioning for a provider. Returns bearer token and endpoint URL. |
| `DisableSCIM` | Disable SCIM provisioning for a provider. |
| `RotateSCIMToken` | Generate a new SCIM bearer token (invalidates the old one). |

### Identity Links (2 RPCs)

| Method | Description |
|--------|-------------|
| `ListIdentityLinks` | List the current user's linked external identities. |
| `UnlinkIdentity` | Remove a linked external identity. |

### Audit (1 RPC)

| Method | Description |
|--------|-------------|
| `ListAuditEvents` | Paginated event log. Filters: `actor_id`, `stream_type`, `event_type`. Returns raw event data from the event store. |

### Search (2 RPCs)

Server-side full-text search across actions, action sets, and definitions. Backed by Valkey RediSearch (`FT.CREATE`/`FT.SEARCH`). The search index is managed by the **Indexer** service (`cmd/indexer/`), which reads from PostgreSQL and writes to Valkey. Incremental updates are processed via Asynq workers after every mutation. A periodic reconciliation rebuild runs every hour to correct any drift. Supports server-side date and tag filtering.

Search uses prefix matching — the query `"ngi"` matches `"nginx"`, `"engine"`, etc. **Minimum query length is 2 characters** (RediSearch default `MINPREFIX 2`). Single-character queries return no results.

When `scope` is empty, results are returned from all three indexes (actions, action sets, definitions). When set to a specific scope, only that index is queried.

| Method | Description | Permission |
|--------|-------------|------------|
| `Search` | Full-text search across actions, action sets, and definitions. Supports scoped queries and pagination. | `Search` |
| `RebuildSearchIndex` | Force a full rebuild of the search index from PostgreSQL. Admin-only. | `RebuildSearchIndex` |

### Compliance Policies (11 RPCs)

| Method | Description |
|--------|-------------|
| `GetDeviceCompliance` | Returns compliance check results and overall status for a device. |
| `CreateCompliancePolicy` | Create a named compliance policy. |
| `GetCompliancePolicy` | Get a compliance policy by ID, including its rules. |
| `ListCompliancePolicies` | Paginated list of compliance policies. |
| `RenameCompliancePolicy` | Rename a compliance policy. |
| `UpdateCompliancePolicyDescription` | Update a compliance policy's description. |
| `DeleteCompliancePolicy` | Delete a compliance policy (soft delete). |
| `AddCompliancePolicyRule` | Add a compliance script action as a rule with a grace period. |
| `RemoveCompliancePolicyRule` | Remove a rule from a compliance policy. |
| `UpdateCompliancePolicyRule` | Update the grace period of an existing rule. |
| `GetDeviceCompliancePolicyStatus` | Get per-policy, per-rule compliance evaluation status for a device, including grace period state. |

### Registration & Certificates (2 RPCs)

| Method | Description |
|--------|-------------|
| `Register` | Agent registration. Validates token (hash, expiry, disabled, max uses), signs agent CSR to issue mTLS client certificate, generates device ID, auto-assigns to token owner. Returns device ID, CA cert, signed cert, gateway URL. |
| `RenewCertificate` | Certificate renewal. Agent presents its current (still valid) certificate and a new CSR. Server verifies the certificate was issued by the CA, checks the fingerprint matches the database, signs the new CSR, and emits a `DeviceCertRenewed` event. No JWT required. |

### Gateway — Agent Service (2 RPCs)

| Method | Description |
|--------|-------------|
| `Stream` | Bidirectional streaming. Agent sends Hello, Heartbeat, ActionResult, OutputChunk, LogQueryResult, SecurityAlert. Server sends Welcome, ActionDispatch, LogQuery. |
| `SyncActions` | Agent pulls all assigned actions for offline storage. Returns effective sync interval. |

## Auth System

### JWT Tokens (`internal/auth/jwt.go`)

Access tokens (15 min) and refresh tokens (7 days) with HMAC-SHA256 signing. Refresh token rotation — each refresh revokes the old token and issues a new pair. Claims include user ID, email, permissions, session version, and a unique JTI (ULID). Revoked tokens tracked in PostgreSQL with automatic cleanup.

### TOTP Two-Factor Authentication

Optional TOTP-based 2FA with HMAC-SHA1 (RFC 6238). Users enroll via `SetupTOTP`, verify with `VerifyTOTP`, and receive backup codes. TOTP verification is required at login when enabled. Backup codes are single-use and can be regenerated.

### SSO / OIDC Identity Providers (`internal/idp/`)

OIDC authorization code flow for external identity providers (Google, Okta, Azure AD, etc.). Features:
- Auto-create users on first SSO login (configurable per provider)
- Auto-link by email when existing user matches
- IdP group claim → user group mapping
- Optionally disable password authentication for SSO-linked users
- Multiple providers can be configured simultaneously
- Client-provided redirect URL support (enables non-browser OIDC flows, e.g. pm-enroll)
- Auto-delete orphaned users when an identity provider is deleted

### SCIM v2 Provisioning (`internal/scim/`)

REST API at `/scim/v2/{slug}/` for automated user and group provisioning from external IdPs. Bearer token authentication (per-provider, bcrypt-hashed). Supports Users (CRUD, filter by userName/externalId) and Groups (CRUD with member management).

### Dynamic RBAC (`internal/auth/permissions.go`)

Permission-based authorization replaces the old admin/user role model. Roles are custom collections of permissions. Users can have multiple roles (directly assigned or inherited via user groups). Permissions include scoped variants like `GetUser:self` and `ListDevices:assigned`.

### OPA Authorization (`internal/auth/opa.go`)

Embedded Rego policies (`internal/auth/policies/authz.rego`) evaluate every RPC call based on the user's effective permissions (union of all assigned roles).

### Rate Limiting (`internal/auth/ratelimit.go`)

Sliding-window rate limiter keyed by IP address:
- Login: 10 attempts per 15 minutes
- RefreshToken: 30 attempts per 15 minutes
- Register: 10 attempts per 15 minutes

Background goroutine cleans up stale entries every 5 minutes.

### Cookies (`internal/auth/cookie.go`)

JWT tokens stored in httpOnly cookies (`pm_access`, `pm_refresh`) as a fallback to Authorization headers. Automatic secure mode detection via `Origin` header or `X-Forwarded-Proto`. HTTPS uses `SameSite=None; Secure`; HTTP uses `SameSite=Lax`.

### mTLS (`internal/ca/`)

Internal CA signs agent CSRs during registration. Certificates use CN={deviceID}, valid for 1 year (configurable). The Gateway validates client certificates using `RequireAndVerifyClientCert` (TLS 1.3 minimum) and extracts device identity. Actions are also signed by the CA so agents can verify authenticity.

Certificate renewal is handled via the `RenewCertificate` RPC — agents present their current certificate and a new CSR. The server verifies the certificate was issued by a trusted CA (from the trust bundle if configured), checks the fingerprint matches the database record (preventing use of revoked certificates), signs the new CSR, and returns the active CA certificate so agents can update their trust store during CA rotation.

### Self-Scope Enforcement (`internal/auth/context.go`)

RPCs with `:self` scoped permissions (e.g., `GetUser:self`, `UpdateUserEmail:self`) enforce that the resource ID matches the caller's user ID. The `auth.EnforceSelfScope()` helper is called in each affected handler after validation. Users with the unrestricted permission (e.g., `GetUser`) can access any resource.

### HTTP Server Hardening

The Control Server sets `IdleTimeout` (120s) and `ReadHeaderTimeout` (10s) on the HTTP server to prevent connection exhaustion attacks.

## Database

- **Migrations**: `internal/store/migrations/` (Goose, embedded at compile time)
- **Queries**: `internal/store/queries/*.sql` (sqlc annotations)
- **Generated code**: `internal/store/generated/` (do not edit — run `sqlc generate` in `internal/store/`)
- **Config**: `internal/store/sqlc.yaml` (pgx/v5 driver)

## Building

```bash
# All binaries
CGO_ENABLED=0 go build -ldflags="-s -w" -o control ./cmd/control
CGO_ENABLED=0 go build -ldflags="-s -w" -o gateway ./cmd/gateway
CGO_ENABLED=0 go build -ldflags="-s -w" -o indexer ./cmd/indexer

# With version injection
CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=2026.3.0" -o control ./cmd/control
CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=2026.3.0" -o gateway ./cmd/gateway
```

## Running Locally

Requires a running PostgreSQL and Valkey instance. See the [self-hosting guide](../docs/self-hosting.md) for Docker/Podman Compose deployment.

```bash
# Control server
./control \
  -addr=:8081 \
  -db="postgres://user:pass@localhost:5432/powermanage?sslmode=disable" \
  -jwt-secret="$(openssl rand -base64 48)" \
  -ca-cert=certs/ca.crt \
  -ca-key=certs/ca.key \
  -gateway-url=http://localhost:8080

# Gateway server (no database required, connects to Valkey and Control)
export VALKEY_ADDR=localhost:6379
export VALKEY_PASSWORD=your-valkey-password
export GATEWAY_CONTROL_URL=http://localhost:8081
./gateway -tls -tls-cert=certs/gateway.crt -tls-key=certs/gateway.key -tls-ca=certs/ca.crt
```

## Regenerating Code

```bash
# After editing SQL queries
cd internal/store && sqlc generate

# After editing proto definitions (in the SDK repo)
cd ../../sdk && make generate
```

## Testing

The server has ~328 tests across 29 files covering auth, connection management, event store projections, all API handlers, SCIM provisioning, and gateway message handling.

### Running Tests

```bash
# Unit tests only (no Docker/Podman required, ~8s)
go test ./internal/auth/... ./internal/connection/...

# Integration tests (requires Docker or Podman, ~15 min total)
go test -timeout 20m ./internal/store/... ./internal/api/... ./internal/handler/...

# Full suite
go test -timeout 20m ./...
```

**Podman users**: testcontainers-go expects a Docker socket. Set these environment variables:

```bash
export DOCKER_HOST=unix:///run/user/1000/podman/podman.sock
export TESTCONTAINERS_RYUK_DISABLED=true
```

### Test Architecture

Integration tests use [testcontainers-go](https://golang.testcontainers.org/) to spin up a real PostgreSQL 17 container per test. This validates the full event-sourcing pipeline — events are appended, PostgreSQL triggers fire, projections are populated, and queries return the correct data. Each test gets an isolated container that is automatically torn down via `t.Cleanup()`.

Tests create entities directly via `store.AppendEvent()` rather than through handlers, ensuring each test is isolated to the layer it's testing. Auth context is injected via `auth.WithUser(ctx, ...)` to bypass interceptors (which are tested separately).

Test isolation relies on unique ULIDs — every test entity gets a unique ID, so tests sharing a database never interfere with each other.

### Test Infrastructure (`internal/testutil/`)

The `testutil` package provides shared helpers used across all integration tests:

| Helper | Description |
|--------|-------------|
| `SetupPostgres(t)` | Starts a PostgreSQL testcontainer, runs Goose migrations, returns a connected `*store.Store`. |
| `NewID()` | Generates a unique ULID for test isolation. |
| `CreateTestUser(t, st, email, password, role)` | Creates a user via `UserCreated` event. Uses a precomputed bcrypt hash for the default password `"pass"` to avoid ~1-2s bcrypt cost per test. |
| `CreateTestDevice(t, st, hostname)` | Creates a device via `DeviceRegistered` event. |
| `CreateTestAction(t, st, actorID, name, actionType)` | Creates an action via `ActionCreated` event. |
| `CreateTestActionSet(t, st, actorID, name)` | Creates an action set via `ActionSetCreated` event. |
| `CreateTestDefinition(t, st, actorID, name)` | Creates a definition via `DefinitionCreated` event. |
| `CreateTestDeviceGroup(t, st, actorID, name)` | Creates a device group via `DeviceGroupCreated` event. |
| `CreateTestToken(t, st, actorID, name, hash)` | Creates a registration token via `TokenCreated` event. |
| `CreateTestRole(t, st, actorID, name, perms)` | Creates a role via `RoleCreated` event. |
| `CreateTestUserGroup(t, st, actorID, name)` | Creates a user group via `UserGroupCreated` event. |
| `CreateTestIdentityProvider(t, st, enc, actorID, name, slug)` | Creates an identity provider via `IdentityProviderCreated` event. |
| `CreateTestIdentityLink(t, st, actorID, userID, providerID, externalID)` | Creates an identity link via `IdentityLinked` event. |
| `EnableSCIMForProvider(t, st, actorID, providerID)` | Enables SCIM for a provider via `IdentityProviderSCIMEnabled` event. Returns the plaintext token. |
| `NewEncryptor(t)` | Creates a test AES-GCM encryptor. |
| `AdminContext(id)` | Returns a `context.Context` with an admin user injected (all permissions). |
| `UserContext(id)` | Returns a `context.Context` with a regular user injected (default user permissions). |
| `DisableEvent(userID)` | Returns a `UserDisabled` event for use with `AppendEvent`. |
| `NewJWTManager()` | Creates a `JWTManager` with test-friendly configuration (15 min access, 1 hr refresh). |

### Test Files

#### Auth Unit Tests (7 files, ~79 tests)

No database required. Test pure Go logic.

| File | Tests | What it covers |
|------|-------|----------------|
| `internal/auth/jwt_test.go` | 14 | Token generation, validation (valid/expired/wrong-type/wrong-secret), refresh with rotation, revocation, unique JTIs |
| `internal/auth/password_test.go` | 6 | bcrypt hashing, verification (correct/wrong/empty), unique salts, dummy hash for timing attack prevention |
| `internal/auth/ratelimit_test.go` | 5 | Allow within limit, block after limit, independent keys, window expiry, 200-goroutine concurrent access |
| `internal/auth/cookie_test.go` | 10 | Set/clear cookies (secure/insecure), parse Cookie header, detect HTTPS via Origin and X-Forwarded-Proto |
| `internal/auth/context_test.go` | 9 | User/device context storage and retrieval, SubjectFromContext precedence |
| `internal/auth/opa_test.go` | 17 | Admin allows all 18 actions, user self-access vs. other-access, user denied admin actions, device own-resource vs. other |
| `internal/auth/interceptor_test.go` | 8 | Public procedure list (Login, RefreshToken, Logout, Register), non-public procedures, interceptor creation, streaming passthrough |

#### Connection Manager Unit Tests (1 file, 14 tests)

| File | Tests | What it covers |
|------|-------|----------------|
| `internal/connection/manager_test.go` | 14 | Register/Get, replace existing connection, unregister, count, list, IsConnected, UpdateLastSeen, Send to disconnected agent, context cancellation, 100-goroutine concurrent access |

#### Store Integration Tests (1 file, ~31 tests)

| File | Tests | What it covers |
|------|-------|----------------|
| `internal/store/store_test.go` | ~31 | AppendEvent basics, auto-versioning (5 events), explicit version conflict, WithTx commit/rollback, Notify. Projection tests: UserCreated/EmailChanged/Disabled/Enabled/Deleted, DeviceRegistered/Heartbeat/LabelSet, ActionCreated, ActionSetWithMembers, DefinitionCreated, DeviceGroupCreated, TokenCreated, ExecutionLifecycle (created → dispatched → completed), AssignmentCreated |

#### API Handler Integration Tests (18 files, ~178 tests)

Each test spins up a PostgreSQL container and tests handler methods directly.

| File | Tests | What it covers |
|------|-------|----------------|
| `internal/api/validator_test.go` | 9 | Struct validation: required fields, email, ULID, min-length, optional fields, snake_case conversion |
| `internal/api/auth_handler_test.go` | 15 | Login (success, wrong password, nonexistent user, disabled user, cookie setting, TOTP verification), GetCurrentUser, SSO callback |
| `internal/api/user_handler_test.go` | 11 | CreateUser, GetUser (found, not found), ListUsers pagination, UpdateEmail, UpdatePassword (self, wrong current, privileged), SetUserDisabled, DeleteUser |
| `internal/api/device_handler_test.go` | 10 | ListDevices (empty, with devices), GetDevice (found, not found), SetDeviceLabel, RemoveDeviceLabel, DeleteDevice, AssignDevice, UnassignDevice, SetDeviceSyncInterval |
| `internal/api/token_handler_test.go` | 7 | CreateToken (admin, user one-time), GetToken (value hidden), ListTokens, RenameToken, SetTokenDisabled, DeleteToken |
| `internal/api/action_handler_test.go` | 12 | CreateAction (shell, default timeout), GetAction (found, not found), ListActions, RenameAction, DeleteAction, DispatchAction (by ID, device not found), ListExecutions, GetExecution, DispatchInstantAction |
| `internal/api/action_set_handler_test.go` | 8 | CreateActionSet, GetActionSet, ListActionSets, RenameActionSet, DeleteActionSet, AddActionToSet, RemoveActionFromSet, ReorderActionInSet |
| `internal/api/definition_handler_test.go` | 6 | CreateDefinition, GetDefinition, ListDefinitions, RenameDefinition, DeleteDefinition, AddActionSetToDefinition |
| `internal/api/device_group_handler_test.go` | 10 | CreateDeviceGroup (static), GetDeviceGroup (found, not found), ListDeviceGroups, RenameDeviceGroup, DeleteDeviceGroup, AddDeviceToGroup, RemoveDeviceFromGroup, SetDeviceGroupSyncInterval, ValidateDynamicQuery |
| `internal/api/assignment_handler_test.go` | 10 | CreateAssignment (action→device, set→group, user target, user_group target, idempotent), DeleteAssignment, ListAssignments, GetDeviceAssignments, GetUserAssignments |
| `internal/api/audit_handler_test.go` | 4 | ListAuditEvents, filter by stream_type, filter by event_type, pagination |
| `internal/api/totp_handler_test.go` | 14 | SetupTOTP, VerifyTOTP (valid/invalid/replay), DisableTOTP, GetTOTPStatus, RegenerateBackupCodes, backup code login |
| `internal/api/user_group_handler_test.go` | 20 | CreateUserGroup, GetUserGroup, ListUserGroups, UpdateUserGroup, DeleteUserGroup, AddUserToGroup, RemoveUserFromGroup, AssignRoleToUserGroup, RevokeRoleFromUserGroup, ListUserGroupsForUser, additive permissions |
| `internal/api/idp_handler_test.go` | 15 | CreateIdentityProvider (success, duplicate slug, group mapping), Get/List/Update/Delete IDP, EnableSCIM (success, already enabled), DisableSCIM (success, not enabled), RotateSCIMToken (success, not enabled) |
| `internal/api/sso_handler_test.go` | 6 | SSO authorization URL generation, callback handling, identity linking |
| `internal/api/identity_link_handler_test.go` | 6 | ListIdentityLinks, UnlinkIdentity |
| `internal/api/luks_action_test.go` | 7 | LUKS key management actions |
| `internal/api/osquery_handler_test.go` | 11 | OSQuery dispatch, result retrieval, device inventory |

#### SCIM Integration Tests (1 file, 21 tests)

| File | Tests | What it covers |
|------|-------|----------------|
| `internal/scim/handler_test.go` | 21 | Auth (missing/invalid/non-existent/valid token), Discovery (ServiceProviderConfig, Schemas, ResourceTypes), Users (create, get, list, filter, replace, patch deactivate, delete), Groups (create, get, list, patch add member, replace members, delete) |

#### Gateway Handler Tests (1 file, ~3 tests)

| File | Tests | What it covers |
|------|-------|----------------|
| `internal/handler/agent_test.go` | ~3 | SyncActions (missing device ID), DeviceIDFromContext (present, absent) |

## Dynamic Device Groups

Dynamic device groups use a query language to automatically evaluate device membership based on device properties. Membership is re-evaluated whenever a device's inventory or labels change.

### Supported Properties

**Label properties** — custom key-value labels assigned to devices:

```
device.labels.<key>    e.g., device.labels.environment
labels.<key>           e.g., labels.role  (shorthand)
```

**Device properties** — available immediately from registration:

| Property | Description | Example Value |
|----------|-------------|---------------|
| `device.hostname` | Device hostname | `web-server-01` |

**Inventory properties** — hardware and OS information collected by the agent via OSQuery. These fields are only available after the agent has connected and sent its first inventory report (typically within seconds of first connection). Queries using these fields will not match devices that have not yet reported inventory.

| Property | Description | Example Value |
|----------|-------------|---------------|
| `device.os` | Operating system name | `Ubuntu`, `Fedora` |
| `device.os_version` | Full OS version string | `24.04`, `41` |
| `device.os_major` | OS major version number | `24`, `41` |
| `device.os_minor` | OS minor version number | `04`, `0` |
| `device.os_arch` | CPU architecture | `x86_64`, `aarch64` |
| `device.os_platform` | Platform family | `debian`, `rhel`, `arch` |
| `device.cpu_type` | CPU type | `GenuineIntel` |
| `device.cpu_brand` | CPU brand string | `Intel(R) Core(TM) i7-1265U` |
| `device.cpu_cores` | Physical CPU core count | `10` |
| `device.cpu_logical_cores` | Logical CPU core count | `12` |
| `device.memory_total` | Total memory in bytes | `17179869184` |
| `device.kernel` | Kernel version | `6.8.0-45-generic` |

### Supported Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match | `device.os equals "Ubuntu"` |
| `notEquals` | Not equal | `device.os notEquals "Windows"` |
| `contains` | Substring match | `device.hostname contains "web"` |
| `notContains` | No substring match | `device.hostname notContains "test"` |
| `startsWith` | Prefix match | `device.hostname startsWith "prod-"` |
| `endsWith` | Suffix match | `device.hostname endsWith ".local"` |
| `greaterThan` | Numeric greater than | `device.cpu_cores greaterThan "4"` |
| `lessThan` | Numeric less than | `device.memory_total lessThan "8589934592"` |
| `exists` | Property exists | `device.labels.environment exists` |
| `notExists` | Property does not exist | `device.labels.decommissioned notExists` |
| `in` | Value in list | `device.os in ("Ubuntu", "Fedora")` |
| `notIn` | Value not in list | `device.os_platform notIn ("arch", "gentoo")` |
| `matches` | Regex match | `device.hostname matches "^web-[0-9]+"` |
| `notMatches` | No regex match | `device.kernel notMatches "debug"` |

### Logic and Grouping

Conditions can be combined with logic operators and grouped with parentheses:

- **`AND`** — both conditions must be true
- **`OR`** — at least one condition must be true
- **`NOT`** — negates a condition
- **Parentheses** — control evaluation order

### Examples

```
# All Ubuntu devices
device.os equals "Ubuntu"

# 64-bit devices with at least 8 GB RAM
device.os_arch equals "x86_64" AND device.memory_total greaterThan "8589934592"

# Production devices on Debian or RHEL-based systems
device.labels.environment equals "production" AND device.os_platform in ("debian", "rhel")

# Fedora or Ubuntu devices with more than 4 CPU cores
(device.os equals "Fedora" OR device.os equals "Ubuntu") AND device.cpu_cores greaterThan "4"

# Devices without a decommissioned label
NOT device.labels.decommissioned exists
```

### Evaluation

Dynamic group membership is evaluated by PostgreSQL using the `evaluate_dynamic_query_v2()` function. The query is parsed into an expression tree of conditions, logical operators, and groups. Each condition is evaluated against the device's labels (stored in `devices_projection.labels`) and inventory data (collected by the agent via OSQuery and stored in `device_inventory`).

**Data availability by source:**

| Source | Available | Fields |
|--------|-----------|--------|
| Registration | Immediately | `device.hostname`, `device.labels.*` |
| Agent inventory (OSQuery) | After first connection | `device.os`, `device.os_version`, `device.os_arch`, `device.cpu_*`, `device.memory_total`, `device.kernel` |

The `ValidateDynamicQuery` RPC validates syntax and returns the number of currently matching devices. The `EvaluateDynamicGroup` RPC triggers a manual re-evaluation of membership.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
