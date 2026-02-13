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

## API Reference

The Control Server exposes a Connect-RPC API (`pm.v1.ControlService`) with 79 RPC methods. The Gateway Server exposes `pm.v1.AgentService` with 2 methods.

### Authentication (4 RPCs)

| Method | Description |
|--------|-------------|
| `Login` | Authenticate with email/password, returns JWT access + refresh tokens. Sets httpOnly cookies. |
| `RefreshToken` | Exchange refresh token for new token pair (with rotation). Reads from cookie or request body. |
| `Logout` | Revoke refresh token and clear cookies. |
| `GetCurrentUser` | Return the authenticated user's profile from JWT claims. |

### Users (9 RPCs)

| Method | Description |
|--------|-------------|
| `CreateUser` | Create user with email, password, and role (`admin` or `user`). Admin-only. |
| `GetUser` | Fetch user by ID. Users can view their own profile; admins can view any. |
| `ListUsers` | Paginated list of all users. Admin-only. |
| `UpdateUserEmail` | Change a user's email address. |
| `UpdateUserPassword` | Change password. Self-update requires current password; admins can reset without it. |
| `UpdateUserRole` | Promote/demote between `admin` and `user`. Admin-only. |
| `SetUserDisabled` | Enable or disable a user account. Admin-only. |
| `DeleteUser` | Soft-delete a user. Admin-only. |

### Devices (10 RPCs)

| Method | Description |
|--------|-------------|
| `ListDevices` | Paginated device list with optional status filter (online/offline). Users see only assigned devices. |
| `GetDevice` | Fetch device by ID. Online status based on 5-minute heartbeat threshold. |
| `SetDeviceLabel` | Add or update a key-value label on a device. |
| `RemoveDeviceLabel` | Remove a label by key. |
| `AssignDevice` | Assign a device to a user. Admin-only. |
| `UnassignDevice` | Remove device-user assignment. Admin-only. |
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

Manages action definitions. Supports 15 action types:

**Package management**: `PACKAGE`, `UPDATE`, `REPOSITORY`, `APP_IMAGE`, `DEB`, `RPM`, `FLATPAK`
**System**: `SHELL`, `SYSTEMD`, `FILE`, `DIRECTORY`, `REBOOT`, `SYNC`
**Identity**: `USER`, `GROUP`, `SSH`, `SSHD`, `SUDO`, `LPS`

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

### Device Groups (11 RPCs)

Static groups with manual membership or dynamic groups with a query language.

| Method | Description |
|--------|-------------|
| `CreateDeviceGroup` | Create a static or dynamic group. Dynamic groups use a query like `(device.labels.environment equals "production")`. |
| `GetDeviceGroup` | Fetch group with member device IDs. |
| `ListDeviceGroups` | Paginated list. |
| `RenameDeviceGroup` | Change name. |
| `UpdateDeviceGroupDescription` | Update description. |
| `UpdateDeviceGroupQuery` | Change the dynamic query expression. |
| `DeleteDeviceGroup` | Remove group. |
| `AddDeviceToGroup` | Add a device to a static group. |
| `RemoveDeviceFromGroup` | Remove a device from a group. |
| `ValidateDynamicQuery` | Validate query syntax and return matching device count. |
| `EvaluateDynamicGroup` | Manually trigger re-evaluation of dynamic group membership. |
| `SetDeviceGroupSyncInterval` | Set sync interval for all devices in the group. |

### Assignments (4 RPCs)

Link sources (actions, action sets, definitions) to targets (devices, device groups) with an assignment mode.

| Method | Description |
|--------|-------------|
| `CreateAssignment` | Create a source-to-target assignment. Modes: `REQUIRED` (always applied), `AVAILABLE` (user opt-in), `EXCLUDED`. Idempotent. |
| `DeleteAssignment` | Remove an assignment. |
| `ListAssignments` | Paginated list with optional filters. |
| `GetDeviceAssignments` | Resolve all effective actions for a device (expands groups, definitions, and sets). |

### User Selections (2 RPCs)

Allow users to opt in or out of `AVAILABLE`-mode assignments on their devices.

| Method | Description |
|--------|-------------|
| `SetUserSelection` | Accept or reject an available assignment for a device. |
| `ListAvailableActions` | List available-mode items for a device with current selection state. |

### Audit (1 RPC)

| Method | Description |
|--------|-------------|
| `ListAuditEvents` | Paginated event log. Filters: `actor_id`, `stream_type`, `event_type`. Returns raw event data from the event store. |

### Registration (1 RPC)

| Method | Description |
|--------|-------------|
| `Register` | Agent registration. Validates token (hash, expiry, disabled, max uses), signs agent CSR to issue mTLS client certificate, generates device ID, auto-assigns to token owner. Returns device ID, CA cert, signed cert, gateway URL. |

### Gateway — Agent Service (2 RPCs)

| Method | Description |
|--------|-------------|
| `Stream` | Bidirectional streaming. Agent sends Hello, then Heartbeat, ActionResult, OutputChunk, SecurityAlert. Server sends Welcome, ActionDispatch. |
| `SyncActions` | Agent pulls all assigned actions for offline storage. Returns effective sync interval. |

## Auth System

### JWT Tokens (`internal/auth/jwt.go`)

Access tokens (15 min) and refresh tokens (7 days) with HMAC-SHA256 signing. Refresh token rotation — each refresh revokes the old token and issues a new pair. Claims include user ID, email, role, session version, and a unique JTI (ULID). Revoked tokens tracked in PostgreSQL with automatic cleanup.

### OPA Authorization (`internal/auth/opa.go`)

Embedded Rego policies (`internal/auth/policies/authz.rego`) evaluate every RPC call. Rules:
- **Admins**: allowed for all actions
- **Users**: can view/update own profile, list devices (filtered by assignment), create tokens, view own executions
- **Devices**: can view own info, list definitions, view own executions

### Rate Limiting (`internal/auth/ratelimit.go`)

Sliding-window rate limiter keyed by IP address:
- Login: 10 attempts per 15 minutes
- RefreshToken: 30 attempts per 15 minutes
- Register: 10 attempts per 15 minutes

Background goroutine cleans up stale entries every 5 minutes.

### Cookies (`internal/auth/cookie.go`)

JWT tokens stored in httpOnly cookies (`pm_access`, `pm_refresh`) as a fallback to Authorization headers. Automatic secure mode detection via `Origin` header or `X-Forwarded-Proto`. HTTPS uses `SameSite=None; Secure`; HTTP uses `SameSite=Lax`.

### mTLS (`internal/ca/`)

Internal CA signs agent CSRs during registration. Certificates use CN={deviceID}, valid for 1 year (configurable). The Gateway validates client certificates and extracts device identity. Actions are also signed by the CA so agents can verify authenticity.

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

## Testing

The server has ~196 tests across 21 files covering auth, connection management, event store projections, all API handlers, and gateway message handling.

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
| `AdminContext(id)` | Returns a `context.Context` with an admin user injected. |
| `UserContext(id)` | Returns a `context.Context` with a regular user injected. |
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

#### API Handler Integration Tests (11 files, ~88 tests)

Each test spins up a PostgreSQL container and tests handler methods directly.

| File | Tests | What it covers |
|------|-------|----------------|
| `internal/api/validator_test.go` | 9 | Struct validation: required fields, email, ULID, min-length, optional fields, snake_case conversion |
| `internal/api/auth_handler_test.go` | 6 | Login (success, wrong password, nonexistent user, disabled user, cookie setting), GetCurrentUser |
| `internal/api/user_handler_test.go` | 12 | CreateUser (success, role required, unauthenticated), GetUser (found, not found), ListUsers pagination, UpdateEmail, UpdatePassword (self, wrong current, admin), UpdateRole, SetUserDisabled, DeleteUser |
| `internal/api/device_handler_test.go` | 11 | ListDevices (empty, with devices), GetDevice (found, not found), SetDeviceLabel, RemoveDeviceLabel, DeleteDevice, AssignDevice, UnassignDevice, SetDeviceSyncInterval |
| `internal/api/token_handler_test.go` | 7 | CreateToken (admin, user one-time), GetToken (value hidden), ListTokens, RenameToken, SetTokenDisabled, DeleteToken |
| `internal/api/action_handler_test.go` | 12 | CreateAction (shell, default timeout), GetAction (found, not found), ListActions, RenameAction, DeleteAction, DispatchAction (by ID, device not found), ListExecutions, GetExecution, DispatchInstantAction |
| `internal/api/action_set_handler_test.go` | 8 | CreateActionSet, GetActionSet, ListActionSets, RenameActionSet, DeleteActionSet, AddActionToSet, RemoveActionFromSet, ReorderActionInSet |
| `internal/api/definition_handler_test.go` | 6 | CreateDefinition, GetDefinition, ListDefinitions, RenameDefinition, DeleteDefinition, AddActionSetToDefinition |
| `internal/api/device_group_handler_test.go` | 10 | CreateDeviceGroup (static), GetDeviceGroup (found, not found), ListDeviceGroups, RenameDeviceGroup, DeleteDeviceGroup, AddDeviceToGroup, RemoveDeviceFromGroup, SetDeviceGroupSyncInterval, ValidateDynamicQuery |
| `internal/api/assignment_handler_test.go` | 6 | CreateAssignment (action→device, set→group, idempotent), DeleteAssignment, ListAssignments, GetDeviceAssignments |
| `internal/api/audit_handler_test.go` | 4 | ListAuditEvents, filter by stream_type, filter by event_type, pagination |

#### Gateway Handler Tests (1 file, ~11 tests)

| File | Tests | What it covers |
|------|-------|----------------|
| `internal/handler/agent_test.go` | ~11 | SyncActions (empty, with assigned actions, missing device ID), handleAgentMessage (heartbeat, action result success/failed, agent-scheduled action, security alert, output chunk), DeviceIDFromContext (present, absent) |

## License

AGPL-3.0 — see [LICENSE](LICENSE).
