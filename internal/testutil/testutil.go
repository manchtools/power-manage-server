// Package testutil provides shared test helpers for integration tests.
package testutil

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"golang.org/x/crypto/bcrypt"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/auth/totp"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
)

var entropy = ulid.Monotonic(rand.Reader, 0)

// precomputedHash is a bcrypt hash of "pass" computed once at init time.
// This avoids calling auth.HashPassword (bcrypt cost=14) for every test user,
// which would take ~1-2s per call and cause test timeouts.
var precomputedHash string

func init() {
	h, err := auth.HashPassword("pass")
	if err != nil {
		panic("testutil: precompute hash: " + err.Error())
	}
	precomputedHash = h
}

// NewID generates a unique ULID for test isolation.
func NewID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}

// SetupPostgres starts a PostgreSQL testcontainer and returns a connected Store.
// The container is stopped when the test completes.
func SetupPostgres(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase("power_manage_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { container.Terminate(context.Background()) })

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	st, err := store.New(ctx, connStr)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	return st
}

// CreateTestUser creates a user via events and returns the user ID.
func CreateTestUser(t *testing.T, st *store.Store, email, password, role string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	hash := precomputedHash
	if password != "pass" {
		var err error
		hash, err = auth.HashPassword(password)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
	}

	if err := st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   id,
		EventType:  "UserCreated",
		Data: map[string]any{
			"email":         email,
			"password_hash": hash,
			"role":          role,
		},
		ActorType: "system",
		ActorID:   "test",
	}); err != nil {
		t.Fatalf("create test user: %v", err)
	}

	return id
}

// CreateTestDevice creates a device via events and returns the device ID.
func CreateTestDevice(t *testing.T, st *store.Store, hostname string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   id,
		EventType:  "DeviceRegistered",
		Data: map[string]any{
			"hostname":      hostname,
			"agent_version": "1.0.0",
		},
		ActorType: "system",
		ActorID:   "test",
	})
	if err != nil {
		t.Fatalf("create test device: %v", err)
	}

	return id
}

// CreateTestAction creates an action via events and returns the action ID.
func CreateTestAction(t *testing.T, st *store.Store, actorID, name string, actionType int) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   id,
		EventType:  "ActionCreated",
		Data: map[string]any{
			"name":            name,
			"action_type":     actionType,
			"params":          map[string]any{},
			"timeout_seconds": 300,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test action: %v", err)
	}

	return id
}

// CreateTestActionSet creates an action set via events and returns the action set ID.
func CreateTestActionSet(t *testing.T, st *store.Store, actorID, name string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "action_set",
		StreamID:   id,
		EventType:  "ActionSetCreated",
		Data: map[string]any{
			"name": name,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test action set: %v", err)
	}

	return id
}

// CreateTestDefinition creates a definition via events and returns the definition ID.
func CreateTestDefinition(t *testing.T, st *store.Store, actorID, name string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "definition",
		StreamID:   id,
		EventType:  "DefinitionCreated",
		Data: map[string]any{
			"name": name,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test definition: %v", err)
	}

	return id
}

// CreateTestDeviceGroup creates a device group via events and returns the group ID.
func CreateTestDeviceGroup(t *testing.T, st *store.Store, actorID, name string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   id,
		EventType:  "DeviceGroupCreated",
		Data: map[string]any{
			"name":       name,
			"is_dynamic": false,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test device group: %v", err)
	}

	return id
}

// CreateTestToken creates a registration token via events and returns the token ID.
func CreateTestToken(t *testing.T, st *store.Store, actorID, name, valueHash string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   id,
		EventType:  "TokenCreated",
		Data: map[string]any{
			"name":       name,
			"value_hash": valueHash,
			"one_time":   false,
			"max_uses":   0,
			"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test token: %v", err)
	}

	return id
}

// AuthContext returns a context with the given user and permissions injected.
func AuthContext(id, email string, permissions []string) context.Context {
	return auth.WithUser(context.Background(), &auth.UserContext{
		ID:          id,
		Email:       email,
		Permissions: permissions,
	})
}

// AdminContext returns a context with an admin user (all permissions).
func AdminContext(id string) context.Context {
	return AuthContext(id, fmt.Sprintf("admin-%s@test.com", id[:8]), auth.AdminPermissions())
}

// UserContext returns a context with a regular user (default permissions).
func UserContext(id string) context.Context {
	return AuthContext(id, fmt.Sprintf("user-%s@test.com", id[:8]), auth.DefaultUserPermissions())
}

// SSOOnlyUserEvent returns a store.Event that creates a user without a password (SSO-only).
func SSOOnlyUserEvent(userID, email string) store.Event {
	return store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserCreated",
		Data: map[string]any{
			"email": email,
			"role":  "user",
		},
		ActorType: "system",
		ActorID:   "sso",
	}
}

// DisableEvent returns a store.Event that disables a user.
func DisableEvent(userID string) store.Event {
	return store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserDisabled",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	}
}

// NewJWTManager creates a JWTManager with test-friendly configuration.
func NewJWTManager() *auth.JWTManager {
	return auth.NewJWTManager(auth.JWTConfig{
		Secret:             []byte("test-secret-key-for-jwt-signing"),
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 1 * time.Hour,
		Issuer:             "power-manage-test",
	})
}

// CreateTestRole creates a role via events and returns the role ID.
func CreateTestRole(t *testing.T, st *store.Store, actorID, name string, permissions []string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "role",
		StreamID:   id,
		EventType:  "RoleCreated",
		Data: map[string]any{
			"name":        name,
			"description": "",
			"permissions": permissions,
			"is_system":   false,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test role: %v", err)
	}

	return id
}

// CreateTestUserGroup creates a user group via events and returns the group ID.
func CreateTestUserGroup(t *testing.T, st *store.Store, actorID, name string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   id,
		EventType:  "UserGroupCreated",
		Data: map[string]any{
			"name":        name,
			"description": "",
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test user group: %v", err)
	}

	return id
}

// AddUserToTestGroup adds a user to a user group via events.
func AddUserToTestGroup(t *testing.T, st *store.Store, actorID, groupID, userID string) {
	t.Helper()
	ctx := context.Background()

	streamID := groupID + ":" + userID
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   streamID,
		EventType:  "UserGroupMemberAdded",
		Data: map[string]any{
			"group_id": groupID,
			"user_id":  userID,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("add user to test group: %v", err)
	}
}

// AssignRoleToTestGroup assigns a role to a user group via events.
func AssignRoleToTestGroup(t *testing.T, st *store.Store, actorID, groupID, roleID string) {
	t.Helper()
	ctx := context.Background()

	streamID := groupID + ":role:" + roleID
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   streamID,
		EventType:  "UserGroupRoleAssigned",
		Data: map[string]any{
			"group_id": groupID,
			"role_id":  roleID,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("assign role to test group: %v", err)
	}
}

// AssignRoleToTestUser assigns a role to a user via events.
func AssignRoleToTestUser(t *testing.T, st *store.Store, actorID, userID, roleID string) {
	t.Helper()
	ctx := context.Background()

	streamID := userID + ":" + roleID
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   streamID,
		EventType:  "UserRoleAssigned",
		Data: map[string]any{
			"user_id": userID,
			"role_id": roleID,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("assign role to test user: %v", err)
	}
}

// AssignDeviceToUser assigns a device to a user via events.
func AssignDeviceToUser(t *testing.T, st *store.Store, actorID, deviceID, userID string) {
	t.Helper()
	ctx := context.Background()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceAssigned",
		Data: map[string]any{
			"user_id": userID,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("assign device to user: %v", err)
	}
}

// CreateTestAssignment creates an assignment via events and returns its ID.
func CreateTestAssignment(t *testing.T, st *store.Store, actorID, sourceType, sourceID, targetType, targetID string, mode int) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "assignment",
		StreamID:   id,
		EventType:  "AssignmentCreated",
		Data: map[string]any{
			"source_type": sourceType,
			"source_id":   sourceID,
			"target_type": targetType,
			"target_id":   targetID,
			"mode":        int32(mode),
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test assignment: %v", err)
	}

	return id
}

// NewEncryptor creates an Encryptor with a test key.
func NewEncryptor(t *testing.T) *crypto.Encryptor {
	t.Helper()
	// 32-byte hex key (64 hex chars)
	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("create test encryptor: %v", err)
	}
	return enc
}

// SetupTOTP enables TOTP for a user and returns the TOTP secret.
// It creates the TOTPSetupInitiated and TOTPVerified events.
func SetupTOTP(t *testing.T, st *store.Store, enc *crypto.Encryptor, userID, email string) string {
	t.Helper()
	ctx := context.Background()

	key, err := totp.GenerateKey("Test", email)
	if err != nil {
		t.Fatalf("generate TOTP key: %v", err)
	}

	encryptedSecret, err := enc.Encrypt(key.Secret())
	if err != nil {
		t.Fatalf("encrypt TOTP secret: %v", err)
	}

	// Generate backup codes
	_, hashes, err := totp.GenerateBackupCodes()
	if err != nil {
		t.Fatalf("generate backup codes: %v", err)
	}

	if err := st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPSetupInitiated",
		Data: map[string]any{
			"secret_encrypted":  encryptedSecret,
			"backup_codes_hash": hashes,
		},
		ActorType: "user",
		ActorID:   userID,
	}); err != nil {
		t.Fatalf("setup TOTP: %v", err)
	}

	if err := st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPVerified",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userID,
	}); err != nil {
		t.Fatalf("verify TOTP: %v", err)
	}

	return key.Secret()
}

// CreateTestIdentityProvider creates an identity provider via events and returns the provider ID.
func CreateTestIdentityProvider(t *testing.T, st *store.Store, enc *crypto.Encryptor, actorID, name, slug string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	encSecret, err := enc.Encrypt("test-client-secret")
	if err != nil {
		t.Fatalf("encrypt test secret: %v", err)
	}

	err = st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   id,
		EventType:  "IdentityProviderCreated",
		Data: map[string]any{
			"name":                    name,
			"slug":                    slug,
			"provider_type":           "oidc",
			"client_id":              "test-client-id",
			"client_secret_encrypted": encSecret,
			"issuer_url":             "https://idp.example.com",
			"scopes":                 []string{"openid", "profile", "email"},
			"auto_create_users":      false,
			"auto_link_by_email":     false,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test identity provider: %v", err)
	}

	return id
}

// CreateTestIdentityLink creates an identity link via events and returns the link ID.
func CreateTestIdentityLink(t *testing.T, st *store.Store, userID, providerID, externalID, externalEmail string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   id,
		EventType:  "IdentityLinked",
		Data: map[string]any{
			"user_id":        userID,
			"provider_id":    providerID,
			"external_id":    externalID,
			"external_email": externalEmail,
			"external_name":  "Test User",
		},
		ActorType: "system",
		ActorID:   "sso",
	})
	if err != nil {
		t.Fatalf("create test identity link: %v", err)
	}

	return id
}

// EnableSCIMForProvider enables SCIM on an identity provider and returns the plaintext bearer token.
func EnableSCIMForProvider(t *testing.T, st *store.Store, actorID, providerID string) string {
	t.Helper()
	ctx := context.Background()

	token := "scim-test-token-" + NewID()
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash SCIM token: %v", err)
	}

	err = st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   providerID,
		EventType:  "IdentityProviderSCIMEnabled",
		Data: map[string]any{
			"scim_token_hash": string(hash),
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("enable SCIM for provider: %v", err)
	}

	return token
}
