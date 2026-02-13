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

	"github.com/manchtools/power-manage/server/internal/auth"
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

// AuthContext returns a context with the given user injected.
func AuthContext(id, email, role string) context.Context {
	return auth.WithUser(context.Background(), &auth.UserContext{
		ID:    id,
		Email: email,
		Role:  role,
	})
}

// AdminContext returns a context with an admin user.
func AdminContext(id string) context.Context {
	return AuthContext(id, fmt.Sprintf("admin-%s@test.com", id[:8]), "admin")
}

// UserContext returns a context with a regular user.
func UserContext(id string) context.Context {
	return AuthContext(id, fmt.Sprintf("user-%s@test.com", id[:8]), "user")
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
