package testutil

// User / role / user-group fixtures + auth-context helpers + JWT
// manager. Everything tests need to put a user, group, role, and
// session into the projection layer for the rest of the suite to
// run RPC handlers against.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

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
		EventType:  string(eventtypes.UserCreatedWithRoles),
		Data: map[string]any{
			"email":         email,
			"password_hash": hash,
			"role":          role,
			"role_ids":      []string{},
		},
		ActorType: "system",
		ActorID:   "test",
	}); err != nil {
		t.Fatalf("create test user: %v", err)
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
		EventType:  string(eventtypes.UserCreatedWithRoles),
		Data: map[string]any{
			"email":    email,
			"role":     "user",
			"role_ids": []string{},
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
		EventType:  string(eventtypes.UserDisabled),
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
		EventType:  string(eventtypes.RoleCreated),
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
		EventType:  string(eventtypes.UserGroupCreated),
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
		EventType:  string(eventtypes.UserGroupMemberAdded),
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
		EventType:  string(eventtypes.UserGroupRoleAssigned),
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
		EventType:  string(eventtypes.UserRoleAssigned),
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
