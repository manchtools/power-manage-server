package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPermissionQuerier implements PermissionQuerier for testing.
type mockPermissionQuerier struct {
	permissions map[string][]string // userID -> permissions
	callCount   int
	err         error
}

func (m *mockPermissionQuerier) GetUserPermissions(_ context.Context, userID string) ([]string, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	return m.permissions[userID], nil
}

func TestPermissionResolver_LoadsFromDB(t *testing.T) {
	mock := &mockPermissionQuerier{
		permissions: map[string][]string{
			"user-1": {"CreateUser", "ListUsers"},
		},
	}
	resolver := NewPermissionResolver(mock)

	perms, err := resolver.UserPermissions(context.Background(), "user-1", 0)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"CreateUser", "ListUsers"}, perms)
	assert.Equal(t, 1, mock.callCount)
}

func TestPermissionResolver_CachesResult(t *testing.T) {
	mock := &mockPermissionQuerier{
		permissions: map[string][]string{
			"user-1": {"CreateUser"},
		},
	}
	resolver := NewPermissionResolver(mock)

	// First call — loads from DB
	perms, err := resolver.UserPermissions(context.Background(), "user-1", 0)
	require.NoError(t, err)
	assert.Len(t, perms, 1)
	assert.Equal(t, 1, mock.callCount)

	// Second call with same version — should use cache
	perms, err = resolver.UserPermissions(context.Background(), "user-1", 0)
	require.NoError(t, err)
	assert.Len(t, perms, 1)
	assert.Equal(t, 1, mock.callCount, "should not query DB again")
}

func TestPermissionResolver_VersionMismatchReloads(t *testing.T) {
	mock := &mockPermissionQuerier{
		permissions: map[string][]string{
			"user-1": {"CreateUser"},
		},
	}
	resolver := NewPermissionResolver(mock)

	// Load with version 0
	_, err := resolver.UserPermissions(context.Background(), "user-1", 0)
	require.NoError(t, err)
	assert.Equal(t, 1, mock.callCount)

	// Update mock to return different permissions
	mock.permissions["user-1"] = []string{"CreateUser", "DeleteUser"}

	// Call with version 1 — should reload
	perms, err := resolver.UserPermissions(context.Background(), "user-1", 1)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"CreateUser", "DeleteUser"}, perms)
	assert.Equal(t, 2, mock.callCount)
}

func TestPermissionResolver_DifferentUsers(t *testing.T) {
	mock := &mockPermissionQuerier{
		permissions: map[string][]string{
			"user-1": {"CreateUser"},
			"user-2": {"ListDevices"},
		},
	}
	resolver := NewPermissionResolver(mock)

	perms1, err := resolver.UserPermissions(context.Background(), "user-1", 0)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"CreateUser"}, perms1)

	perms2, err := resolver.UserPermissions(context.Background(), "user-2", 0)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"ListDevices"}, perms2)

	assert.Equal(t, 2, mock.callCount)
}

func TestPermissionResolver_InvalidateUser(t *testing.T) {
	mock := &mockPermissionQuerier{
		permissions: map[string][]string{
			"user-1": {"CreateUser"},
		},
	}
	resolver := NewPermissionResolver(mock)

	// Load and cache
	_, err := resolver.UserPermissions(context.Background(), "user-1", 0)
	require.NoError(t, err)
	assert.Equal(t, 1, mock.callCount)

	// Invalidate
	resolver.InvalidateUser("user-1")

	// Should reload from DB
	_, err = resolver.UserPermissions(context.Background(), "user-1", 0)
	require.NoError(t, err)
	assert.Equal(t, 2, mock.callCount)
}

func TestPermissionResolver_DBError(t *testing.T) {
	mock := &mockPermissionQuerier{
		err: errors.New("db connection failed"),
	}
	resolver := NewPermissionResolver(mock)

	_, err := resolver.UserPermissions(context.Background(), "user-1", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db connection failed")
}

func TestPermissionResolver_EmptyPermissions(t *testing.T) {
	mock := &mockPermissionQuerier{
		permissions: map[string][]string{
			"user-1": {},
		},
	}
	resolver := NewPermissionResolver(mock)

	perms, err := resolver.UserPermissions(context.Background(), "user-1", 0)
	require.NoError(t, err)
	assert.Empty(t, perms)
}

func TestPermissionResolver_UserNotFound(t *testing.T) {
	mock := &mockPermissionQuerier{
		permissions: map[string][]string{},
	}
	resolver := NewPermissionResolver(mock)

	perms, err := resolver.UserPermissions(context.Background(), "nonexistent", 0)
	require.NoError(t, err)
	assert.Nil(t, perms)
}

func TestNewQueriesAdapter(t *testing.T) {
	// Just verify the adapter can be created (nil is fine for type check)
	adapter := NewQueriesAdapter(nil)
	assert.NotNil(t, adapter)
}
