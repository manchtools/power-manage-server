package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAuthorizer(t *testing.T) *Authorizer {
	t.Helper()
	authz, err := NewAuthorizer()
	require.NoError(t, err)
	return authz
}

// ============================================================================
// Permission-based user access
// ============================================================================

func TestAuthorizer_UnrestrictedPermission(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Permissions: []string{"CreateUser", "ListUsers", "DeleteUser"},
		SubjectID:   "user-1",
		Action:      "CreateUser",
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestAuthorizer_UnrestrictedPermissionDenied(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Permissions: []string{"ListUsers"},
		SubjectID:   "user-1",
		Action:      "CreateUser",
	})
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_AdminPermissionsAllowAll(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	adminPerms := AdminPermissions()
	actions := []string{
		"CreateUser", "GetUser", "ListUsers", "DeleteUser",
		"ListDevices", "GetDevice", "DeleteDevice",
		"CreateToken", "DeleteToken",
		"CreateAction", "DispatchAction",
		"CreateDefinition", "DeleteDefinition",
		"CreateDeviceGroup", "DeleteDeviceGroup",
		"CreateAssignment", "DeleteAssignment",
		"ListAuditEvents",
		"CreateRole", "UpdateRole", "DeleteRole",
	}

	for _, action := range actions {
		allowed, err := authz.Authorize(ctx, AuthzInput{
			Permissions: adminPerms,
			SubjectID:   "admin-1",
			Action:      action,
		})
		require.NoError(t, err)
		assert.True(t, allowed, "admin should be allowed %s", action)
	}
}

func TestAuthorizer_SelfScopeAllowed(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Permissions: []string{"GetUser:self"},
		SubjectID:   "user-1",
		Action:      "GetUser",
		ResourceID:  "user-1",
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestAuthorizer_SelfScopeDeniedForOtherUser(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Permissions: []string{"GetUser:self"},
		SubjectID:   "user-1",
		Action:      "GetUser",
		ResourceID:  "user-2",
	})
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_SelfScopeUpdatePassword(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	// Can update own password
	allowed, err := authz.Authorize(ctx, AuthzInput{
		Permissions: []string{"UpdateUserPassword:self"},
		SubjectID:   "user-1",
		Action:      "UpdateUserPassword",
		ResourceID:  "user-1",
	})
	require.NoError(t, err)
	assert.True(t, allowed)

	// Cannot update other's password
	allowed, err = authz.Authorize(ctx, AuthzInput{
		Permissions: []string{"UpdateUserPassword:self"},
		SubjectID:   "user-1",
		Action:      "UpdateUserPassword",
		ResourceID:  "user-2",
	})
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_AssignedScopeAllowed(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	// Assigned scope just requires the permission; SQL filtering handles the rest
	allowed, err := authz.Authorize(ctx, AuthzInput{
		Permissions: []string{"ListDevices:assigned"},
		SubjectID:   "user-1",
		Action:      "ListDevices",
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestAuthorizer_NoPermissionsDenied(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Permissions: []string{},
		SubjectID:   "user-1",
		Action:      "CreateUser",
	})
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_NilPermissionsDenied(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		SubjectID: "user-1",
		Action:    "CreateUser",
	})
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_DefaultUserPermissions(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	userPerms := DefaultUserPermissions()

	// GetCurrentUser should work (unrestricted in user perms)
	allowed, err := authz.Authorize(ctx, AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "GetCurrentUser",
	})
	require.NoError(t, err)
	assert.True(t, allowed)

	// GetUser:self should work for own user
	allowed, err = authz.Authorize(ctx, AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "GetUser",
		ResourceID:  "user-1",
	})
	require.NoError(t, err)
	assert.True(t, allowed)

	// GetUser:self should NOT work for other user
	allowed, err = authz.Authorize(ctx, AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "GetUser",
		ResourceID:  "user-2",
	})
	require.NoError(t, err)
	assert.False(t, allowed)

	// CreateUser should be denied
	allowed, err = authz.Authorize(ctx, AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "CreateUser",
	})
	require.NoError(t, err)
	assert.False(t, allowed)

	// ListDevices:assigned should work
	allowed, err = authz.Authorize(ctx, AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "ListDevices",
	})
	require.NoError(t, err)
	assert.True(t, allowed)

	// DeleteDevice should be denied
	allowed, err = authz.Authorize(ctx, AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "DeleteDevice",
	})
	require.NoError(t, err)
	assert.False(t, allowed)
}

// ============================================================================
// Device access (unchanged rules)
// ============================================================================

func TestAuthorizer_DeviceGetOwnInfo(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Role:       "device",
		SubjectID:  "device-1",
		Action:     "GetDevice",
		ResourceID: "device-1",
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestAuthorizer_DeviceGetOtherDevice(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Role:       "device",
		SubjectID:  "device-1",
		Action:     "GetDevice",
		ResourceID: "device-2",
	})
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_DeviceViewDefinitions(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	for _, action := range []string{"ListDefinitions", "GetDefinition"} {
		allowed, err := authz.Authorize(ctx, AuthzInput{
			Role:      "device",
			SubjectID: "device-1",
			Action:    action,
		})
		require.NoError(t, err)
		assert.True(t, allowed, "device should be allowed %s", action)
	}
}

func TestAuthorizer_DeviceViewOwnExecutions(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	for _, action := range []string{"ListExecutions", "GetExecution"} {
		allowed, err := authz.Authorize(ctx, AuthzInput{
			Role:      "device",
			SubjectID: "device-1",
			Action:    action,
			DeviceID:  "device-1",
		})
		require.NoError(t, err)
		assert.True(t, allowed, "device should be allowed %s for own executions", action)
	}
}

func TestAuthorizer_DeviceHeartbeat(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	for _, action := range []string{"Heartbeat", "UpdateStatus"} {
		allowed, err := authz.Authorize(ctx, AuthzInput{
			Role:      "device",
			SubjectID: "device-1",
			Action:    action,
		})
		require.NoError(t, err)
		assert.True(t, allowed, "device should be allowed %s", action)
	}
}

func TestAuthorizer_DeviceDeniedAdminActions(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	denied := []string{"CreateUser", "DeleteDevice", "DispatchAction", "ListUsers"}
	for _, action := range denied {
		allowed, err := authz.Authorize(ctx, AuthzInput{
			Role:      "device",
			SubjectID: "device-1",
			Action:    action,
		})
		require.NoError(t, err)
		assert.False(t, allowed, "device should be denied %s", action)
	}
}

// ============================================================================
// Helpers
// ============================================================================

func TestIsDevice(t *testing.T) {
	assert.True(t, IsDevice("device"))
	assert.False(t, IsDevice("user"))
	assert.False(t, IsDevice("admin"))
}
