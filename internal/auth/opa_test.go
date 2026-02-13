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

func TestAuthorizer_AdminAllowsAll(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	actions := []string{
		"CreateUser", "GetUser", "ListUsers", "DeleteUser",
		"ListDevices", "GetDevice", "DeleteDevice",
		"CreateToken", "DeleteToken",
		"CreateAction", "DispatchAction",
		"CreateDefinition", "DeleteDefinition",
		"CreateDeviceGroup", "DeleteDeviceGroup",
		"CreateAssignment", "DeleteAssignment",
		"ListAuditEvents",
	}

	for _, action := range actions {
		allowed, err := authz.Authorize(ctx, AuthzInput{
			Role:      "admin",
			SubjectID: "admin-1",
			Action:    action,
		})
		require.NoError(t, err)
		assert.True(t, allowed, "admin should be allowed %s", action)
	}
}

func TestAuthorizer_UserGetOwnProfile(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Role:       "user",
		SubjectID:  "user-1",
		Action:     "GetUser",
		ResourceID: "user-1",
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestAuthorizer_UserGetOtherProfile(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Role:       "user",
		SubjectID:  "user-1",
		Action:     "GetUser",
		ResourceID: "user-2",
	})
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_UserGetCurrentUser(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Role:      "user",
		SubjectID: "user-1",
		Action:    "GetCurrentUser",
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestAuthorizer_UserUpdateOwnPassword(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Role:       "user",
		SubjectID:  "user-1",
		Action:     "UpdateUserPassword",
		ResourceID: "user-1",
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestAuthorizer_UserUpdateOtherPassword(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Role:       "user",
		SubjectID:  "user-1",
		Action:     "UpdateUserPassword",
		ResourceID: "user-2",
	})
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestAuthorizer_UserDeniedAdminActions(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	adminOnly := []string{
		"CreateUser", "ListUsers", "UpdateUserEmail", "UpdateUserRole",
		"SetUserDisabled", "DeleteUser",
		"SetDeviceLabel", "RemoveDeviceLabel", "DeleteDevice",
		"DispatchAction", "DispatchToMultiple",
		"CreateDefinition", "DeleteDefinition",
		"CreateDeviceGroup", "DeleteDeviceGroup",
		"CreateAssignment", "DeleteAssignment",
		"ListAuditEvents",
	}

	for _, action := range adminOnly {
		allowed, err := authz.Authorize(ctx, AuthzInput{
			Role:      "user",
			SubjectID: "user-1",
			Action:    action,
		})
		require.NoError(t, err)
		assert.False(t, allowed, "user should be denied %s", action)
	}
}

func TestAuthorizer_UserCanListDevices(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Role:      "user",
		SubjectID: "user-1",
		Action:    "ListDevices",
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestAuthorizer_UserCanCreateToken(t *testing.T) {
	authz := newTestAuthorizer(t)
	ctx := context.Background()

	allowed, err := authz.Authorize(ctx, AuthzInput{
		Role:      "user",
		SubjectID: "user-1",
		Action:    "CreateToken",
	})
	require.NoError(t, err)
	assert.True(t, allowed)
}

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

func TestIsAdmin(t *testing.T) {
	assert.True(t, IsAdmin("admin"))
	assert.False(t, IsAdmin("user"))
	assert.False(t, IsAdmin("device"))
}

func TestIsUser(t *testing.T) {
	assert.True(t, IsUser("user"))
	assert.False(t, IsUser("admin"))
}

func TestIsDevice(t *testing.T) {
	assert.True(t, IsDevice("device"))
	assert.False(t, IsDevice("user"))
}
