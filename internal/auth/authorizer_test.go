package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Permission-based user access
// ============================================================================

func TestAuthorize_UnrestrictedPermission(t *testing.T) {
	allowed := Authorize(AuthzInput{
		Permissions: []string{"CreateUser", "ListUsers", "DeleteUser"},
		SubjectID:   "user-1",
		Action:      "CreateUser",
	})
	assert.True(t, allowed)
}

func TestAuthorize_UnrestrictedPermissionDenied(t *testing.T) {
	allowed := Authorize(AuthzInput{
		Permissions: []string{"ListUsers"},
		SubjectID:   "user-1",
		Action:      "CreateUser",
	})
	assert.False(t, allowed)
}

func TestAuthorize_AdminPermissionsAllowAll(t *testing.T) {
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
		allowed := Authorize(AuthzInput{
			Permissions: adminPerms,
			SubjectID:   "admin-1",
			Action:      action,
		})
		assert.True(t, allowed, "admin should be allowed %s", action)
	}
}

func TestAuthorize_SelfScopeAllowed(t *testing.T) {
	allowed := Authorize(AuthzInput{
		Permissions: []string{"GetUser:self"},
		SubjectID:   "user-1",
		Action:      "GetUser",
		ResourceID:  "user-1",
	})
	assert.True(t, allowed)
}

func TestAuthorize_SelfScopeDeniedForOtherUser(t *testing.T) {
	allowed := Authorize(AuthzInput{
		Permissions: []string{"GetUser:self"},
		SubjectID:   "user-1",
		Action:      "GetUser",
		ResourceID:  "user-2",
	})
	assert.False(t, allowed)
}

func TestAuthorize_SelfScopeUpdatePassword(t *testing.T) {
	// Can update own password
	allowed := Authorize(AuthzInput{
		Permissions: []string{"UpdateUserPassword:self"},
		SubjectID:   "user-1",
		Action:      "UpdateUserPassword",
		ResourceID:  "user-1",
	})
	assert.True(t, allowed)

	// Cannot update other's password
	allowed = Authorize(AuthzInput{
		Permissions: []string{"UpdateUserPassword:self"},
		SubjectID:   "user-1",
		Action:      "UpdateUserPassword",
		ResourceID:  "user-2",
	})
	assert.False(t, allowed)
}

func TestAuthorize_SelfScopeNoResource(t *testing.T) {
	// Self-scope without resource_id (creation actions) should be allowed
	allowed := Authorize(AuthzInput{
		Permissions: []string{"CreateToken:self"},
		SubjectID:   "user-1",
		Action:      "CreateToken",
	})
	assert.True(t, allowed)

	// But unrestricted CreateToken should not match self-scope
	allowed = Authorize(AuthzInput{
		Permissions: []string{"CreateToken:self"},
		SubjectID:   "user-1",
		Action:      "DeleteToken",
	})
	assert.False(t, allowed)
}

func TestAuthorize_AssignedScopeAllowed(t *testing.T) {
	// Assigned scope just requires the permission; SQL filtering handles the rest
	allowed := Authorize(AuthzInput{
		Permissions: []string{"ListDevices:assigned"},
		SubjectID:   "user-1",
		Action:      "ListDevices",
	})
	assert.True(t, allowed)
}

func TestAuthorize_NoPermissionsDenied(t *testing.T) {
	allowed := Authorize(AuthzInput{
		Permissions: []string{},
		SubjectID:   "user-1",
		Action:      "CreateUser",
	})
	assert.False(t, allowed)
}

func TestAuthorize_NilPermissionsDenied(t *testing.T) {
	allowed := Authorize(AuthzInput{
		SubjectID: "user-1",
		Action:    "CreateUser",
	})
	assert.False(t, allowed)
}

func TestAuthorize_DefaultUserPermissions(t *testing.T) {
	userPerms := DefaultUserPermissions()

	// GetCurrentUser should work (unrestricted in user perms)
	assert.True(t, Authorize(AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "GetCurrentUser",
	}))

	// GetUser:self should work for own user
	assert.True(t, Authorize(AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "GetUser",
		ResourceID:  "user-1",
	}))

	// GetUser:self should NOT work for other user
	assert.False(t, Authorize(AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "GetUser",
		ResourceID:  "user-2",
	}))

	// CreateUser should be denied
	assert.False(t, Authorize(AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "CreateUser",
	}))

	// ListDevices:assigned should work
	assert.True(t, Authorize(AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "ListDevices",
	}))

	// DeleteDevice should be denied
	assert.False(t, Authorize(AuthzInput{
		Permissions: userPerms,
		SubjectID:   "user-1",
		Action:      "DeleteDevice",
	}))
}

// ============================================================================
// Device access
// ============================================================================

func TestAuthorize_DeviceGetOwnInfo(t *testing.T) {
	allowed := Authorize(AuthzInput{
		IsDevice:   true,
		SubjectID:  "device-1",
		Action:     "GetDevice",
		ResourceID: "device-1",
	})
	assert.True(t, allowed)
}

func TestAuthorize_DeviceGetOtherDevice(t *testing.T) {
	allowed := Authorize(AuthzInput{
		IsDevice:   true,
		SubjectID:  "device-1",
		Action:     "GetDevice",
		ResourceID: "device-2",
	})
	assert.False(t, allowed)
}

func TestAuthorize_DeviceViewDefinitions(t *testing.T) {
	for _, action := range []string{"ListDefinitions", "GetDefinition"} {
		allowed := Authorize(AuthzInput{
			IsDevice:  true,
			SubjectID: "device-1",
			Action:    action,
		})
		assert.True(t, allowed, "device should be allowed %s", action)
	}
}

func TestAuthorize_DeviceViewOwnExecutions(t *testing.T) {
	for _, action := range []string{"ListExecutions", "GetExecution"} {
		allowed := Authorize(AuthzInput{
			IsDevice:  true,
			SubjectID: "device-1",
			Action:    action,
			DeviceID:  "device-1",
		})
		assert.True(t, allowed, "device should be allowed %s for own executions", action)
	}
}

func TestAuthorize_DeviceHeartbeat(t *testing.T) {
	for _, action := range []string{"Heartbeat", "UpdateStatus"} {
		allowed := Authorize(AuthzInput{
			IsDevice:  true,
			SubjectID: "device-1",
			Action:    action,
		})
		assert.True(t, allowed, "device should be allowed %s", action)
	}
}

func TestAuthorize_DeviceDeniedAdminActions(t *testing.T) {
	denied := []string{"CreateUser", "DeleteDevice", "DispatchAction", "ListUsers"}
	for _, action := range denied {
		allowed := Authorize(AuthzInput{
			IsDevice:  true,
			SubjectID: "device-1",
			Action:    action,
		})
		assert.False(t, allowed, "device should be denied %s", action)
	}
}
