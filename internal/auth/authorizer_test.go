package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Permission-based user access
// ============================================================================

// TestAuthorize_UpdateUserLinuxUsername_AdminOnly pins the #354 fix at the
// authorization layer: a stock User must NOT be authorized for
// UpdateUserLinuxUsername, while an admin must be. The interceptor invokes
// Authorize with an EMPTY ResourceID (it never extracts the target id), so a
// :self grant would short-circuit to allowed here — which is exactly how the
// bug let any user rewrite any user's linux_username. The fix removes the
// :self variant, so the stock User role no longer authorizes the action.
func TestAuthorize_UpdateUserLinuxUsername_AdminOnly(t *testing.T) {
	// Stock User: denied (no linux_username permission of any kind).
	deniedUser := Authorize(AuthzInput{
		Permissions: DefaultUserPermissions(),
		SubjectID:   "user-1",
		Action:      "UpdateUserLinuxUsername",
		ResourceID:  "", // interceptor shape: target id not threaded in
	})
	assert.False(t, deniedUser, "stock User must not be authorized for UpdateUserLinuxUsername")

	// The :self variant being removed from the registry is asserted in
	// reconcile_test (TestUpdateUserLinuxUsername_IsAdminOnly); here we pin the
	// authorization outcome for the stock role and the admin.

	// Admin: allowed via the base TargetUser permission.
	allowedAdmin := Authorize(AuthzInput{
		Permissions: []string{"UpdateUserLinuxUsername"},
		SubjectID:   "admin-1",
		Action:      "UpdateUserLinuxUsername",
	})
	assert.True(t, allowedAdmin, "an admin holding UpdateUserLinuxUsername must be authorized")
}

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
		"CreateStaticDeviceGroup", "CreateDynamicDeviceGroup", "DeleteDeviceGroup",
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
