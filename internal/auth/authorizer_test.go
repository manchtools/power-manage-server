package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestAuthorize_DeviceAllowed_ExactSet pins the EXACT set of actions a device
// cert may invoke and proves every other registered permission is denied —
// self-discoveringly, so a new permission can never silently become
// device-reachable (#11). Replaces the old hand-picked denied-actions sample.
//
// The allowed set is sourced from the device trust model (a device may read
// itself, read definitions to execute, read its own executions, and report
// status), NOT from authorizeDevice — so a change to authorizeDevice that widens
// device reach fails this test.
func TestAuthorize_DeviceAllowed_ExactSet(t *testing.T) {
	const self = "device-1"
	allowed := map[string]AuthzInput{
		"GetDevice":       {IsDevice: true, SubjectID: self, Action: "GetDevice", ResourceID: self},
		"ListDefinitions": {IsDevice: true, SubjectID: self, Action: "ListDefinitions"},
		"GetDefinition":   {IsDevice: true, SubjectID: self, Action: "GetDefinition"},
		"ListExecutions":  {IsDevice: true, SubjectID: self, Action: "ListExecutions", DeviceID: self},
		"GetExecution":    {IsDevice: true, SubjectID: self, Action: "GetExecution", DeviceID: self},
		"Heartbeat":       {IsDevice: true, SubjectID: self, Action: "Heartbeat"},
		"UpdateStatus":    {IsDevice: true, SubjectID: self, Action: "UpdateStatus"},
	}
	require.NotEmpty(t, allowed)

	for name, in := range allowed {
		assert.Truef(t, Authorize(in), "device must be allowed %s with its correct binding", name)
	}

	// Self-discovering deny: every registered RBAC permission NOT in the allow-set
	// must be denied for a device — even handed a self-binding, a device must not
	// gain a permission merely because it was added to the registry.
	perms := AllPermissions()
	require.NotEmpty(t, perms, "no permissions discovered — the deny sweep would be vacuous")
	denied := 0
	for _, p := range perms {
		if _, ok := allowed[p.Key]; ok {
			continue
		}
		in := AuthzInput{IsDevice: true, SubjectID: self, Action: p.Key, ResourceID: self, DeviceID: self}
		assert.Falsef(t, Authorize(in), "device must be denied %s (not in the device allow-list)", p.Key)
		denied++
	}
	require.Greater(t, denied, len(allowed), "deny sweep must cover more permissions than the allow-list")
}
