package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllPermissions_NotEmpty(t *testing.T) {
	perms := AllPermissions()
	assert.Greater(t, len(perms), 50, "should have many permissions")
}

func TestAllPermissions_HasRequiredGroups(t *testing.T) {
	perms := AllPermissions()
	groups := make(map[string]bool)
	for _, p := range perms {
		groups[p.Group] = true
	}

	requiredGroups := []string{
		"Users", "Devices", "Tokens", "Actions", "Action Sets",
		"Definitions", "Device Groups", "Assignments", "Dispatch",
		"Executions", "Audit", "Roles",
	}
	for _, g := range requiredGroups {
		assert.True(t, groups[g], "missing group: %s", g)
	}
}

func TestAllPermissions_KeysAreNonEmpty(t *testing.T) {
	for _, p := range AllPermissions() {
		assert.NotEmpty(t, p.Key, "permission key should not be empty")
		assert.NotEmpty(t, p.Group, "permission group should not be empty")
		assert.NotEmpty(t, p.Description, "permission description should not be empty")
	}
}

func TestAllPermissions_ScopeFormat(t *testing.T) {
	for _, p := range AllPermissions() {
		parts := strings.SplitN(p.Key, ":", 2)
		if len(parts) == 2 {
			scope := parts[1]
			assert.Contains(t, []string{"self", "assigned"}, scope,
				"invalid scope suffix in permission %s", p.Key)
		}
	}
}

func TestAdminPermissions_NoScopes(t *testing.T) {
	for _, p := range AdminPermissions() {
		assert.False(t, strings.Contains(p, ":"),
			"admin permission should not contain scope suffix: %s", p)
	}
}

func TestAdminPermissions_NotEmpty(t *testing.T) {
	perms := AdminPermissions()
	assert.Greater(t, len(perms), 40, "should have many admin permissions")
}

func TestAdminPermissions_ContainsRolePerms(t *testing.T) {
	perms := make(map[string]bool)
	for _, p := range AdminPermissions() {
		perms[p] = true
	}
	assert.True(t, perms["CreateRole"])
	assert.True(t, perms["UpdateRole"])
	assert.True(t, perms["DeleteRole"])
	assert.True(t, perms["AssignRoleToUser"])
	assert.True(t, perms["RevokeRoleFromUser"])
	assert.True(t, perms["ListPermissions"])
}

func TestDefaultUserPermissions_AreValid(t *testing.T) {
	valid := ValidPermissionKeys()
	for _, p := range DefaultUserPermissions() {
		assert.True(t, valid[p], "default user permission %s is not in valid set", p)
	}
}

func TestDefaultUserPermissions_HasSelfScopes(t *testing.T) {
	perms := DefaultUserPermissions()
	hasSelf := false
	hasAssigned := false
	for _, p := range perms {
		if strings.HasSuffix(p, ":self") {
			hasSelf = true
		}
		if strings.HasSuffix(p, ":assigned") {
			hasAssigned = true
		}
	}
	assert.True(t, hasSelf, "should have :self scoped permissions")
	assert.True(t, hasAssigned, "should have :assigned scoped permissions")
}

func TestDefaultUserPermissions_IncludesBasics(t *testing.T) {
	perms := make(map[string]bool)
	for _, p := range DefaultUserPermissions() {
		perms[p] = true
	}
	assert.True(t, perms["GetCurrentUser"])
	assert.True(t, perms["GetUser:self"])
	assert.True(t, perms["UpdateUserEmail:self"])
	assert.True(t, perms["UpdateUserPassword:self"])
	assert.True(t, perms["ListDevices:assigned"])
	assert.True(t, perms["GetDevice:assigned"])
}

func TestValidPermissionKeys_IncludesAll(t *testing.T) {
	valid := ValidPermissionKeys()
	allPerms := AllPermissions()
	require.Equal(t, len(allPerms), len(valid), "ValidPermissionKeys should match AllPermissions count")
	for _, p := range allPerms {
		assert.True(t, valid[p.Key], "missing valid key: %s", p.Key)
	}
}

func TestValidPermissionKeys_RejectsInvalid(t *testing.T) {
	valid := ValidPermissionKeys()
	assert.False(t, valid["FakePermission"])
	assert.False(t, valid[""])
	assert.False(t, valid["CreateUser:admin"])
}

func TestAdminPermissions_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range AdminPermissions() {
		assert.False(t, seen[p], "duplicate admin permission: %s", p)
		seen[p] = true
	}
}
