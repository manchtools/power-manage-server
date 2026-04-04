package auth_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestAdminPermissions_IncludesAllPermissions(t *testing.T) {
	all := auth.AllPermissions()
	admin := auth.AdminPermissions()

	adminSet := make(map[string]bool, len(admin))
	for _, p := range admin {
		adminSet[p] = true
	}

	for _, p := range all {
		assert.True(t, adminSet[p.Key], "AdminPermissions() should include %q", p.Key)
	}
}

func TestReconcileSystemRoles_UpdatesDB(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	err := auth.ReconcileSystemRoles(ctx, st.Queries(), slog.Default())
	require.NoError(t, err)

	// Verify admin role has all AdminPermissions
	adminRole, err := st.Queries().GetRoleByID(ctx, auth.AdminRoleID)
	require.NoError(t, err)
	assert.ElementsMatch(t, auth.AdminPermissions(), adminRole.Permissions)

	// Verify user role has all DefaultUserPermissions
	userRole, err := st.Queries().GetRoleByID(ctx, auth.UserRoleID)
	require.NoError(t, err)
	assert.ElementsMatch(t, auth.DefaultUserPermissions(), userRole.Permissions)
}

func TestUpdateUserLinuxUsername_PermissionExists(t *testing.T) {
	allPerms := auth.AllPermissions()
	allKeys := make(map[string]bool, len(allPerms))
	for _, p := range allPerms {
		allKeys[p.Key] = true
	}

	assert.True(t, allKeys["UpdateUserLinuxUsername"], "AllPermissions() should include UpdateUserLinuxUsername")
	assert.True(t, allKeys["UpdateUserLinuxUsername:self"], "AllPermissions() should include UpdateUserLinuxUsername:self")

	defaultPerms := auth.DefaultUserPermissions()
	defaultSet := make(map[string]bool, len(defaultPerms))
	for _, p := range defaultPerms {
		defaultSet[p] = true
	}

	assert.True(t, defaultSet["UpdateUserLinuxUsername:self"], "DefaultUserPermissions() should include UpdateUserLinuxUsername:self")
}

