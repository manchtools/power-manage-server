package auth_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// failingReconciler / zeroRowsReconciler model the two ways the reconcile can
// fail: a query error and a "system role not found" (0 rows updated).
type failingReconciler struct{}

func (failingReconciler) UpdateSystemRolePermissions(context.Context, db.UpdateSystemRolePermissionsParams) (int64, error) {
	return 0, errors.New("db unavailable")
}

type zeroRowsReconciler struct{}

func (zeroRowsReconciler) UpdateSystemRolePermissions(context.Context, db.UpdateSystemRolePermissionsParams) (int64, error) {
	return 0, nil
}

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

// TestSystemRoleSeed_IsReconcilerOwned pins that the migration seed leaves the
// system-role permissions EMPTY (WS17b #18). The Go reconciler
// (auth.ReconcileSystemRoles, validated by TestReconcileSystemRoles_UpdatesDB)
// is the single source of truth, so there is no SQL literal to drift from
// AdminPermissions/DefaultUserPermissions. Earlier the seed hard-coded literals
// that DID drift — granting the admin-only UpdateUserLinuxUsername:self and
// omitting newer permissions — masked only by the non-fatal reconciler (#16).
// The fresh-install window before the first boot reconcile is intentionally
// permission-less for the system roles.
func TestSystemRoleSeed_IsReconcilerOwned(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	for _, id := range []string{auth.AdminRoleID, auth.UserRoleID} {
		role, err := st.Queries().GetRoleByID(ctx, id)
		require.NoError(t, err)
		assert.Emptyf(t, role.Permissions,
			"system role %s seed must be reconciler-owned (empty) so it cannot drift from the Go set", id)
	}
}

// TestReconcileSystemRoles_FailClosedOnError pins that the reconcile SURFACES
// failures (a query error or a missing system role) so the boot caller can fail
// closed rather than serve traffic with drifted system-role permissions (#16).
func TestReconcileSystemRoles_FailClosedOnError(t *testing.T) {
	err := auth.ReconcileSystemRoles(context.Background(), failingReconciler{}, slog.Default())
	require.Error(t, err, "a query failure must be returned, not swallowed")

	err = auth.ReconcileSystemRoles(context.Background(), zeroRowsReconciler{}, slog.Default())
	require.Error(t, err, "a missing system role (0 rows) must be a fail-closed error")
}

// TestUpdateUserLinuxUsername_IsAdminOnly pins the intent that changing a
// user's linux_username is an ADMIN action, not self-service: linux_username
// keys pm-tty/sudo account naming on managed devices, so a user must not be
// able to rewrite it (theirs or anyone's). The audit (#354) found the handler
// never enforced :self, so the :self grant in the default User role let any
// user rewrite ANY user's linux_username. The fix removes the :self variant
// entirely — only the base TargetUser permission gates the RPC.
func TestUpdateUserLinuxUsername_IsAdminOnly(t *testing.T) {
	allPerms := auth.AllPermissions()
	allKeys := make(map[string]bool, len(allPerms))
	for _, p := range allPerms {
		allKeys[p.Key] = true
	}

	assert.True(t, allKeys["UpdateUserLinuxUsername"], "AllPermissions() should include the admin UpdateUserLinuxUsername")
	assert.False(t, allKeys["UpdateUserLinuxUsername:self"], "the :self variant must be removed — linux_username is admin-only (#354)")

	defaultPerms := auth.DefaultUserPermissions()
	defaultSet := make(map[string]bool, len(defaultPerms))
	for _, p := range defaultPerms {
		defaultSet[p] = true
	}

	assert.False(t, defaultSet["UpdateUserLinuxUsername:self"], "the default User role must not self-service linux_username (#354)")
	assert.False(t, defaultSet["UpdateUserLinuxUsername"], "the default User role must not hold the admin linux_username permission either (#354)")
}
