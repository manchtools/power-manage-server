package api_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// The last-admin guard (#365) refuses any operation that would leave zero
// ENABLED administrators (counting group-inherited admins). These tests rely on
// CreateTestUser(...,"admin") being a real RBAC admin (a user_roles_projection
// assignment), which the factory now ensures.

func TestDeleteUser_LastAdminRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Deleting the only admin is refused.
	_, err := h.DeleteUser(ctx, connect.NewRequest(&pm.DeleteUserRequest{Id: adminID}))
	require.Error(t, err, "deleting the sole admin must be refused")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	// With a second admin, deleting one is allowed.
	admin2 := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	_, err = h.DeleteUser(ctx, connect.NewRequest(&pm.DeleteUserRequest{Id: admin2}))
	require.NoError(t, err)
}

func TestSetUserDisabled_LastAdminRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.SetUserDisabled(ctx, connect.NewRequest(&pm.SetUserDisabledRequest{Id: adminID, Disabled: true}))
	require.Error(t, err, "disabling the sole admin must be refused")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestRevokeRoleFromUser_LastAdminRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	adminRole, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)

	// Revoking Admin from the sole admin is refused.
	_, err = h.RevokeRoleFromUser(ctx, connect.NewRequest(&pm.RevokeRoleFromUserRequest{
		UserId: adminID, RoleId: adminRole.ID,
	}))
	require.Error(t, err, "revoking Admin from the sole admin must be refused")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	// With a second admin, revoking from one is allowed.
	admin2 := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	_, err = h.RevokeRoleFromUser(ctx, connect.NewRequest(&pm.RevokeRoleFromUserRequest{
		UserId: admin2, RoleId: adminRole.ID,
	}))
	require.NoError(t, err)
}

// TestRevokeRoleFromUser_ScopedAdminRevokeNotBlocked pins that the last-admin
// guard is UNSCOPED-only: revoking a SCOPED Admin grant doesn't remove global
// admin, so it must reach scope resolution rather than be rejected as a
// lockout. The sole admin holds only an unscoped Admin grant here, so targeting
// a scoped grant surfaces the wrong-scope precondition — proving the guard was
// skipped (else it would be the last-admin error).
func TestRevokeRoleFromUser_ScopedAdminRevokeNotBlocked(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	adminRole, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 1")

	_, err = h.RevokeRoleFromUser(ctx, connect.NewRequest(&pm.RevokeRoleFromUserRequest{
		UserId: adminID, RoleId: adminRole.ID, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not assigned at the specified scope",
		"a scoped Admin revoke must reach scope resolution, not be blocked by the unscoped last-admin guard")
}

func TestUpdateRole_AdminPermissionsImmutable(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	adminRole, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)

	// Stripping the Admin role's permissions is refused (it would disable every
	// administrator at once).
	_, err = h.UpdateRole(ctx, connect.NewRequest(&pm.UpdateRoleRequest{
		RoleId: adminRole.ID, Name: adminRole.Name, Permissions: []string{"ListDevices"},
	}))
	require.Error(t, err, "the Admin role's permissions must be immutable")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

// countEnabledAdmins returns the number of enabled, non-deleted holders of the
// Admin role (direct grants — the test factory assigns it directly).
func countEnabledAdmins(t *testing.T, st *store.Store) int {
	t.Helper()
	ctx := context.Background()
	role, err := st.Repos().Role.GetByName(ctx, "Admin")
	require.NoError(t, err)
	ids, err := st.Repos().Role.ListUserIDsWithRole(ctx, role.ID)
	require.NoError(t, err)
	n := 0
	for _, id := range ids {
		u, err := st.Repos().User.Get(ctx, id)
		require.NoError(t, err)
		if !u.Disabled && !u.IsDeleted {
			n++
		}
	}
	return n
}

// TestSetUserDisabled_ConcurrentLastAdminInvariant pins the #369 fix's
// invariant: no amount of concurrent admin-disabling may drive the enabled-admin
// count to zero. Four admins are disabled simultaneously; the advisory lock
// serializes each guard+append so each guard sees the running count and refuses
// the one that would hit zero — at least one enabled admin must remain. Without
// the lock the guards read a stale count concurrently and can all pass, zeroing
// out admins — which this asserts against.
func TestSetUserDisabled_ConcurrentLastAdminInvariant(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)

	const n = 4
	admins := make([]string, n)
	for i := range admins {
		admins[i] = testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	}
	ctx := testutil.AdminContext(admins[0])

	var wg sync.WaitGroup
	for _, id := range admins {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, _ = h.SetUserDisabled(ctx, connect.NewRequest(&pm.SetUserDisabledRequest{Id: id, Disabled: true}))
		}(id)
	}
	wg.Wait()

	assert.GreaterOrEqual(t, countEnabledAdmins(t, st), 1,
		"at least one enabled admin must always remain — concurrent disables must not race to zero (#369)")
}
