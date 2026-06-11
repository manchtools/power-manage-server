package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
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
