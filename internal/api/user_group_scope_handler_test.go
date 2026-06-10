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
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// scopedGroupRole reads the (scope_kind, scope_id) a group-role grant
// carries in the projection, for end-to-end assertion of the emitted
// scoped event.
func scopedGroupRole(t *testing.T, st *store.Store, groupID, roleID string) (*string, *string) {
	t.Helper()
	var sk, si *string
	err := st.TestingPool().QueryRow(context.Background(),
		"SELECT scope_kind, scope_id FROM user_group_roles_projection WHERE group_id=$1 AND role_id=$2",
		groupID, roleID).Scan(&sk, &si)
	require.NoError(t, err)
	return sk, si
}

func TestAssignRoleToUserGroup_DeviceGroupScopedGrant(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	group := testutil.CreateTestUserGroup(t, st, adminID, "Ops Group")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices", "GetDevice"})
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 2")

	_, err := h.AssignRoleToUserGroup(ctx, connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: group, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.NoError(t, err)

	sk, si := scopedGroupRole(t, st, group, role)
	require.NotNil(t, sk)
	require.NotNil(t, si)
	assert.Equal(t, "device_group", *sk)
	assert.Equal(t, dg, *si)
}

func TestAssignRoleToUserGroup_TargetKindMismatchRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	group := testutil.CreateTestUserGroup(t, st, adminID, "Ops Group")
	role := testutil.CreateTestRole(t, st, adminID, "Mixed Role", []string{"ListDevices", "GetUser"})
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 2")

	_, err := h.AssignRoleToUserGroup(ctx, connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: group, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestRevokeRoleFromUserGroup_ScopeTargeted(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	group := testutil.CreateTestUserGroup(t, st, adminID, "Ops Group")
	role := testutil.CreateTestRole(t, st, adminID, "Device Role", []string{"ListDevices"})
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 2")

	_, err := h.AssignRoleToUserGroup(ctx, connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: group, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.NoError(t, err)

	// Revoking the unscoped grant fails — it's assigned at a scope.
	_, err = h.RevokeRoleFromUserGroup(ctx, connect.NewRequest(&pm.RevokeRoleFromUserGroupRequest{
		GroupId: group, RoleId: role,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	// The exact scoped revoke succeeds.
	_, err = h.RevokeRoleFromUserGroup(ctx, connect.NewRequest(&pm.RevokeRoleFromUserGroupRequest{
		GroupId: group, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.NoError(t, err)
}
