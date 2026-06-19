package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func userHasRole(t *testing.T, st *store.Store, userID, roleID string) bool {
	t.Helper()
	ok, err := st.Queries().UserHasRole(context.Background(), db.UserHasRoleParams{UserID: userID, RoleID: roleID})
	require.NoError(t, err)
	return ok
}

// The role-management permissions ARE the authorization. Holding
// AssignRoleToUser / AssignRoleToUserGroup / AddUserToGroup / CreateRole /
// UpdateRole / CreateUser lets the holder assign or define ANY role — there is
// NO secondary "grant only the permissions you personally hold" ceiling. These
// permissions are powerful and meant to be handed out carefully; the gate is
// holding the permission, not the caller's own permission set. (Scope authority
// — WHERE a scope-limited admin may grant — is a separate axis and still
// enforced; see role_scope_handler_test.go.)

func TestAssignRoleToUser_PermissionAloneAuthorizesAnyRole(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	adminRole, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)

	// A non-admin holding ONLY AssignRoleToUser may assign the Admin role.
	ctx := testutil.AuthContext(testutil.NewID(), "mgr@test.com", []string{"AssignRoleToUser"})
	_, err = h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: adminRole.ID,
	}))
	require.NoError(t, err)
	assert.True(t, userHasRole(t, st, target, adminRole.ID), "the Admin role must actually be assigned")
}

func TestAssignRoleToUserGroup_PermissionAloneAuthorizesAnyRole(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	group := testutil.CreateTestUserGroup(t, st, adminID, "Team")
	adminRole, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)

	ctx := testutil.AuthContext(testutil.NewID(), "mgr@test.com", []string{"AssignRoleToUserGroup"})
	_, err = h.AssignRoleToUserGroup(ctx, connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: group, RoleId: adminRole.ID,
	}))
	require.NoError(t, err)
	hasRole, err := st.Queries().UserGroupHasRole(context.Background(), db.UserGroupHasRoleParams{GroupID: group, RoleID: adminRole.ID})
	require.NoError(t, err)
	assert.True(t, hasRole, "the Admin role must actually be granted to the group")
}

func TestAddUserToGroup_PermissionAloneAuthorizesAdminBearingGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	groupH := api.NewUserGroupHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	group := testutil.CreateTestUserGroup(t, st, adminID, "Admins")
	adminRole, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)
	_, err = groupH.AssignRoleToUserGroup(testutil.AdminContext(adminID), connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: group, RoleId: adminRole.ID,
	}))
	require.NoError(t, err)

	// A non-admin holding ONLY AddUserToGroup may add a member even though the
	// group confers Admin to its members.
	ctx := testutil.AuthContext(testutil.NewID(), "mgr@test.com", []string{"AddUserToGroup"})
	_, err = groupH.AddUserToGroup(ctx, connect.NewRequest(&pm.AddUserToGroupRequest{
		GroupId: group, UserId: target,
	}))
	require.NoError(t, err)
	inGroup, err := st.Queries().IsUserInGroup(context.Background(), db.IsUserInGroupParams{GroupID: group, UserID: target})
	require.NoError(t, err)
	assert.True(t, inGroup, "the member must actually be added to the group")
}

func TestCreateRole_PermissionAloneAuthorizesAnyPermissions(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	// A non-admin holding ONLY CreateRole may mint a role conferring a
	// permission they do not personally hold.
	ctx := testutil.AuthContext(testutil.NewID(), "mgr@test.com", []string{"CreateRole"})
	_, err := h.CreateRole(ctx, connect.NewRequest(&pm.CreateRoleRequest{
		Name: "Dispatcher", Permissions: []string{"DispatchAction"},
	}))
	require.NoError(t, err)
}

func TestUpdateRole_PermissionAloneAuthorizesAnyPermissions(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	role := testutil.CreateTestRole(t, st, adminID, "Editable", []string{"ListDevices"})

	ctx := testutil.AuthContext(testutil.NewID(), "mgr@test.com", []string{"UpdateRole"})
	_, err := h.UpdateRole(ctx, connect.NewRequest(&pm.UpdateRoleRequest{
		RoleId: role, Name: "Editable", Permissions: []string{"ListDevices", "DispatchAction"},
	}))
	require.NoError(t, err)
}

func TestCreateUser_PermissionAloneAuthorizesAnyRole(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)
	adminRole, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)

	// A non-admin holding ONLY CreateUser may create a user carrying Admin.
	ctx := testutil.AuthContext(testutil.NewID(), "mgr@test.com", []string{"CreateUser"})
	resp, err := h.CreateUser(ctx, connect.NewRequest(&pm.CreateUserRequest{
		Email:    testutil.NewID() + "@new.com",
		Password: "secure-pass-123",
		RoleIds:  []string{adminRole.ID},
	}))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Msg.User.Id)
	assert.True(t, userHasRole(t, st, resp.Msg.User.Id, adminRole.ID), "the new user must actually carry the Admin role")
}
