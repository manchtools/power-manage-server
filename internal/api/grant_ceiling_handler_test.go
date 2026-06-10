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

// delegatedManagerCtx is a non-admin who holds role/group MANAGEMENT
// permissions plus ListDevices — but NOT DispatchAction. Granting
// DispatchAction is therefore an escalation the "grant only what you hold"
// ceiling must block (#365).
func delegatedManagerCtx(id string) context.Context {
	return testutil.AuthContext(id, "mgr@test.com", []string{
		"CreateRole", "UpdateRole", "AssignRoleToUser",
		"AssignRoleToUserGroup", "AddUserToGroup", "ListDevices",
	})
}

func TestCreateRole_PrivilegeCeiling(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	mgr := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	ctx := delegatedManagerCtx(mgr)

	// Granting a permission the caller does NOT hold is rejected.
	_, err := h.CreateRole(ctx, connect.NewRequest(&pm.CreateRoleRequest{
		Name: "escalation", Permissions: []string{"DispatchAction"},
	}))
	require.Error(t, err, "must not be able to mint a role with a permission you don't hold")
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// Granting only permissions the caller holds succeeds.
	_, err = h.CreateRole(ctx, connect.NewRequest(&pm.CreateRoleRequest{
		Name: "ok-role", Permissions: []string{"ListDevices"},
	}))
	require.NoError(t, err)
}

func TestUpdateRole_PrivilegeCeiling(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	mgr := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "Editable", []string{"ListDevices"})

	ctx := delegatedManagerCtx(mgr)
	_, err := h.UpdateRole(ctx, connect.NewRequest(&pm.UpdateRoleRequest{
		RoleId: role, Name: "Editable", Permissions: []string{"ListDevices", "DispatchAction"},
	}))
	require.Error(t, err, "must not be able to rewrite a role to add a permission you don't hold")
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestAssignRoleToUser_PrivilegeCeiling(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	mgr := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	privRole := testutil.CreateTestRole(t, st, adminID, "Privileged", []string{"DispatchAction"})
	okRole := testutil.CreateTestRole(t, st, adminID, "OkRole", []string{"ListDevices"})

	ctx := delegatedManagerCtx(mgr)
	// Unscoped (global) assignment of a role with permissions the caller lacks → rejected.
	_, err := h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: privRole,
	}))
	require.Error(t, err, "must not globally assign a role conferring a permission you don't hold")
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// Unscoped assignment within the caller's permissions → allowed.
	_, err = h.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: okRole,
	}))
	require.NoError(t, err)

	// An admin (holds every permission) is never blocked by the ceiling.
	_, err = h.AssignRoleToUser(testutil.AdminContext(adminID), connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: privRole,
	}))
	require.NoError(t, err)
}

func TestAddUserToGroup_PrivilegeCeiling(t *testing.T) {
	st := testutil.SetupPostgres(t)
	groupH := api.NewUserGroupHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	adminCtx := testutil.AdminContext(adminID)
	mgr := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")

	// Admin builds a group that confers a privileged role (DispatchAction).
	group := testutil.CreateTestUserGroup(t, st, adminID, "Privileged Group")
	privRole := testutil.CreateTestRole(t, st, adminID, "Privileged", []string{"DispatchAction"})
	_, err := groupH.AssignRoleToUserGroup(adminCtx, connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: group, RoleId: privRole,
	}))
	require.NoError(t, err)

	// A delegated manager who lacks DispatchAction cannot add a member to that
	// group (doing so would confer DispatchAction to the member).
	_, err = groupH.AddUserToGroup(delegatedManagerCtx(mgr), connect.NewRequest(&pm.AddUserToGroupRequest{
		GroupId: group, UserId: target,
	}))
	require.Error(t, err, "must not add a member to a group conferring a permission you don't hold")
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// The admin can.
	_, err = groupH.AddUserToGroup(adminCtx, connect.NewRequest(&pm.AddUserToGroupRequest{
		GroupId: group, UserId: target,
	}))
	require.NoError(t, err)
}
