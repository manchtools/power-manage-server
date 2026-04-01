package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

const (
	systemAdminRoleID = "00000000000000000000000001"
	systemUserRoleID  = "00000000000000000000000002"
)

func TestDeleteRole_SystemAdminRoleBlocked(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteRole(ctx, connect.NewRequest(&pm.DeleteRoleRequest{
		Id: systemAdminRoleID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestDeleteRole_SystemUserRoleBlocked(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteRole(ctx, connect.NewRequest(&pm.DeleteRoleRequest{
		Id: systemUserRoleID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestUpdateRole_InvalidPermissionRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	roleID := testutil.CreateTestRole(t, st, adminID, "Custom Role", []string{"devices:read"})

	_, err := h.UpdateRole(ctx, connect.NewRequest(&pm.UpdateRoleRequest{
		RoleId:      roleID,
		Name:        "Custom Role Updated",
		Permissions: []string{"totally:bogus:permission"},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestCreateRole_InvalidPermissionRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateRole(ctx, connect.NewRequest(&pm.CreateRoleRequest{
		Name:        "Bad Perms Role",
		Permissions: []string{"nonexistent:permission"},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestCreateRole_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateRole(ctx, connect.NewRequest(&pm.CreateRoleRequest{
		Name:        "Viewer Role",
		Description: "Can only view",
		Permissions: []string{"devices:read"},
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Role.Id)
	assert.Equal(t, "Viewer Role", resp.Msg.Role.Name)
	assert.Equal(t, "Can only view", resp.Msg.Role.Description)
	assert.Contains(t, resp.Msg.Role.Permissions, "devices:read")
	assert.False(t, resp.Msg.Role.IsSystem)
}

func TestCreateRole_DuplicateNameRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateRole(ctx, connect.NewRequest(&pm.CreateRoleRequest{
		Name:        "Unique Role",
		Permissions: []string{},
	}))
	require.NoError(t, err)

	_, err = h.CreateRole(ctx, connect.NewRequest(&pm.CreateRoleRequest{
		Name:        "Unique Role",
		Permissions: []string{},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
}

func TestDeleteRole_CustomRoleSuccess(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	roleID := testutil.CreateTestRole(t, st, adminID, "Deletable Role", []string{})

	_, err := h.DeleteRole(ctx, connect.NewRequest(&pm.DeleteRoleRequest{
		Id: roleID,
	}))
	require.NoError(t, err)

	// Verify role is gone
	_, err = h.GetRole(ctx, connect.NewRequest(&pm.GetRoleRequest{Id: roleID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestDeleteRole_InUseByUserBlocked(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	roleID := testutil.CreateTestRole(t, st, adminID, "Assigned Role", []string{"devices:read"})

	// Assign the role to a user
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	testutil.AssignRoleToTestUser(t, st, adminID, userID, roleID)

	_, err := h.DeleteRole(ctx, connect.NewRequest(&pm.DeleteRoleRequest{
		Id: roleID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestUpdateRole_CannotRenameSystemRole(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.UpdateRole(ctx, connect.NewRequest(&pm.UpdateRoleRequest{
		RoleId:      systemAdminRoleID,
		Name:        "Renamed Admin",
		Permissions: []string{"devices:read"},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestGetRole_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetRole(ctx, connect.NewRequest(&pm.GetRoleRequest{
		Id: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListRoles_IncludesSystemRoles(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewRoleHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ListRoles(ctx, connect.NewRequest(&pm.ListRolesRequest{}))
	require.NoError(t, err)

	// Should include at least the two system roles (Admin and User)
	assert.GreaterOrEqual(t, len(resp.Msg.Roles), 2)

	foundAdmin := false
	foundUser := false
	for _, r := range resp.Msg.Roles {
		if r.Id == systemAdminRoleID {
			foundAdmin = true
			assert.True(t, r.IsSystem)
			assert.Equal(t, "Admin", r.Name)
		}
		if r.Id == systemUserRoleID {
			foundUser = true
			assert.True(t, r.IsSystem)
			assert.Equal(t, "User", r.Name)
		}
	}
	assert.True(t, foundAdmin, "system Admin role must be in list")
	assert.True(t, foundUser, "system User role must be in list")
}
