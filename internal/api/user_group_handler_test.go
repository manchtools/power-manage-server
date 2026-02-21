package api_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestCreateUserGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateUserGroup(ctx, connect.NewRequest(&pm.CreateUserGroupRequest{
		Name:        "Engineering",
		Description: "Engineering team",
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Group.Id)
	assert.Equal(t, "Engineering", resp.Msg.Group.Name)
	assert.Equal(t, "Engineering team", resp.Msg.Group.Description)
	assert.Equal(t, int32(0), resp.Msg.Group.MemberCount)
}

func TestCreateUserGroup_DuplicateName(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateUserGroup(ctx, connect.NewRequest(&pm.CreateUserGroupRequest{
		Name: "Unique Group",
	}))
	require.NoError(t, err)

	_, err = h.CreateUserGroup(ctx, connect.NewRequest(&pm.CreateUserGroupRequest{
		Name: "Unique Group",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
}

func TestGetUserGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Test Group")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.GetUserGroup(ctx, connect.NewRequest(&pm.GetUserGroupRequest{Id: groupID}))
	require.NoError(t, err)
	assert.Equal(t, groupID, resp.Msg.Group.Id)
	assert.Equal(t, "Test Group", resp.Msg.Group.Name)
}

func TestGetUserGroup_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetUserGroup(ctx, connect.NewRequest(&pm.GetUserGroupRequest{Id: testutil.NewID()}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListUserGroups(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for i := 0; i < 3; i++ {
		testutil.CreateTestUserGroup(t, st, adminID, testutil.NewID())
	}

	resp, err := h.ListUserGroups(ctx, connect.NewRequest(&pm.ListUserGroupsRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Groups), 3)
}

func TestUpdateUserGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Old Name")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.UpdateUserGroup(ctx, connect.NewRequest(&pm.UpdateUserGroupRequest{
		GroupId:     groupID,
		Name:        "New Name",
		Description: "Updated description",
	}))
	require.NoError(t, err)
	assert.Equal(t, "New Name", resp.Msg.Group.Name)
	assert.Equal(t, "Updated description", resp.Msg.Group.Description)
}

func TestDeleteUserGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "To Delete")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteUserGroup(ctx, connect.NewRequest(&pm.DeleteUserGroupRequest{Id: groupID}))
	require.NoError(t, err)

	_, err = h.GetUserGroup(ctx, connect.NewRequest(&pm.GetUserGroupRequest{Id: groupID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAddUserToGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Members Group")
	ctx := testutil.AdminContext(adminID)

	_, err := h.AddUserToGroup(ctx, connect.NewRequest(&pm.AddUserToGroupRequest{
		GroupId: groupID,
		UserId:  userID,
	}))
	require.NoError(t, err)

	// Verify membership by getting the group
	resp, err := h.GetUserGroup(ctx, connect.NewRequest(&pm.GetUserGroupRequest{Id: groupID}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.Msg.Group.MemberCount)
	require.Len(t, resp.Msg.Members, 1)
	assert.Equal(t, userID, resp.Msg.Members[0].UserId)
}

func TestAddUserToGroup_AlreadyMember(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Dup Group")
	ctx := testutil.AdminContext(adminID)

	_, err := h.AddUserToGroup(ctx, connect.NewRequest(&pm.AddUserToGroupRequest{
		GroupId: groupID,
		UserId:  userID,
	}))
	require.NoError(t, err)

	_, err = h.AddUserToGroup(ctx, connect.NewRequest(&pm.AddUserToGroupRequest{
		GroupId: groupID,
		UserId:  userID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
}

func TestRemoveUserFromGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Remove Group")
	ctx := testutil.AdminContext(adminID)

	testutil.AddUserToTestGroup(t, st, adminID, groupID, userID)

	_, err := h.RemoveUserFromGroup(ctx, connect.NewRequest(&pm.RemoveUserFromGroupRequest{
		GroupId: groupID,
		UserId:  userID,
	}))
	require.NoError(t, err)

	resp, err := h.GetUserGroup(ctx, connect.NewRequest(&pm.GetUserGroupRequest{Id: groupID}))
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Msg.Group.MemberCount)
	assert.Empty(t, resp.Msg.Members)
}

func TestRemoveUserFromGroup_NotMember(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "NM Group")
	ctx := testutil.AdminContext(adminID)

	_, err := h.RemoveUserFromGroup(ctx, connect.NewRequest(&pm.RemoveUserFromGroupRequest{
		GroupId: groupID,
		UserId:  userID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAssignRoleToUserGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Role Group")
	roleID := testutil.CreateTestRole(t, st, adminID, "TestRole", []string{"GetDevice"})
	ctx := testutil.AdminContext(adminID)

	_, err := h.AssignRoleToUserGroup(ctx, connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: groupID,
		RoleId:  roleID,
	}))
	require.NoError(t, err)

	// Verify role appears on the group
	resp, err := h.GetUserGroup(ctx, connect.NewRequest(&pm.GetUserGroupRequest{Id: groupID}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Group.Roles, 1)
	assert.Equal(t, roleID, resp.Msg.Group.Roles[0].Id)
}

func TestAssignRoleToUserGroup_AlreadyAssigned(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Dup Role Group")
	roleID := testutil.CreateTestRole(t, st, adminID, "TestRole2", []string{"GetDevice"})
	ctx := testutil.AdminContext(adminID)

	_, err := h.AssignRoleToUserGroup(ctx, connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: groupID,
		RoleId:  roleID,
	}))
	require.NoError(t, err)

	_, err = h.AssignRoleToUserGroup(ctx, connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: groupID,
		RoleId:  roleID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
}

func TestRevokeRoleFromUserGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Revoke Group")
	roleID := testutil.CreateTestRole(t, st, adminID, "RevokeRole", []string{"GetDevice"})
	ctx := testutil.AdminContext(adminID)

	testutil.AssignRoleToTestGroup(t, st, adminID, groupID, roleID)

	_, err := h.RevokeRoleFromUserGroup(ctx, connect.NewRequest(&pm.RevokeRoleFromUserGroupRequest{
		GroupId: groupID,
		RoleId:  roleID,
	}))
	require.NoError(t, err)

	resp, err := h.GetUserGroup(ctx, connect.NewRequest(&pm.GetUserGroupRequest{Id: groupID}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Group.Roles)
}

func TestRevokeRoleFromUserGroup_NotAssigned(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "NR Group")
	roleID := testutil.CreateTestRole(t, st, adminID, "NRRole", []string{"GetDevice"})
	ctx := testutil.AdminContext(adminID)

	_, err := h.RevokeRoleFromUserGroup(ctx, connect.NewRequest(&pm.RevokeRoleFromUserGroupRequest{
		GroupId: groupID,
		RoleId:  roleID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListUserGroupsForUser(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AdminContext(adminID)

	group1 := testutil.CreateTestUserGroup(t, st, adminID, "Group A")
	group2 := testutil.CreateTestUserGroup(t, st, adminID, "Group B")
	testutil.CreateTestUserGroup(t, st, adminID, "Group C") // user is NOT in this one

	testutil.AddUserToTestGroup(t, st, adminID, group1, userID)
	testutil.AddUserToTestGroup(t, st, adminID, group2, userID)

	resp, err := h.ListUserGroupsForUser(ctx, connect.NewRequest(&pm.ListUserGroupsForUserRequest{
		UserId: userID,
	}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Groups, 2)
}

func TestAdditivePermissions_DirectAndGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	// Create two roles with different permissions
	role1 := testutil.CreateTestRole(t, st, adminID, "DirectRole"+testutil.NewID(), []string{"GetDevice", "ListDevices"})
	role2 := testutil.CreateTestRole(t, st, adminID, "GroupRole"+testutil.NewID(), []string{"CreateAction", "ListActions"})

	// Assign role1 directly to user
	testutil.AssignRoleToTestUser(t, st, adminID, userID, role1)

	// Assign role2 via user group
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Perm Group"+testutil.NewID())
	testutil.AddUserToTestGroup(t, st, adminID, groupID, userID)
	testutil.AssignRoleToTestGroup(t, st, adminID, groupID, role2)

	// Resolve permissions via the combined query
	perms, err := st.Queries().GetUserPermissionsWithGroups(context.Background(), userID)
	require.NoError(t, err)

	// Should have all 4 permissions (additive)
	permSet := make(map[string]bool)
	for _, p := range perms {
		permSet[p] = true
	}
	assert.True(t, permSet["GetDevice"], "should have GetDevice from direct role")
	assert.True(t, permSet["ListDevices"], "should have ListDevices from direct role")
	assert.True(t, permSet["CreateAction"], "should have CreateAction from group role")
	assert.True(t, permSet["ListActions"], "should have ListActions from group role")
}

func TestAdditivePermissions_NoDuplicates(t *testing.T) {
	st := testutil.SetupPostgres(t)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	// Both roles have "GetDevice"
	role1 := testutil.CreateTestRole(t, st, adminID, "R1"+testutil.NewID(), []string{"GetDevice", "ListDevices"})
	role2 := testutil.CreateTestRole(t, st, adminID, "R2"+testutil.NewID(), []string{"GetDevice", "CreateAction"})

	testutil.AssignRoleToTestUser(t, st, adminID, userID, role1)

	groupID := testutil.CreateTestUserGroup(t, st, adminID, "NoDup"+testutil.NewID())
	testutil.AddUserToTestGroup(t, st, adminID, groupID, userID)
	testutil.AssignRoleToTestGroup(t, st, adminID, groupID, role2)

	perms, err := st.Queries().GetUserPermissionsWithGroups(context.Background(), userID)
	require.NoError(t, err)

	// Count occurrences of GetDevice - should be exactly 1 (DISTINCT)
	count := 0
	for _, p := range perms {
		if p == "GetDevice" {
			count++
		}
	}
	assert.Equal(t, 1, count, "GetDevice should appear exactly once (DISTINCT)")
	assert.Len(t, perms, 3, "should have exactly 3 unique permissions")
}

func TestAdditivePermissions_MultipleGroups(t *testing.T) {
	st := testutil.SetupPostgres(t)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	role1 := testutil.CreateTestRole(t, st, adminID, "MG1"+testutil.NewID(), []string{"GetDevice"})
	role2 := testutil.CreateTestRole(t, st, adminID, "MG2"+testutil.NewID(), []string{"CreateAction"})
	role3 := testutil.CreateTestRole(t, st, adminID, "MG3"+testutil.NewID(), []string{"ListUsers"})

	group1 := testutil.CreateTestUserGroup(t, st, adminID, "MG-A"+testutil.NewID())
	group2 := testutil.CreateTestUserGroup(t, st, adminID, "MG-B"+testutil.NewID())

	testutil.AddUserToTestGroup(t, st, adminID, group1, userID)
	testutil.AddUserToTestGroup(t, st, adminID, group2, userID)

	testutil.AssignRoleToTestGroup(t, st, adminID, group1, role1)
	testutil.AssignRoleToTestGroup(t, st, adminID, group1, role2)
	testutil.AssignRoleToTestGroup(t, st, adminID, group2, role3)

	perms, err := st.Queries().GetUserPermissionsWithGroups(context.Background(), userID)
	require.NoError(t, err)

	permSet := make(map[string]bool)
	for _, p := range perms {
		permSet[p] = true
	}
	assert.True(t, permSet["GetDevice"])
	assert.True(t, permSet["CreateAction"])
	assert.True(t, permSet["ListUsers"])
}

func TestDeleteUserGroup_CleansUpMembersAndRoles(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Cleanup Group")
	roleID := testutil.CreateTestRole(t, st, adminID, "CleanupRole"+testutil.NewID(), []string{"GetDevice"})
	ctx := testutil.AdminContext(adminID)

	testutil.AddUserToTestGroup(t, st, adminID, groupID, userID)
	testutil.AssignRoleToTestGroup(t, st, adminID, groupID, roleID)

	// Verify user has permission via group before deletion
	perms, err := st.Queries().GetUserPermissionsWithGroups(context.Background(), userID)
	require.NoError(t, err)
	assert.Contains(t, perms, "GetDevice")

	// Delete group
	_, err = h.DeleteUserGroup(ctx, connect.NewRequest(&pm.DeleteUserGroupRequest{Id: groupID}))
	require.NoError(t, err)

	// Verify user no longer has permission from deleted group
	perms, err = st.Queries().GetUserPermissionsWithGroups(context.Background(), userID)
	require.NoError(t, err)
	assert.NotContains(t, perms, "GetDevice")
}
