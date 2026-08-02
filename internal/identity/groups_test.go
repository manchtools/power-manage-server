package identity_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

func TestUserGroups_DirectCRUDMembershipAndAudit(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	operator := f.seedActor(grant{Permissions: []string{
		"CreateStaticUserGroup", "GetUserGroup", "ListUserGroups", "UpdateUserGroup",
		"DeleteUserGroup", "AddUserToGroup", "RemoveUserFromGroup",
		"ListUserGroupsForUser", "SetUserGroupMaintenanceWindow",
	}})
	member := f.seedSubject()

	created, err := f.client.CreateUserGroup(f.ctx(), authed(&pmv1.CreateUserGroupRequest{
		Name: "Operators", Description: "static operators",
	}, operator.Token))
	require.NoError(t, err)
	groupID := created.Msg.Group.Id
	assert.False(t, created.Msg.Group.IsDynamic)
	assert.Equal(t, int32(0), created.Msg.Group.MemberCount)

	var beforeVersion int32
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT session_version FROM users WHERE id = $1`, member.ID).Scan(&beforeVersion))
	_, err = f.client.AddUserToGroup(f.ctx(), authed(&pmv1.AddUserToGroupRequest{
		GroupId: groupID, UserId: member.ID, UserIds: []string{member.ID},
	}, operator.Token))
	require.NoError(t, err)

	got, err := f.client.GetUserGroup(f.ctx(), authed(&pmv1.GetUserGroupRequest{Id: groupID}, operator.Token))
	require.NoError(t, err)
	assert.Equal(t, int32(1), got.Msg.Group.MemberCount)
	require.Len(t, got.Msg.Members, 1)
	assert.Equal(t, member.ID, got.Msg.Members[0].UserId)
	assert.Equal(t, member.Email, got.Msg.Members[0].Email)

	listed, err := f.client.ListUserGroups(f.ctx(), authed(&pmv1.ListUserGroupsRequest{PageSize: 10}, operator.Token))
	require.NoError(t, err)
	require.Len(t, listed.Msg.Groups, 1)
	assert.Equal(t, groupID, listed.Msg.Groups[0].Id)
	assert.Equal(t, int32(1), listed.Msg.TotalCount)

	forUser, err := f.client.ListUserGroupsForUser(f.ctx(), authed(&pmv1.ListUserGroupsForUserRequest{
		UserId: member.ID,
	}, operator.Token))
	require.NoError(t, err)
	require.Len(t, forUser.Msg.Groups, 1)
	assert.Equal(t, groupID, forUser.Msg.Groups[0].Id)

	updated, err := f.client.UpdateUserGroup(f.ctx(), authed(&pmv1.UpdateUserGroupRequest{
		GroupId: groupID, Name: "Platform operators", Description: "renamed",
	}, operator.Token))
	require.NoError(t, err)
	assert.Equal(t, "Platform operators", updated.Msg.Group.Name)

	windowed, err := f.client.SetUserGroupMaintenanceWindow(f.ctx(), authed(&pmv1.SetUserGroupMaintenanceWindowRequest{
		Id: groupID, MaintenanceWindow: &pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{{
			Days: []string{"mon"}, Allow: "09:00-17:00",
		}}},
	}, operator.Token))
	require.NoError(t, err)
	require.NotNil(t, windowed.Msg.Group.MaintenanceWindow)
	require.Len(t, windowed.Msg.Group.MaintenanceWindow.Schedule, 1)

	_, err = f.client.RemoveUserFromGroup(f.ctx(), authed(&pmv1.RemoveUserFromGroupRequest{
		GroupId: groupID, UserId: member.ID,
	}, operator.Token))
	require.NoError(t, err)
	var afterVersion int32
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT session_version FROM users WHERE id = $1`, member.ID).Scan(&afterVersion))
	assert.Equal(t, beforeVersion+2, afterVersion, "membership add and removal each invalidate existing sessions")

	_, err = f.client.DeleteUserGroup(f.ctx(), authed(&pmv1.DeleteUserGroupRequest{Id: groupID}, operator.Token))
	require.NoError(t, err)
	_, err = f.client.GetUserGroup(f.ctx(), authed(&pmv1.GetUserGroupRequest{Id: groupID}, operator.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err))

	createOp := f.onlyOperationFor(powermanagev1connect.ControlServiceCreateUserGroupProcedure)
	assert.Equal(t, operator.ID, createOp.ActorID)
	assert.Equal(t, "CreateStaticUserGroup", createOp.AuthorizationDetail)
	assert.Equal(t, "CREATE", f.effectWithAction(f.effectsOf(createOp.OperationID), "CREATE").Action)
	assert.Len(t, f.operationsFor(powermanagev1connect.ControlServiceAddUserToGroupProcedure), 1)
	assert.Len(t, f.operationsFor(powermanagev1connect.ControlServiceRemoveUserFromGroupProcedure), 1)
	assert.Len(t, f.operationsFor(powermanagev1connect.ControlServiceDeleteUserGroupProcedure), 1)
}

func TestUserGroups_DynamicMembershipRejectsManualChanges(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	operator := f.seedActor(grant{Permissions: []string{
		"CreateDynamicUserGroup", "AddUserToGroup", "RemoveUserFromGroup",
	}})
	member := f.seedSubject()
	created, err := f.client.CreateUserGroup(f.ctx(), authed(&pmv1.CreateUserGroupRequest{
		Name: "Disabled", IsDynamic: true, DynamicQuery: `user.disabled equals "true"`,
	}, operator.Token))
	require.NoError(t, err)

	_, err = f.client.AddUserToGroup(f.ctx(), authed(&pmv1.AddUserToGroupRequest{
		GroupId: created.Msg.Group.Id, UserId: member.ID,
	}, operator.Token))
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err))
	_, err = f.client.RemoveUserFromGroup(f.ctx(), authed(&pmv1.RemoveUserFromGroupRequest{
		GroupId: created.Msg.Group.Id, UserId: member.ID,
	}, operator.Token))
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err))
}

func TestDeleteUserGroup_AllowsRemovingFinalAdminGrant(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	soleAdmin := f.seedSubject()
	groupID := f.insertUserGroup()
	f.addUserToGroup(groupID, soleAdmin.ID)
	const adminRoleID = "00000000000000000000000001"
	_, err := f.raw.Exec(f.ctx(),
		`INSERT INTO user_group_roles (grant_id, group_id, role_id, assigned_at, assigned_by)
		 VALUES ($1, $2, $3, $4, '')`, newULID(), groupID, adminRoleID, f.now)
	require.NoError(t, err)
	token := f.mintToken(soleAdmin.ID, soleAdmin.Email)

	_, err = f.client.DeleteUserGroup(f.ctx(), authed(&pmv1.DeleteUserGroupRequest{Id: groupID}, token))
	require.NoError(t, err)
	var deleted bool
	require.NoError(t, f.raw.QueryRow(f.ctx(), `SELECT is_deleted FROM user_groups WHERE id = $1`, groupID).Scan(&deleted))
	assert.True(t, deleted)
	assert.Len(t, f.operationsFor(powermanagev1connect.ControlServiceDeleteUserGroupProcedure), 1)
}

func TestDynamicUserGroups_ValidateUpdateAndEvaluateDirectState(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	operator := f.seedActor(grant{Permissions: []string{
		"CreateDynamicUserGroup", "ValidateUserGroupQuery", "UpdateDynamicUserGroupQuery",
		"EvaluateDynamicUserGroup", "GetUserGroup",
	}})
	matched := f.seedSubject()
	disabled := f.seedSubject()
	_, err := f.raw.Exec(f.ctx(), `UPDATE users SET disabled = TRUE WHERE id = $1`, disabled.ID)
	require.NoError(t, err)

	preview, err := f.client.ValidateUserGroupQuery(f.ctx(), authed(&pmv1.ValidateUserGroupQueryRequest{
		Query: `user.disabled equals "true"`,
	}, operator.Token))
	require.NoError(t, err)
	assert.True(t, preview.Msg.Valid)
	assert.Equal(t, int32(1), preview.Msg.MatchingUserCount)

	invalid, err := f.client.ValidateUserGroupQuery(f.ctx(), authed(&pmv1.ValidateUserGroupQueryRequest{
		Query: `user.has_password equals "true"`,
	}, operator.Token))
	require.NoError(t, err)
	assert.False(t, invalid.Msg.Valid, "removed local-auth state cannot remain a dynamic-group field")

	created, err := f.client.CreateUserGroup(f.ctx(), authed(&pmv1.CreateUserGroupRequest{
		Name: "Selected user", IsDynamic: true,
		DynamicQuery: `user.email equals "` + matched.Email + `"`,
	}, operator.Token))
	require.NoError(t, err)
	groupID := created.Msg.Group.Id

	first, err := f.client.EvaluateDynamicUserGroup(f.ctx(), authed(&pmv1.EvaluateDynamicUserGroupRequest{Id: groupID}, operator.Token))
	require.NoError(t, err)
	assert.Equal(t, int32(1), first.Msg.UsersAdded)
	assert.Zero(t, first.Msg.UsersRemoved)
	assert.Equal(t, int32(1), first.Msg.Group.MemberCount)

	updated, err := f.client.UpdateUserGroupQuery(f.ctx(), authed(&pmv1.UpdateUserGroupQueryRequest{
		Id: groupID, IsDynamic: true, DynamicQuery: `user.disabled equals "true"`,
	}, operator.Token))
	require.NoError(t, err)
	assert.Equal(t, `user.disabled equals "true"`, updated.Msg.Group.DynamicQuery)

	second, err := f.client.EvaluateDynamicUserGroup(f.ctx(), authed(&pmv1.EvaluateDynamicUserGroupRequest{Id: groupID}, operator.Token))
	require.NoError(t, err)
	assert.Equal(t, int32(1), second.Msg.UsersAdded)
	assert.Equal(t, int32(1), second.Msg.UsersRemoved)
	got, err := f.client.GetUserGroup(f.ctx(), authed(&pmv1.GetUserGroupRequest{Id: groupID}, operator.Token))
	require.NoError(t, err)
	require.Len(t, got.Msg.Members, 1)
	assert.Equal(t, disabled.ID, got.Msg.Members[0].UserId)

	materialized, err := f.client.UpdateUserGroupQuery(f.ctx(), authed(&pmv1.UpdateUserGroupQueryRequest{
		Id: groupID, IsDynamic: false,
	}, operator.Token))
	require.NoError(t, err)
	assert.False(t, materialized.Msg.Group.IsDynamic)
	assert.Equal(t, int32(1), materialized.Msg.Group.MemberCount, "materializing preserves the compiled membership")
	_, err = f.client.EvaluateDynamicUserGroup(f.ctx(), authed(&pmv1.EvaluateDynamicUserGroupRequest{Id: groupID}, operator.Token))
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err))

	ops := f.operationsFor(powermanagev1connect.ControlServiceEvaluateDynamicUserGroupProcedure)
	require.Len(t, ops, 2)
	evaluate := f.effectWithAction(f.effectsOf(ops[0].OperationID), "EVALUATE")
	require.NotNil(t, evaluate.BeforeCount)
	require.NotNil(t, evaluate.AfterCount)
	assert.Equal(t, int64(0), *evaluate.BeforeCount)
	assert.Equal(t, int64(1), *evaluate.AfterCount)
}

func TestEvaluateDynamicUserGroup_AllowsRemovingFinalAdminMembership(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	soleAdmin := f.seedSubject()
	groupID := f.insertUserGroup()
	_, err := f.raw.Exec(f.ctx(),
		`UPDATE user_groups SET is_dynamic = TRUE, dynamic_query = 'user.disabled equals "true"' WHERE id = $1`, groupID)
	require.NoError(t, err)
	f.addUserToGroup(groupID, soleAdmin.ID)
	const adminRoleID = "00000000000000000000000001"
	_, err = f.raw.Exec(f.ctx(),
		`INSERT INTO user_group_roles (grant_id, group_id, role_id, assigned_at, assigned_by)
		 VALUES ($1, $2, $3, $4, '')`, newULID(), groupID, adminRoleID, f.now)
	require.NoError(t, err)
	token := f.mintToken(soleAdmin.ID, soleAdmin.Email)

	_, err = f.client.EvaluateDynamicUserGroup(f.ctx(), authed(&pmv1.EvaluateDynamicUserGroupRequest{Id: groupID}, token))
	require.NoError(t, err)
	members, err := f.store.ListUserGroupMembers(f.ctx(), groupID)
	require.NoError(t, err)
	assert.Empty(t, members)
	assert.Len(t, f.operationsFor(powermanagev1connect.ControlServiceEvaluateDynamicUserGroupProcedure), 1)
}
