package identity_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

func TestCreateRole_RecordsThePermissionCount(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateRole", "GetRole"}})

	resp, err := f.client.CreateRole(f.ctx(), authed(&pmv1.CreateRoleRequest{
		Name:        "Auditors",
		Description: "Read the audit log",
		Permissions: []string{"ListAuditEvents", "ListUsers"},
	}, admin.Token))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.Role)
	assert.ElementsMatch(t, []string{"ListAuditEvents", "ListUsers"}, resp.Msg.Role.Permissions)
	assert.False(t, resp.Msg.Role.IsSystem)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceCreateRoleProcedure)
	assert.Equal(t, "MUTATION", op.Class)
	assert.Equal(t, admin.ID, op.ActorID)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "CREATE")
	require.NotNil(t, effect.AfterCount)
	assert.Equal(t, int64(2), *effect.AfterCount)
}

func TestCreateRole_RejectsUnknownPermissionKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateRole"}})

	_, err := f.client.CreateRole(f.ctx(), authed(&pmv1.CreateRoleRequest{
		Name:        "Typo",
		Permissions: []string{"ListUsers", "LsitDevices"},
	}, admin.Token))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err),
		"a permission nobody can hold is dead weight in the role builder and a silent gap if it was a typo")
	assert.Zero(t, f.countAuditOperations())
}

func TestUpdateRole_RefusesSystemRolesAndInvalidatesHolderSessions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateRole", "UpdateRole", "AssignRoleToUser"}})

	_, err := f.client.UpdateRole(f.ctx(), authed(&pmv1.UpdateRoleRequest{
		RoleId:      auth.AdminRoleID,
		Name:        "Admin",
		Permissions: []string{"ListUsers"},
	}, admin.Token))
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err),
		"a system role is reconciled from the code registry; an edit here would be silently undone")

	// An ordinary role, held by a subject, then edited.
	created, err := f.client.CreateRole(f.ctx(), authed(&pmv1.CreateRoleRequest{
		Name: "Operators", Permissions: []string{"ListUsers"},
	}, admin.Token))
	require.NoError(t, err)
	holder := f.seedSubject()
	f.insertUserRoleGrant(holder.ID, created.Msg.Role.Id, "", "")

	before, err := f.store.GetUserSessionState(f.ctx(), holder.ID)
	require.NoError(t, err)

	_, err = f.client.UpdateRole(f.ctx(), authed(&pmv1.UpdateRoleRequest{
		RoleId: created.Msg.Role.Id, Name: "Operators", Permissions: []string{"ListUsers", "GetUser"},
	}, admin.Token))
	require.NoError(t, err)

	after, err := f.store.GetUserSessionState(f.ctx(), holder.ID)
	require.NoError(t, err)
	assert.Greater(t, after.SessionVersion, before.SessionVersion,
		"widening a role must not leave a session running under the old permission set")

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceUpdateRoleProcedure)
	effects := f.effectsOf(op.OperationID)
	invalidate := f.effectWithAction(effects, "INVALIDATE_HOLDER_SESSIONS")
	require.NotNil(t, invalidate.AfterCount)
	assert.Equal(t, int64(1), *invalidate.AfterCount)
}

func TestDeleteRole_RefusesARoleSomebodyStillHolds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"CreateRole", "DeleteRole"}})
	created, err := f.client.CreateRole(f.ctx(), authed(&pmv1.CreateRoleRequest{
		Name: "Temporary", Permissions: []string{"ListUsers"},
	}, admin.Token))
	require.NoError(t, err)

	holder := f.seedSubject()
	f.insertUserRoleGrant(holder.ID, created.Msg.Role.Id, "", "")

	_, err = f.client.DeleteRole(f.ctx(), authed(&pmv1.DeleteRoleRequest{Id: created.Msg.Role.Id}, admin.Token))
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err),
		"dropping a held role would be an authorization change disguised as a catalogue edit")

	// Once nobody holds it, the delete goes through.
	_, err = f.raw.Exec(f.ctx(), `DELETE FROM user_roles WHERE role_id = $1`, created.Msg.Role.Id)
	require.NoError(t, err)
	_, err = f.client.DeleteRole(f.ctx(), authed(&pmv1.DeleteRoleRequest{Id: created.Msg.Role.Id}, admin.Token))
	require.NoError(t, err)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceDeleteRoleProcedure)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "DELETE")
	require.NotNil(t, effect.AfterFlag)
	assert.True(t, *effect.AfterFlag)
}

func TestAssignRoleToUser_GrantsAndInvalidatesTheSubjectSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AssignRoleToUser"}})
	subject := f.seedSubject()
	role := f.insertRole([]string{"ListUsers"})

	before, err := f.store.GetUserSessionState(f.ctx(), subject.ID)
	require.NoError(t, err)

	_, err = f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId: subject.ID, RoleId: role,
	}, admin.Token))
	require.NoError(t, err)

	grants, err := f.store.ListUserRoleGrants(f.ctx(), subject.ID)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Nil(t, grants[0].ScopeID, "no scope was requested, so the grant is global")

	after, err := f.store.GetUserSessionState(f.ctx(), subject.ID)
	require.NoError(t, err)
	assert.Greater(t, after.SessionVersion, before.SessionVersion)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceAssignRoleToUserProcedure)
	effects := f.effectsOf(op.OperationID)
	grantEffect := f.effectWithAction(effects, "GRANT")
	assert.Equal(t, grants[0].GrantID, grantEffect.ResourceID,
		"the effect names the GRANT, not the role: revocation names a grant too")
	f.effectWithAction(effects, "INVALIDATE_SESSIONS")
}

// The same role can be held globally and at two scopes at once, so the
// unique indexes must allow it and each grant must be independently
// revocable.
func TestAssignRoleToUser_SameRoleGlobalAndAtTwoScopes(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AssignRoleToUser", "RevokeRoleFromUser", "AssignRoleScope"}})
	subject := f.seedSubject()
	role := f.insertRole([]string{"UpdateUserProfile"})
	groupA, groupB := f.insertUserGroup(), f.insertUserGroup()

	for _, req := range []*pmv1.AssignRoleToUserRequest{
		{UserId: subject.ID, RoleId: role},
		{UserId: subject.ID, RoleId: role, ScopeKind: pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_USER_GROUP, ScopeId: groupA},
		{UserId: subject.ID, RoleId: role, ScopeKind: pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_USER_GROUP, ScopeId: groupB},
	} {
		_, err := f.client.AssignRoleToUser(f.ctx(), authed(req, admin.Token))
		require.NoError(t, err)
	}

	grants, err := f.store.ListUserRoleGrants(f.ctx(), subject.ID)
	require.NoError(t, err)
	assert.Len(t, grants, 3, "one role, three distinct grants")

	// Revoking "the unscoped grant" takes exactly that one.
	_, err = f.client.RevokeRoleFromUser(f.ctx(), authed(&pmv1.RevokeRoleFromUserRequest{
		UserId: subject.ID, RoleId: role,
	}, admin.Token))
	require.NoError(t, err)
	grants, err = f.store.ListUserRoleGrants(f.ctx(), subject.ID)
	require.NoError(t, err)
	require.Len(t, grants, 2)
	for _, g := range grants {
		assert.NotNil(t, g.ScopeID, "only the unscoped grant was named, so only it was removed")
	}

	// Revoking it a second time matches nothing and says so, rather
	// than silently taking a scoped grant.
	_, err = f.client.RevokeRoleFromUser(f.ctx(), authed(&pmv1.RevokeRoleFromUserRequest{
		UserId: subject.ID, RoleId: role,
	}, admin.Token))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err))
}

func TestAssignRoleToUser_RejectsDuplicateGrantAtTheSameScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AssignRoleToUser"}})
	subject := f.seedSubject()
	role := f.insertRole([]string{"ListUsers"})

	_, err := f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId: subject.ID, RoleId: role,
	}, admin.Token))
	require.NoError(t, err)
	_, err = f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId: subject.ID, RoleId: role,
	}, admin.Token))
	assert.Equal(t, connect.CodeAlreadyExists, connectCodeOf(t, err))
}

// A role that can grant or widen privilege is global-only. Scoping it
// would be a lie: the authority its holder mints inside the scope is
// not itself confined to that scope.
func TestAssignRoleToUser_RefusesScopedGrantOfPrivilegeGrantingRole(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AssignRoleToUser", "AssignRoleScope"}})
	subject := f.seedSubject()
	group := f.insertUserGroup()

	privileged := f.insertRole([]string{"AssignRoleToUser"})
	_, err := f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId:    subject.ID,
		RoleId:    privileged,
		ScopeKind: pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_USER_GROUP,
		ScopeId:   group,
	}, admin.Token))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))

	grants, err := f.store.ListUserRoleGrants(f.ctx(), subject.ID)
	require.NoError(t, err)
	assert.Empty(t, grants, "the refused grant was never written")

	// The same role granted GLOBALLY is fine.
	_, err = f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId: subject.ID, RoleId: privileged,
	}, admin.Token))
	require.NoError(t, err, "the restriction is on scoping it, not on granting it")
}

// Every permission the registry marks privilege-granting must be
// refused when scoped, not just the one the test above picked.
func TestAssignRoleToUser_EveryPrivilegeGrantingPermissionRefusesAScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AssignRoleToUser", "AssignRoleScope"}})
	group := f.insertUserGroup()

	var privileged []string
	for _, p := range auth.AllPermissions() {
		if p.PrivilegeGranting {
			privileged = append(privileged, p.Key)
		}
	}
	require.NotEmpty(t, privileged,
		"the registry marks no permission privilege-granting; this test would pass vacuously")

	for _, key := range privileged {
		t.Run(key, func(t *testing.T) {
			subject := f.seedSubject()
			role := f.insertRole([]string{key})
			_, err := f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
				UserId:    subject.ID,
				RoleId:    role,
				ScopeKind: pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_USER_GROUP,
				ScopeId:   group,
			}, admin.Token))
			assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err),
				"%s can grant or widen privilege, so it must stay global-only", key)
		})
	}
}

// A permission that acts on devices cannot be confined by a user-group
// scope: the scope would not constrain it at all.
func TestAssignRoleToUser_RefusesAScopeOfTheWrongKind(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AssignRoleToUser", "AssignRoleScope"}})
	subject := f.seedSubject()
	userGroup := f.insertUserGroup()
	deviceGroup := f.insertDeviceGroup()

	deviceRole := f.insertRole([]string{"GetDevice"})
	_, err := f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId:    subject.ID,
		RoleId:    deviceRole,
		ScopeKind: pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_USER_GROUP,
		ScopeId:   userGroup,
	}, admin.Token))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))

	_, err = f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId:    subject.ID,
		RoleId:    deviceRole,
		ScopeKind: pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_DEVICE_GROUP,
		ScopeId:   deviceGroup,
	}, admin.Token))
	require.NoError(t, err, "the matching scope kind is accepted")
}

func TestAssignRoleToUser_RejectsHalfSetScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AssignRoleToUser", "AssignRoleScope"}})
	subject := f.seedSubject()
	role := f.insertRole([]string{"UpdateUserProfile"})

	_, err := f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId:    subject.ID,
		RoleId:    role,
		ScopeKind: pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_USER_GROUP,
	}, admin.Token))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err),
		"guessing which half of a scope was meant is how an unscoped grant gets minted by accident")
}

// A scope-limited administrator — one who holds AssignRoleScope only at
// a scope — may not mint an unscoped grant, and may not attach a scope
// outside their own authority.
func TestAssignRoleToUser_ScopeLimitedAdminCannotEscapeTheirScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ownScope := f.insertUserGroup()
	otherScope := f.insertUserGroup()
	subject := f.seedSubject()
	role := f.insertRole([]string{"UpdateUserProfile"})

	confined := f.seedActor(
		grant{Permissions: []string{"AssignRoleToUser"}},
		grant{Permissions: []string{"AssignRoleScope"}, ScopeKind: auth.ScopeKindUserGroup, ScopeID: ownScope},
	)

	_, err := f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId: subject.ID, RoleId: role,
	}, confined.Token))
	assert.Equal(t, connect.CodePermissionDenied, connectCodeOf(t, err),
		"an unscoped grant would extend a confined admin's reach to the whole fleet")

	_, err = f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId:    subject.ID,
		RoleId:    role,
		ScopeKind: pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_USER_GROUP,
		ScopeId:   otherScope,
	}, confined.Token))
	assert.Equal(t, connect.CodePermissionDenied, connectCodeOf(t, err),
		"a confined admin cannot mint a grant outside their own scope authority")

	_, err = f.client.AssignRoleToUser(f.ctx(), authed(&pmv1.AssignRoleToUserRequest{
		UserId:    subject.ID,
		RoleId:    role,
		ScopeKind: pmv1.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_USER_GROUP,
		ScopeId:   ownScope,
	}, confined.Token))
	require.NoError(t, err, "inside their own scope authority they may grant")
}

func TestAssignRoleToUserGroup_GrantsAndRevokesByScope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"AssignRoleToUserGroup", "RevokeRoleFromUserGroup"}})
	group := f.insertUserGroup()
	role := f.insertRole([]string{"UpdateUserProfile"})
	member := f.seedSubject()
	f.addUserToGroup(group, member.ID)
	before, err := f.store.GetUserSessionState(f.ctx(), member.ID)
	require.NoError(t, err)

	_, err = f.client.AssignRoleToUserGroup(f.ctx(), authed(&pmv1.AssignRoleToUserGroupRequest{
		GroupId: group, RoleId: role,
	}, admin.Token))
	require.NoError(t, err)
	afterGrant, err := f.store.GetUserSessionState(f.ctx(), member.ID)
	require.NoError(t, err)
	assert.Equal(t, before.SessionVersion+1, afterGrant.SessionVersion)

	grants, err := f.store.ListUserGroupRoleGrants(f.ctx(), group)
	require.NoError(t, err)
	require.Len(t, grants, 1)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceAssignRoleToUserGroupProcedure)
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "GRANT")
	assert.Equal(t, grants[0].GrantID, effect.ResourceID)

	_, err = f.client.RevokeRoleFromUserGroup(f.ctx(), authed(&pmv1.RevokeRoleFromUserGroupRequest{
		GroupId: group, RoleId: role,
	}, admin.Token))
	require.NoError(t, err)
	afterRevoke, err := f.store.GetUserSessionState(f.ctx(), member.ID)
	require.NoError(t, err)
	assert.Equal(t, before.SessionVersion+2, afterRevoke.SessionVersion)
	grants, err = f.store.ListUserGroupRoleGrants(f.ctx(), group)
	require.NoError(t, err)
	assert.Empty(t, grants)
}

func TestRevokeRoleFromUser_RefusesLastEnabledAdmin(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	soleAdmin := f.seedSubject()
	f.insertUserRoleGrant(soleAdmin.ID, auth.AdminRoleID, "", "")
	token := f.mintToken(soleAdmin.ID, soleAdmin.Email)

	_, err := f.client.RevokeRoleFromUser(f.ctx(), authed(&pmv1.RevokeRoleFromUserRequest{
		UserId: soleAdmin.ID, RoleId: auth.AdminRoleID,
	}, token))
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err))
	grants, err := f.store.ListUserRoleGrants(f.ctx(), soleAdmin.ID)
	require.NoError(t, err)
	require.Len(t, grants, 1, "the last-admin refusal must roll back the grant deletion")
}

func TestRevokeRoleFromUserGroup_RefusesLastEnabledAdmin(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	soleAdmin := f.seedSubject()
	group := f.insertUserGroup()
	f.addUserToGroup(group, soleAdmin.ID)
	_, err := f.raw.Exec(f.ctx(),
		`INSERT INTO user_group_roles (grant_id, group_id, role_id, assigned_at, assigned_by)
		 VALUES ($1, $2, $3, $4, '')`, newULID(), group, auth.AdminRoleID, f.now)
	require.NoError(t, err)
	token := f.mintToken(soleAdmin.ID, soleAdmin.Email)

	_, err = f.client.RevokeRoleFromUserGroup(f.ctx(), authed(&pmv1.RevokeRoleFromUserGroupRequest{
		GroupId: group, RoleId: auth.AdminRoleID,
	}, token))
	assert.Equal(t, connect.CodeFailedPrecondition, connectCodeOf(t, err))
	grants, err := f.store.ListUserGroupRoleGrants(f.ctx(), group)
	require.NoError(t, err)
	require.Len(t, grants, 1, "the last-admin refusal must roll back the group grant deletion")
}

// A role held through a group confers its permissions, and the token
// resolution sees them.
func TestGroupInheritedRole_ConfersItsPermissions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	group := f.insertUserGroup()
	role := f.insertRole([]string{"UpdateUserProfile"})
	_, err := f.raw.Exec(f.ctx(),
		`INSERT INTO user_group_roles (grant_id, group_id, role_id, assigned_at, assigned_by)
		 VALUES ($1, $2, $3, $4, '')`, newULID(), group, role, f.now)
	require.NoError(t, err)

	member := f.seedSubject()
	f.addUserToGroup(group, member.ID)
	token := f.mintToken(member.ID, member.Email)

	target := f.seedSubject()
	_, err = f.client.UpdateUserProfile(f.ctx(), authed(&pmv1.UpdateUserProfileRequest{
		Id: target.ID, DisplayName: "via group",
	}, token))
	require.NoError(t, err, "a role held through a group is real authority")

	inherited, err := f.store.ListInheritedRolesForUser(f.ctx(), member.ID)
	require.NoError(t, err)
	require.Len(t, inherited, 1)
	assert.Equal(t, role, inherited[0].RoleID)
	assert.Equal(t, group, inherited[0].GroupID)
}

func TestListPermissions_ExposesTheRegistryWithTargetKinds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	admin := f.seedActor(grant{Permissions: []string{"ListPermissions"}})

	resp, err := f.client.ListPermissions(f.ctx(), authed(&pmv1.ListPermissionsRequest{}, admin.Token))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Permissions, len(auth.AllPermissions()))

	byKey := make(map[string]*pmv1.PermissionInfo, len(resp.Msg.Permissions))
	for _, p := range resp.Msg.Permissions {
		byKey[p.Key] = p
	}
	require.Contains(t, byKey, "GetDevice")
	assert.Equal(t, pmv1.PermissionTargetKind_PERMISSION_TARGET_KIND_DEVICE, byKey["GetDevice"].TargetKind)
	require.Contains(t, byKey, "GetUser")
	assert.Equal(t, pmv1.PermissionTargetKind_PERMISSION_TARGET_KIND_USER, byKey["GetUser"].TargetKind)
	require.Contains(t, byKey, "CreateRole")
	assert.Equal(t, pmv1.PermissionTargetKind_PERMISSION_TARGET_KIND_UNSPECIFIED, byKey["CreateRole"].TargetKind,
		"a privilege-granting permission is never scopable, so it declares no target kind")

	// No local-credential or second-factor permission survives: human
	// identity is the identity provider's business. ListLpsPasswords and
	// RevealLpsPassword concern a MANAGED DEVICE's rotated local-administrator
	// password, not how a human signs in here.
	for _, gone := range []string{
		"UpdateUserPassword", "UpdateUserPassword:self",
		"SetupTOTP", "VerifyTOTP", "DisableTOTP", "GetTOTPStatus",
		"RegenerateBackupCodes", "AdminDisableUserTOTP",
	} {
		assert.NotContains(t, byKey, gone, "%s is a local-credential permission and must not exist", gone)
	}
}
