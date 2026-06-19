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

// adminViaGroup creates a user group that confers the Admin system role and a
// member who is therefore an admin ONLY via that group (no direct grant).
// Returns (groupID, memberID).
func adminViaGroup(t *testing.T, st *store.Store, actorID string) (group, member string) {
	t.Helper()
	adminRole, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)
	group = testutil.CreateTestUserGroup(t, st, actorID, "Admins-"+testutil.NewID())
	testutil.AssignRoleToTestGroup(t, st, actorID, group, adminRole.ID)
	member = testutil.CreateTestUser(t, st, testutil.NewID()+"@viagroup.com", "pass", "user")
	testutil.AddUserToTestGroup(t, st, actorID, group, member)
	return group, member
}

func adminRoleID(t *testing.T, st *store.Store) string {
	t.Helper()
	r, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)
	return r.ID
}

// countEnabledAdminsIncludingGroups counts enabled, non-deleted holders of the
// Admin role via a DIRECT grant OR via group membership.
func countEnabledAdminsIncludingGroups(t *testing.T, st *store.Store) int {
	t.Helper()
	ctx := context.Background()
	role, err := st.Repos().Role.GetByName(ctx, "Admin")
	require.NoError(t, err)
	direct, err := st.Repos().Role.ListUserIDsWithRole(ctx, role.ID)
	require.NoError(t, err)
	viaGroup, err := st.Repos().Role.ListUserIDsWithGroupRole(ctx, role.ID)
	require.NoError(t, err)
	seen := map[string]bool{}
	n := 0
	for _, id := range append(direct, viaGroup...) {
		if seen[id] {
			continue
		}
		seen[id] = true
		u, err := st.Repos().User.Get(ctx, id)
		require.NoError(t, err)
		if !u.Disabled && !u.IsDeleted {
			n++
		}
	}
	return n
}

// Finding #5: the last-admin guard must fire on the user-GROUP demotion paths
// (RevokeRoleFromUserGroup / RemoveUserFromGroup / DeleteUserGroup), not only the
// direct-user paths. When the sole administrator holds Admin via a group, each of
// these would otherwise silently orphan the deployment of all admin access.
func TestLastAdmin_GroupDemotionPaths_RejectWhenSoleAdminViaGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	groupH := api.NewUserGroupHandler(st, slog.Default())
	actor := testutil.NewID()
	caller := testutil.AdminContext(actor)
	group, member := adminViaGroup(t, st, actor)

	// (a) Revoking Admin from the admin-bearing group → rejected.
	_, err := groupH.RevokeRoleFromUserGroup(caller, connect.NewRequest(&pm.RevokeRoleFromUserGroupRequest{
		GroupId: group, RoleId: adminRoleID(t, st),
	}))
	require.Error(t, err, "revoking Admin from the sole admin's group must be refused")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	// (b) Removing the sole admin from the admin-bearing group → rejected.
	_, err = groupH.RemoveUserFromGroup(caller, connect.NewRequest(&pm.RemoveUserFromGroupRequest{
		GroupId: group, UserId: member,
	}))
	require.Error(t, err, "removing the sole admin from their admin group must be refused")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	// (c) Deleting the admin-bearing group → rejected.
	_, err = groupH.DeleteUserGroup(caller, connect.NewRequest(&pm.DeleteUserGroupRequest{Id: group}))
	require.Error(t, err, "deleting the sole admin's group must be refused")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

// With a second DIRECT admin present, each group-demotion path is allowed — the
// guard refuses only the LAST enabled admin, never legitimate demotions.
func TestLastAdmin_GroupDemotionPaths_AllowedWithSecondDirectAdmin(t *testing.T) {
	t.Run("revoke role from group", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		groupH := api.NewUserGroupHandler(st, slog.Default())
		actor := testutil.NewID()
		group, _ := adminViaGroup(t, st, actor)
		testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin") // 2nd DIRECT admin
		_, err := groupH.RevokeRoleFromUserGroup(testutil.AdminContext(actor), connect.NewRequest(&pm.RevokeRoleFromUserGroupRequest{
			GroupId: group, RoleId: adminRoleID(t, st),
		}))
		require.NoError(t, err)
	})
	t.Run("remove member from group", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		groupH := api.NewUserGroupHandler(st, slog.Default())
		actor := testutil.NewID()
		group, member := adminViaGroup(t, st, actor)
		testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
		_, err := groupH.RemoveUserFromGroup(testutil.AdminContext(actor), connect.NewRequest(&pm.RemoveUserFromGroupRequest{
			GroupId: group, UserId: member,
		}))
		require.NoError(t, err)
	})
	t.Run("delete group", func(t *testing.T) {
		st := testutil.SetupPostgres(t)
		groupH := api.NewUserGroupHandler(st, slog.Default())
		actor := testutil.NewID()
		group, _ := adminViaGroup(t, st, actor)
		testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
		_, err := groupH.DeleteUserGroup(testutil.AdminContext(actor), connect.NewRequest(&pm.DeleteUserGroupRequest{Id: group}))
		require.NoError(t, err)
	})
}

// TestLastAdmin_GroupDemotionPaths_DisabledAdminDoesNotCount pins that the
// survivor computation excludes DISABLED admins: a disabled direct admin must
// not be mistaken for the surviving administrator, so removing the sole ENABLED
// admin (held via a group) is still refused. Guards against the lockout where a
// soft-deleted/disabled admin is wrongly counted as a survivor.
func TestLastAdmin_GroupDemotionPaths_DisabledAdminDoesNotCount(t *testing.T) {
	st := testutil.SetupPostgres(t)
	groupH := api.NewUserGroupHandler(st, slog.Default())
	userH := api.NewUserHandler(st, slog.Default(), nil)
	actor := testutil.NewID()
	caller := testutil.AdminContext(actor)
	group, _ := adminViaGroup(t, st, actor)

	// A second (direct) admin exists, then is DISABLED — while two admins are
	// still enabled, so the disable itself is allowed.
	directAdmin := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	_, err := userH.SetUserDisabled(caller, connect.NewRequest(&pm.SetUserDisabledRequest{Id: directAdmin, Disabled: true}))
	require.NoError(t, err)

	// The only ENABLED admin is now the group member. Deleting that group must be
	// refused — the disabled direct admin is not a valid survivor.
	_, err = groupH.DeleteUserGroup(caller, connect.NewRequest(&pm.DeleteUserGroupRequest{Id: group}))
	require.Error(t, err, "a disabled admin must not be counted as the surviving administrator")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

// TestLastAdminGuard_ConcurrentDistinctRemovals_AcrossGroupPaths fires two
// admin-removing requests through DIFFERENT door types — one direct-role revoke,
// one group-membership removal — for two DISTINCT admins concurrently. The shared
// advisory lock must serialize them so the deployment keeps ≥1 enabled admin;
// without it both read the stale 2-admin count and race to zero (#369/#5).
func TestLastAdminGuard_ConcurrentDistinctRemovals_AcrossGroupPaths(t *testing.T) {
	st := testutil.SetupPostgres(t)
	roleH := api.NewRoleHandler(st, slog.Default())
	groupH := api.NewUserGroupHandler(st, slog.Default())
	actor := testutil.NewID()
	adminRole, err := st.Repos().Role.GetByName(context.Background(), "Admin")
	require.NoError(t, err)

	directAdmin := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	group, groupAdmin := adminViaGroup(t, st, actor)
	caller := testutil.AdminContext(actor)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = roleH.RevokeRoleFromUser(caller, connect.NewRequest(&pm.RevokeRoleFromUserRequest{
			UserId: directAdmin, RoleId: adminRole.ID,
		}))
	}()
	go func() {
		defer wg.Done()
		_, _ = groupH.RemoveUserFromGroup(caller, connect.NewRequest(&pm.RemoveUserFromGroupRequest{
			GroupId: group, UserId: groupAdmin,
		}))
	}()
	wg.Wait()

	require.GreaterOrEqual(t, countEnabledAdminsIncludingGroups(t, st), 1,
		"a direct-revoke and a group-remove racing for two distinct admins must not zero out admins (#369/#5)")
}
