package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// findGrant returns the RoleGrant for roleID at the given scope id
// ("" = unscoped), or nil.
func findGrant(grants []*pm.RoleGrant, roleID, scopeID string) *pm.RoleGrant {
	for _, g := range grants {
		if g.GetRole().GetId() == roleID && g.GetScopeId() == scopeID {
			return g
		}
	}
	return nil
}

// A role granted both scoped to a device group AND globally must come
// back as two RoleGrant entries carrying scope, while the legacy `roles`
// field stays de-duplicated. scope_name resolves to the group's name.
func TestGetUser_RoleGrantsCarryScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	roleH := api.NewRoleHandler(st, slog.Default())
	userH := api.NewUserHandler(st, slog.Default(), nil)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")
	role := testutil.CreateTestRole(t, st, adminID, "TTY", []string{"TerminalAdminLimited"})
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 2")

	_, err := roleH.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.NoError(t, err)
	_, err = roleH.AssignRoleToUser(ctx, connect.NewRequest(&pm.AssignRoleToUserRequest{
		UserId: target, RoleId: role, // no scope → global
	}))
	require.NoError(t, err)

	resp, err := userH.GetUser(ctx, connect.NewRequest(&pm.GetUserRequest{Id: target}))
	require.NoError(t, err)
	grants := resp.Msg.GetUser().GetRoleGrants()

	scoped := findGrant(grants, role, dg)
	require.NotNil(t, scoped, "device-group-scoped grant must appear in role_grants")
	assert.Equal(t, deviceGroupScope, scoped.GetScopeKind())
	assert.Equal(t, "Plant 2", scoped.GetScopeName(), "scope_name resolves to the device group's display name")

	global := findGrant(grants, role, "")
	require.NotNil(t, global, "the unscoped grant must appear as a separate role_grant")
	assert.Equal(t, pm.RoleGrantScopeKind_ROLE_GRANT_SCOPE_KIND_UNSPECIFIED, global.GetScopeKind())
	assert.Empty(t, global.GetScopeName())

	count := 0
	for _, r := range resp.Msg.GetUser().GetRoles() {
		if r.GetId() == role {
			count++
		}
	}
	assert.Equal(t, 1, count, "legacy roles field stays de-duplicated by role id")
}

// A user with no role grants returns an empty role_grants list (not nil
// surprises, no panic).
func TestGetUser_NoGrants_EmptyRoleGrants(t *testing.T) {
	st := testutil.SetupPostgres(t)
	userH := api.NewUserHandler(st, slog.Default(), nil)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	target := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "user")

	resp, err := userH.GetUser(testutil.AdminContext(adminID), connect.NewRequest(&pm.GetUserRequest{Id: target}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.GetUser().GetRoleGrants())
}

// A user-group scoped role grant round-trips through GetUserGroup.
func TestGetUserGroup_RoleGrantsCarryScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	groupH := api.NewUserGroupHandler(st, slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	group := testutil.CreateTestUserGroup(t, st, adminID, "Ops Team")
	role := testutil.CreateTestRole(t, st, adminID, "TTY", []string{"TerminalAdminFull"})
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant 7")

	_, err := groupH.AssignRoleToUserGroup(ctx, connect.NewRequest(&pm.AssignRoleToUserGroupRequest{
		GroupId: group, RoleId: role, ScopeKind: deviceGroupScope, ScopeId: dg,
	}))
	require.NoError(t, err)

	resp, err := groupH.GetUserGroup(ctx, connect.NewRequest(&pm.GetUserGroupRequest{Id: group}))
	require.NoError(t, err)

	scoped := findGrant(resp.Msg.GetGroup().GetRoleGrants(), role, dg)
	require.NotNil(t, scoped, "user-group's scoped role grant must appear in role_grants")
	assert.Equal(t, deviceGroupScope, scoped.GetScopeKind())
	assert.Equal(t, "Plant 7", scoped.GetScopeName())
}
