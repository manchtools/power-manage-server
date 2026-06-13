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
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// deviceGroupScopeGrants builds a scoped-caller context holding each device-group
// management permission scoped ONLY to the given device groups.
func deviceGroupScopeGrants(perms, groupIDs []string) context.Context {
	var grants []auth.ScopedGrant
	for _, p := range perms {
		for _, g := range groupIDs {
			grants = append(grants, auth.ScopedGrant{Permission: p, ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: g})
		}
	}
	return testutil.AuthContextScoped(testutil.NewID(), "scoped@test.com", perms, grants)
}

// Finding #3 (device-group management): a caller holding a group-management
// permission scoped to device group dgX may act ONLY on dgX itself — a DIRECT
// scope-id match, not a membership lookup. Before enforcement these handlers had
// no scope gate at all, so a device-group-scoped admin could rename/delete ANY
// group. Each gate now confines via auth.EnforceDeviceGroupScope.
func TestDeviceGroupGates_GroupScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	dgX := testutil.CreateTestDeviceGroup(t, st, actor, "Plant X") // in scope
	dgY := testutil.CreateTestDeviceGroup(t, st, actor, "Plant Y") // out of scope

	perms := []string{
		"GetDeviceGroup", "RenameDeviceGroup", "UpdateDeviceGroupDescription",
		"DeleteDeviceGroup", "SetDeviceGroupSyncInterval", "SetDeviceGroupMaintenanceWindow",
	}
	scoped := func() context.Context { return deviceGroupScopeGrants(perms, []string{dgX}) }

	gates := []struct {
		name   string
		invoke func(ctx context.Context, groupID string) error
	}{
		{"GetDeviceGroup", func(ctx context.Context, id string) error {
			_, err := h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: id}))
			return err
		}},
		{"RenameDeviceGroup", func(ctx context.Context, id string) error {
			_, err := h.RenameDeviceGroup(ctx, connect.NewRequest(&pm.RenameDeviceGroupRequest{Id: id, Name: "renamed"}))
			return err
		}},
		{"UpdateDeviceGroupDescription", func(ctx context.Context, id string) error {
			_, err := h.UpdateDeviceGroupDescription(ctx, connect.NewRequest(&pm.UpdateDeviceGroupDescriptionRequest{Id: id, Description: "d"}))
			return err
		}},
		{"DeleteDeviceGroup", func(ctx context.Context, id string) error {
			_, err := h.DeleteDeviceGroup(ctx, connect.NewRequest(&pm.DeleteDeviceGroupRequest{Id: id}))
			return err
		}},
		{"SetDeviceGroupSyncInterval", func(ctx context.Context, id string) error {
			_, err := h.SetDeviceGroupSyncInterval(ctx, connect.NewRequest(&pm.SetDeviceGroupSyncIntervalRequest{Id: id, SyncIntervalMinutes: 30}))
			return err
		}},
		{"SetDeviceGroupMaintenanceWindow", func(ctx context.Context, id string) error {
			_, err := h.SetDeviceGroupMaintenanceWindow(ctx, connect.NewRequest(&pm.SetDeviceGroupMaintenanceWindowRequest{Id: id}))
			return err
		}},
	}

	for _, g := range gates {
		t.Run(g.name+" denies out-of-scope group", func(t *testing.T) {
			err := g.invoke(scoped(), dgY)
			require.Error(t, err, "a device-group-scoped caller must not manage a group outside the scope")
			assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
		})
		t.Run(g.name+" allows in-scope group", func(t *testing.T) {
			err := g.invoke(scoped(), dgX)
			// May fail for an unrelated reason (e.g. an empty maintenance window),
			// but it must NOT be denied by scope.
			if err != nil {
				assert.NotEqual(t, connect.CodePermissionDenied, connect.CodeOf(err),
					"in-scope group must not be denied by scope")
			}
		})
	}
}

// AddDeviceToGroup must scope-check BOTH the target group (direct id-match) AND
// each device added (membership) — otherwise a device-group-scoped admin could
// pull any fleet device into a group they control and so expand their own scope
// (a scope escape). The device check confines them to organizing devices ALREADY
// in their scope.
func TestAddDeviceToGroup_ScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	dgTarget := testutil.CreateTestDeviceGroup(t, st, actor, "Sub Group") // target, in scope
	dgBroad := testutil.CreateTestDeviceGroup(t, st, actor, "Broad")      // in scope, holds in-scope devices
	dgOther := testutil.CreateTestDeviceGroup(t, st, actor, "Other")      // out of scope

	devInScope := testutil.CreateTestDevice(t, st, "in-scope")
	testutil.AddDeviceToTestGroup(t, st, actor, dgBroad, devInScope)
	devOutOfScope := testutil.CreateTestDevice(t, st, "out-of-scope")

	// Caller is scoped to BOTH the target sub-group and the broad group that holds
	// in-scope devices, modelling the "organize my scoped devices into sub-groups"
	// use case the permissions.go note describes.
	scoped := func() context.Context {
		return deviceGroupScopeGrants([]string{"AddDeviceToGroup"}, []string{dgTarget, dgBroad})
	}

	t.Run("allows adding an in-scope device to an in-scope group", func(t *testing.T) {
		_, err := h.AddDeviceToGroup(scoped(), connect.NewRequest(&pm.AddDeviceToGroupRequest{GroupId: dgTarget, DeviceId: devInScope}))
		require.NoError(t, err)
	})

	t.Run("denies an out-of-scope target group", func(t *testing.T) {
		_, err := h.AddDeviceToGroup(scoped(), connect.NewRequest(&pm.AddDeviceToGroupRequest{GroupId: dgOther, DeviceId: devInScope}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("denies pulling an out-of-scope device into an in-scope group (scope escape)", func(t *testing.T) {
		_, err := h.AddDeviceToGroup(scoped(), connect.NewRequest(&pm.AddDeviceToGroupRequest{GroupId: dgTarget, DeviceId: devOutOfScope}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
}

// RemoveDeviceFromGroup confines to in-scope groups (direct id-match). Removal
// cannot expand scope, so only the group is gated.
func TestRemoveDeviceFromGroup_ScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	dgX := testutil.CreateTestDeviceGroup(t, st, actor, "Plant X")
	dgY := testutil.CreateTestDeviceGroup(t, st, actor, "Plant Y")
	dev := testutil.CreateTestDevice(t, st, "host")
	testutil.AddDeviceToTestGroup(t, st, actor, dgX, dev)

	scoped := func() context.Context {
		return deviceGroupScopeGrants([]string{"RemoveDeviceFromGroup"}, []string{dgX})
	}

	t.Run("allows removing from an in-scope group", func(t *testing.T) {
		_, err := h.RemoveDeviceFromGroup(scoped(), connect.NewRequest(&pm.RemoveDeviceFromGroupRequest{GroupId: dgX, DeviceId: dev}))
		require.NoError(t, err)
	})
	t.Run("denies an out-of-scope group", func(t *testing.T) {
		_, err := h.RemoveDeviceFromGroup(scoped(), connect.NewRequest(&pm.RemoveDeviceFromGroupRequest{GroupId: dgY, DeviceId: dev}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
}

// userGroupScopeGrants is the user-group symmetric of deviceGroupScopeGrants.
func userGroupScopeGrants(perms, groupIDs []string) context.Context {
	var grants []auth.ScopedGrant
	for _, p := range perms {
		for _, g := range groupIDs {
			grants = append(grants, auth.ScopedGrant{Permission: p, ScopeKind: auth.ScopeKindUserGroup, ScopeID: g})
		}
	}
	return testutil.AuthContextScoped(testutil.NewID(), "scoped@test.com", perms, grants)
}

// Finding #3 (user-group management): symmetric with the device-group case.
func TestUserGroupGates_GroupScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	ugX := testutil.CreateTestUserGroup(t, st, actor, "Team X")
	ugY := testutil.CreateTestUserGroup(t, st, actor, "Team Y")

	perms := []string{"GetUserGroup", "UpdateUserGroup", "DeleteUserGroup", "SetUserGroupMaintenanceWindow"}
	scoped := func() context.Context { return userGroupScopeGrants(perms, []string{ugX}) }

	gates := []struct {
		name   string
		invoke func(ctx context.Context, groupID string) error
	}{
		{"GetUserGroup", func(ctx context.Context, id string) error {
			_, err := h.GetUserGroup(ctx, connect.NewRequest(&pm.GetUserGroupRequest{Id: id}))
			return err
		}},
		{"UpdateUserGroup", func(ctx context.Context, id string) error {
			_, err := h.UpdateUserGroup(ctx, connect.NewRequest(&pm.UpdateUserGroupRequest{GroupId: id, Name: "renamed"}))
			return err
		}},
		{"DeleteUserGroup", func(ctx context.Context, id string) error {
			_, err := h.DeleteUserGroup(ctx, connect.NewRequest(&pm.DeleteUserGroupRequest{Id: id}))
			return err
		}},
		{"SetUserGroupMaintenanceWindow", func(ctx context.Context, id string) error {
			_, err := h.SetUserGroupMaintenanceWindow(ctx, connect.NewRequest(&pm.SetUserGroupMaintenanceWindowRequest{Id: id}))
			return err
		}},
	}

	for _, g := range gates {
		t.Run(g.name+" denies out-of-scope group", func(t *testing.T) {
			err := g.invoke(scoped(), ugY)
			require.Error(t, err, "a user-group-scoped caller must not manage a group outside the scope")
			assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
		})
		t.Run(g.name+" allows in-scope group", func(t *testing.T) {
			err := g.invoke(scoped(), ugX)
			if err != nil {
				assert.NotEqual(t, connect.CodePermissionDenied, connect.CodeOf(err),
					"in-scope group must not be denied by scope")
			}
		})
	}
}

// AddUserToGroup mirrors AddDeviceToGroup: group id-match AND per-user membership
// check to prevent pulling out-of-scope users into a group the admin controls.
func TestAddUserToGroup_ScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	ugTarget := testutil.CreateTestUserGroup(t, st, actor, "Sub Team")
	ugBroad := testutil.CreateTestUserGroup(t, st, actor, "Broad Team")
	ugOther := testutil.CreateTestUserGroup(t, st, actor, "Other Team")

	userInScope := testutil.CreateTestUser(t, st, testutil.NewID()+"@in.com", "pass", "user")
	testutil.AddUserToTestGroup(t, st, actor, ugBroad, userInScope)
	userOutOfScope := testutil.CreateTestUser(t, st, testutil.NewID()+"@out.com", "pass", "user")

	scoped := func() context.Context {
		return userGroupScopeGrants([]string{"AddUserToGroup"}, []string{ugTarget, ugBroad})
	}

	t.Run("allows adding an in-scope user to an in-scope group", func(t *testing.T) {
		_, err := h.AddUserToGroup(scoped(), connect.NewRequest(&pm.AddUserToGroupRequest{GroupId: ugTarget, UserId: userInScope}))
		require.NoError(t, err)
	})
	t.Run("denies an out-of-scope target group", func(t *testing.T) {
		_, err := h.AddUserToGroup(scoped(), connect.NewRequest(&pm.AddUserToGroupRequest{GroupId: ugOther, UserId: userInScope}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
	t.Run("denies pulling an out-of-scope user into an in-scope group (scope escape)", func(t *testing.T) {
		_, err := h.AddUserToGroup(scoped(), connect.NewRequest(&pm.AddUserToGroupRequest{GroupId: ugTarget, UserId: userOutOfScope}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
}

// RemoveUserFromGroup confines to in-scope groups (direct id-match).
func TestRemoveUserFromGroup_ScopeEnforced(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	ugX := testutil.CreateTestUserGroup(t, st, actor, "Team X")
	ugY := testutil.CreateTestUserGroup(t, st, actor, "Team Y")
	member := testutil.CreateTestUser(t, st, testutil.NewID()+"@m.com", "pass", "user")
	testutil.AddUserToTestGroup(t, st, actor, ugX, member)

	scoped := func() context.Context {
		return userGroupScopeGrants([]string{"RemoveUserFromGroup"}, []string{ugX})
	}

	t.Run("allows removing from an in-scope group", func(t *testing.T) {
		_, err := h.RemoveUserFromGroup(scoped(), connect.NewRequest(&pm.RemoveUserFromGroupRequest{GroupId: ugX, UserId: member}))
		require.NoError(t, err)
	})
	t.Run("denies an out-of-scope group", func(t *testing.T) {
		_, err := h.RemoveUserFromGroup(scoped(), connect.NewRequest(&pm.RemoveUserFromGroupRequest{GroupId: ugY, UserId: member}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
}
