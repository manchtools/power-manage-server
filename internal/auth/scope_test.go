package auth

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResolver answers membership from in-memory maps and can be forced
// to error.
type fakeResolver struct {
	deviceGroups map[string][]string // deviceID -> group ids
	userGroups   map[string][]string // userID -> group ids
	err          error
}

func (f *fakeResolver) DeviceGroupsForDevice(_ context.Context, deviceID string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.deviceGroups[deviceID], nil
}

func (f *fakeResolver) UserGroupsForUser(_ context.Context, userID string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.userGroups[userID], nil
}

func ctxWithGrants(grants ...ScopedGrant) context.Context {
	return WithUser(context.Background(), &UserContext{ID: "caller", ScopedGrants: grants})
}

func codeOf(err error) connect.Code {
	return connect.CodeOf(err)
}

func TestDeviceScopeFilterFor(t *testing.T) {
	t.Run("unscoped grant is global", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p"})
		f := DeviceScopeFilterFor(ctx, "p")
		assert.True(t, f.Global)
		assert.Empty(t, f.GroupIDs)
	})

	t.Run("device_group grants collect their group ids", func(t *testing.T) {
		ctx := ctxWithGrants(
			ScopedGrant{Permission: "p", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"},
			ScopedGrant{Permission: "p", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg2"},
		)
		f := DeviceScopeFilterFor(ctx, "p")
		assert.False(t, f.Global)
		assert.ElementsMatch(t, []string{"dg1", "dg2"}, f.GroupIDs)
	})

	t.Run("any unscoped grant wins over scoped ones (global)", func(t *testing.T) {
		ctx := ctxWithGrants(
			ScopedGrant{Permission: "p", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"},
			ScopedGrant{Permission: "p"},
		)
		assert.True(t, DeviceScopeFilterFor(ctx, "p").Global)
	})

	t.Run("a user_group-scoped grant of a device permission grants no device access", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		f := DeviceScopeFilterFor(ctx, "p")
		assert.False(t, f.Global)
		assert.Empty(t, f.GroupIDs, "cross-kind scope must be ignored for device targets")
	})

	t.Run("a different permission's scope does not leak", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "other", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		f := DeviceScopeFilterFor(ctx, "p")
		assert.False(t, f.Global)
		assert.Empty(t, f.GroupIDs)
	})
}

func TestEnforceDeviceScope(t *testing.T) {
	res := &fakeResolver{deviceGroups: map[string][]string{
		"devA": {"dg1", "dg9"},
		"devB": {"dg2"},
	}}

	t.Run("unauthenticated", func(t *testing.T) {
		err := EnforceDeviceScope(context.Background(), res, "p", "devA")
		require.Error(t, err)
		assert.Equal(t, connect.CodeUnauthenticated, codeOf(err))
	})

	t.Run("global grant allows any device", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p"})
		assert.NoError(t, EnforceDeviceScope(ctx, res, "p", "devA"))
		assert.NoError(t, EnforceDeviceScope(ctx, res, "p", "devB"))
	})

	t.Run("device inside a scoped group is allowed", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		assert.NoError(t, EnforceDeviceScope(ctx, res, "p", "devA"))
	})

	t.Run("device outside the scoped group is denied", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		err := EnforceDeviceScope(ctx, res, "p", "devB")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("permission held only via user_group scope is denied for devices", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		err := EnforceDeviceScope(ctx, res, "p", "devA")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("no grant for the permission is denied", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "other"})
		err := EnforceDeviceScope(ctx, res, "p", "devA")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("resolver error surfaces as internal, not allow", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		boom := &fakeResolver{err: errors.New("db down")}
		err := EnforceDeviceScope(ctx, boom, "p", "devA")
		require.Error(t, err)
		assert.Equal(t, connect.CodeInternal, codeOf(err))
	})
}

func TestEnforceUserScope(t *testing.T) {
	res := &fakeResolver{userGroups: map[string][]string{
		"userX": {"ug1"},
		"userY": {"ug2"},
	}}

	t.Run("global grant allows any user target", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p"})
		assert.NoError(t, EnforceUserScope(ctx, res, "p", "userX"))
	})

	t.Run("target user inside a scoped user-group is allowed", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		assert.NoError(t, EnforceUserScope(ctx, res, "p", "userX"))
	})

	t.Run("target user outside the scoped user-group is denied", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		err := EnforceUserScope(ctx, res, "p", "userY")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("a device_group-scoped grant grants no user access", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "p", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		err := EnforceUserScope(ctx, res, "p", "userX")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})
}

func TestTargetKindFor(t *testing.T) {
	assert.Equal(t, TargetDevice, TargetKindFor("ListDevices"))
	assert.Equal(t, TargetUser, TargetKindFor("GetUser"))
	assert.Equal(t, TargetUnspecified, TargetKindFor("GetCurrentUser"))
	assert.Equal(t, TargetUnspecified, TargetKindFor("NoSuchPermission"), "unknown key is the safe non-scopable default")
}

func TestRolePermissionsScopableWith(t *testing.T) {
	t.Run("all device perms scopable with device_group", func(t *testing.T) {
		_, ok := RolePermissionsScopableWith([]string{"ListDevices", "GetDevice", "StartTerminal"}, ScopeKindDeviceGroup)
		assert.True(t, ok)
	})
	t.Run("a non-device perm rejects a device_group scope", func(t *testing.T) {
		bad, ok := RolePermissionsScopableWith([]string{"ListDevices", "GetUser"}, ScopeKindDeviceGroup)
		assert.False(t, ok)
		assert.Equal(t, "GetUser", bad)
	})
	t.Run("a TargetUnspecified perm is never scopable", func(t *testing.T) {
		bad, ok := RolePermissionsScopableWith([]string{"GetCurrentUser"}, ScopeKindDeviceGroup)
		assert.False(t, ok)
		assert.Equal(t, "GetCurrentUser", bad)
	})
	t.Run("user perms scopable with user_group", func(t *testing.T) {
		_, ok := RolePermissionsScopableWith([]string{"GetUser"}, ScopeKindUserGroup)
		assert.True(t, ok)
	})
	t.Run("device perm not scopable with user_group", func(t *testing.T) {
		bad, ok := RolePermissionsScopableWith([]string{"ListDevices"}, ScopeKindUserGroup)
		assert.False(t, ok)
		assert.Equal(t, "ListDevices", bad)
	})
	t.Run("unknown scope kind is not scopable", func(t *testing.T) {
		_, ok := RolePermissionsScopableWith([]string{"ListDevices"}, "garbage")
		assert.False(t, ok)
	})
}

func TestEnforceGrantScopeAuthority(t *testing.T) {
	t.Run("global AssignRoleScope may grant any scope", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: AssignRoleScopePermission})
		assert.NoError(t, EnforceGrantScopeAuthority(ctx, ScopeKindDeviceGroup, "dg-anything"))
	})
	t.Run("scoped AssignRoleScope may grant its own scope", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: AssignRoleScopePermission, ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		assert.NoError(t, EnforceGrantScopeAuthority(ctx, ScopeKindDeviceGroup, "dg1"))
	})
	t.Run("scoped AssignRoleScope may NOT grant a different scope", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: AssignRoleScopePermission, ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		err := EnforceGrantScopeAuthority(ctx, ScopeKindDeviceGroup, "dg2")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})
	t.Run("device-scoped authority does not authorize a user_group grant", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: AssignRoleScopePermission, ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		err := EnforceGrantScopeAuthority(ctx, ScopeKindUserGroup, "dg1")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})
}

func TestEnforceUnscopedGrantAuthority(t *testing.T) {
	t.Run("no scope authority (ordinary admin) may grant unscoped", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: "AssignRoleToUser"})
		assert.NoError(t, EnforceUnscopedGrantAuthority(ctx))
	})
	t.Run("global AssignRoleScope (org admin) may grant unscoped", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: AssignRoleScopePermission})
		assert.NoError(t, EnforceUnscopedGrantAuthority(ctx))
	})
	t.Run("scope-limited admin may NOT grant unscoped", func(t *testing.T) {
		ctx := ctxWithGrants(ScopedGrant{Permission: AssignRoleScopePermission, ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		err := EnforceUnscopedGrantAuthority(ctx)
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})
}
