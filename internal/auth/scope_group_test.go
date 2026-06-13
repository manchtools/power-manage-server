package auth

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EnforceDeviceGroupScope confines a group-management action to a SPECIFIC
// device group by a DIRECT scope-id match (is this group one of the caller's
// device-group scope ids), not a membership lookup. Group-management permissions
// (GetDeviceGroup, RenameDeviceGroup, …) have no :assigned tier, so a caller who
// does not hold the base permission is denied outright.
func TestEnforceDeviceGroupScope(t *testing.T) {
	t.Run("unrestricted base allows any group", func(t *testing.T) {
		ctx := ctxWith([]string{"RenameDeviceGroup"}, ScopedGrant{Permission: "RenameDeviceGroup"})
		assert.NoError(t, EnforceDeviceGroupScope(ctx, "RenameDeviceGroup", "dgZ"))
	})

	t.Run("base perm with no scoped grant is unrestricted", func(t *testing.T) {
		ctx := ctxWith([]string{"RenameDeviceGroup"})
		assert.NoError(t, EnforceDeviceGroupScope(ctx, "RenameDeviceGroup", "dgZ"))
	})

	t.Run("device-group-scoped allows the matching group, denies others", func(t *testing.T) {
		ctx := ctxWith([]string{"RenameDeviceGroup"}, ScopedGrant{Permission: "RenameDeviceGroup", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		assert.NoError(t, EnforceDeviceGroupScope(ctx, "RenameDeviceGroup", "dg1"))
		err := EnforceDeviceGroupScope(ctx, "RenameDeviceGroup", "dg2")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	// A direct-id match, NOT membership: a device-group grant for dg1 does not let
	// the caller manage dg2 even if dg2 happens to share member devices with dg1.
	t.Run("matches the group id directly, not by shared members", func(t *testing.T) {
		ctx := ctxWith([]string{"DeleteDeviceGroup"},
			ScopedGrant{Permission: "DeleteDeviceGroup", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"},
			ScopedGrant{Permission: "DeleteDeviceGroup", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg3"})
		assert.NoError(t, EnforceDeviceGroupScope(ctx, "DeleteDeviceGroup", "dg3"))
		err := EnforceDeviceGroupScope(ctx, "DeleteDeviceGroup", "dg2")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("wrong-kind scoped grant fails closed", func(t *testing.T) {
		ctx := ctxWith([]string{"RenameDeviceGroup"}, ScopedGrant{Permission: "RenameDeviceGroup", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		err := EnforceDeviceGroupScope(ctx, "RenameDeviceGroup", "dg1")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("lacking the base permission is denied", func(t *testing.T) {
		ctx := ctxWith([]string{"SomethingElse"})
		err := EnforceDeviceGroupScope(ctx, "RenameDeviceGroup", "dg1")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("unauthenticated is denied", func(t *testing.T) {
		err := EnforceDeviceGroupScope(context.Background(), "RenameDeviceGroup", "dg1")
		require.Error(t, err)
		assert.Equal(t, connect.CodeUnauthenticated, codeOf(err))
	})
}

// EnforceUserGroupScope is the user-group symmetric of EnforceDeviceGroupScope.
func TestEnforceUserGroupScope(t *testing.T) {
	t.Run("unrestricted base allows any group", func(t *testing.T) {
		ctx := ctxWith([]string{"DeleteUserGroup"}, ScopedGrant{Permission: "DeleteUserGroup"})
		assert.NoError(t, EnforceUserGroupScope(ctx, "DeleteUserGroup", "ugZ"))
	})

	t.Run("base perm with no scoped grant is unrestricted", func(t *testing.T) {
		ctx := ctxWith([]string{"DeleteUserGroup"})
		assert.NoError(t, EnforceUserGroupScope(ctx, "DeleteUserGroup", "ugZ"))
	})

	t.Run("user-group-scoped allows the matching group, denies others", func(t *testing.T) {
		ctx := ctxWith([]string{"DeleteUserGroup"}, ScopedGrant{Permission: "DeleteUserGroup", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		assert.NoError(t, EnforceUserGroupScope(ctx, "DeleteUserGroup", "ug1"))
		err := EnforceUserGroupScope(ctx, "DeleteUserGroup", "ug2")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	// A direct-id match, NOT membership: a user-group grant for ug1/ug3 does not
	// let the caller manage ug2.
	t.Run("matches the group id directly, not by shared members", func(t *testing.T) {
		ctx := ctxWith([]string{"DeleteUserGroup"},
			ScopedGrant{Permission: "DeleteUserGroup", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"},
			ScopedGrant{Permission: "DeleteUserGroup", ScopeKind: ScopeKindUserGroup, ScopeID: "ug3"})
		assert.NoError(t, EnforceUserGroupScope(ctx, "DeleteUserGroup", "ug3"))
		err := EnforceUserGroupScope(ctx, "DeleteUserGroup", "ug2")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("wrong-kind scoped grant fails closed", func(t *testing.T) {
		ctx := ctxWith([]string{"DeleteUserGroup"}, ScopedGrant{Permission: "DeleteUserGroup", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		err := EnforceUserGroupScope(ctx, "DeleteUserGroup", "ug1")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("lacking the base permission is denied", func(t *testing.T) {
		ctx := ctxWith([]string{"SomethingElse"})
		err := EnforceUserGroupScope(ctx, "DeleteUserGroup", "ug1")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("unauthenticated is denied", func(t *testing.T) {
		err := EnforceUserGroupScope(context.Background(), "DeleteUserGroup", "ug1")
		require.Error(t, err)
		assert.Equal(t, connect.CodeUnauthenticated, codeOf(err))
	})
}

// DeviceScopeListFilter reduces the caller's device-group scope for a list
// permission to (groupIDs, restricted). restricted=false ⇒ no group filtering;
// restricted=true ⇒ restrict rows to devices in groupIDs (empty ⇒ nothing).
func TestDeviceScopeListFilter(t *testing.T) {
	t.Run("unrestricted base → not restricted", func(t *testing.T) {
		ctx := ctxWith([]string{"ListDevices"}, ScopedGrant{Permission: "ListDevices"})
		ids, restricted := DeviceScopeListFilter(ctx, "ListDevices")
		assert.False(t, restricted)
		assert.Empty(t, ids)
	})

	t.Run("base perm with no scoped grant → not restricted", func(t *testing.T) {
		ctx := ctxWith([]string{"ListDevices"})
		_, restricted := DeviceScopeListFilter(ctx, "ListDevices")
		assert.False(t, restricted)
	})

	t.Run("device-group-scoped → restricted to those groups", func(t *testing.T) {
		ctx := ctxWith([]string{"ListDevices"},
			ScopedGrant{Permission: "ListDevices", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"},
			ScopedGrant{Permission: "ListDevices", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg2"})
		ids, restricted := DeviceScopeListFilter(ctx, "ListDevices")
		assert.True(t, restricted)
		assert.ElementsMatch(t, []string{"dg1", "dg2"}, ids)
	})

	// :assigned-only callers don't hold the base perm; the owner SQL filter
	// confines them, so the group filter must NOT also apply (it would be a
	// second, wrong restriction).
	t.Run("assigned-only tier → not restricted (owner filter handles it)", func(t *testing.T) {
		ctx := ctxWith([]string{"ListDevices:assigned"})
		_, restricted := DeviceScopeListFilter(ctx, "ListDevices")
		assert.False(t, restricted)
	})

	// Defense-in-depth: a base holder with only a wrong-kind grant must restrict
	// to NOTHING, never read as unrestricted.
	t.Run("wrong-kind scoped grant → restricted to nothing", func(t *testing.T) {
		ctx := ctxWith([]string{"ListDevices"}, ScopedGrant{Permission: "ListDevices", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		ids, restricted := DeviceScopeListFilter(ctx, "ListDevices")
		assert.True(t, restricted)
		assert.Empty(t, ids)
	})

	// No caller in context ⇒ fail closed (restrict to nothing), never fail open.
	t.Run("unauthenticated → restricted to nothing", func(t *testing.T) {
		ids, restricted := DeviceScopeListFilter(context.Background(), "ListDevices")
		assert.True(t, restricted)
		assert.Empty(t, ids)
	})
}

// UserScopeListFilter is the user-group symmetric of DeviceScopeListFilter.
func TestUserScopeListFilter(t *testing.T) {
	t.Run("unrestricted base → not restricted", func(t *testing.T) {
		ctx := ctxWith([]string{"ListUsers"}, ScopedGrant{Permission: "ListUsers"})
		_, restricted := UserScopeListFilter(ctx, "ListUsers")
		assert.False(t, restricted)
	})

	t.Run("base perm with no scoped grant → not restricted", func(t *testing.T) {
		ctx := ctxWith([]string{"ListUsers"})
		_, restricted := UserScopeListFilter(ctx, "ListUsers")
		assert.False(t, restricted)
	})

	// Lacking the base permission (e.g. only a :self tier) ⇒ the group filter does
	// not apply here; the caller is confined by other means (or denied upstream).
	t.Run("no base permission → not restricted", func(t *testing.T) {
		ctx := ctxWith([]string{"GetUser:self"})
		_, restricted := UserScopeListFilter(ctx, "ListUsers")
		assert.False(t, restricted)
	})

	t.Run("user-group-scoped → restricted to those groups", func(t *testing.T) {
		ctx := ctxWith([]string{"ListUsers"}, ScopedGrant{Permission: "ListUsers", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		ids, restricted := UserScopeListFilter(ctx, "ListUsers")
		assert.True(t, restricted)
		assert.ElementsMatch(t, []string{"ug1"}, ids)
	})

	t.Run("wrong-kind scoped grant → restricted to nothing", func(t *testing.T) {
		ctx := ctxWith([]string{"ListUsers"}, ScopedGrant{Permission: "ListUsers", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		ids, restricted := UserScopeListFilter(ctx, "ListUsers")
		assert.True(t, restricted)
		assert.Empty(t, ids)
	})

	t.Run("unauthenticated → restricted to nothing", func(t *testing.T) {
		_, restricted := UserScopeListFilter(context.Background(), "ListUsers")
		assert.True(t, restricted)
	})
}
