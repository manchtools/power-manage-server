package auth

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ctxWith builds a caller context carrying both the flat permission set (what
// HasPermission reads) and the detailed scoped grants (what the scope filters
// read) — mirroring how the JWT claims are populated: a scoped grant's BASE
// permission is in the flat set, the scope lives in the grant.
func ctxWith(perms []string, grants ...ScopedGrant) context.Context {
	return WithUser(context.Background(), &UserContext{ID: "caller", Permissions: perms, ScopedGrants: grants})
}

func TestEnforceUserScopeOrSelf(t *testing.T) {
	res := &fakeResolver{userGroups: map[string][]string{
		"userX":  {"ug1"},
		"userY":  {"ug2"},
		"caller": {"ug1"},
	}}

	t.Run("unrestricted base allows any target", func(t *testing.T) {
		ctx := ctxWith([]string{"GetUser"}, ScopedGrant{Permission: "GetUser"})
		assert.NoError(t, EnforceUserScopeOrSelf(ctx, res, "GetUser", "userY"))
	})

	// Flat base permission with no scoping grant (the AuthContext fixture shape;
	// in production an unscoped grant is always present) ⇒ unrestricted.
	t.Run("base perm with no scoped grant is unrestricted", func(t *testing.T) {
		ctx := ctxWith([]string{"GetUser"})
		assert.NoError(t, EnforceUserScopeOrSelf(ctx, res, "GetUser", "userY"))
	})

	t.Run("user-group-scoped allows a target inside the scope", func(t *testing.T) {
		ctx := ctxWith([]string{"GetUser"}, ScopedGrant{Permission: "GetUser", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		assert.NoError(t, EnforceUserScopeOrSelf(ctx, res, "GetUser", "userX"))
	})

	// THE load-bearing case: a scoped holder carries the base permission in the
	// flat set, so a naive HasPermission(base) check would wave them through to
	// ANY user. They must instead be CONFINED to their scope.
	t.Run("user-group-scoped is DENIED for a target outside the scope", func(t *testing.T) {
		ctx := ctxWith([]string{"GetUser"}, ScopedGrant{Permission: "GetUser", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		err := EnforceUserScopeOrSelf(ctx, res, "GetUser", "userY")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	// Defense-in-depth: a base holder with a scoped grant of the WRONG kind
	// (a device_group grant on a user-target perm) must fail CLOSED, not be
	// treated as unrestricted. rejectUnscopableRole should prevent creating
	// such a grant, but this layer must never read it as fleet-wide access.
	t.Run("wrong-kind scoped grant fails closed (not unrestricted)", func(t *testing.T) {
		ctx := ctxWith([]string{"GetUser"}, ScopedGrant{Permission: "GetUser", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		err := EnforceUserScopeOrSelf(ctx, res, "GetUser", "userX")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("self tier allows only own id", func(t *testing.T) {
		ctx := ctxWith([]string{"GetUser:self"})
		assert.NoError(t, EnforceUserScopeOrSelf(ctx, res, "GetUser", "caller"))
		err := EnforceUserScopeOrSelf(ctx, res, "GetUser", "userX")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("no relevant grant is denied", func(t *testing.T) {
		ctx := ctxWith([]string{"SomethingElse"})
		err := EnforceUserScopeOrSelf(ctx, res, "GetUser", "caller")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("unauthenticated is denied", func(t *testing.T) {
		err := EnforceUserScopeOrSelf(context.Background(), res, "GetUser", "userX")
		require.Error(t, err)
		assert.Equal(t, connect.CodeUnauthenticated, codeOf(err))
	})
}

func TestEnforceDeviceScopeOnBaseTier(t *testing.T) {
	res := &fakeResolver{deviceGroups: map[string][]string{
		"devX": {"dg1"},
		"devY": {"dg2"},
	}}

	t.Run("unrestricted base allows any device", func(t *testing.T) {
		ctx := ctxWith([]string{"GetDevice"}, ScopedGrant{Permission: "GetDevice"})
		assert.NoError(t, EnforceDeviceScopeOnBaseTier(ctx, res, "GetDevice", "devY"))
	})

	t.Run("base perm with no scoped grant is unrestricted", func(t *testing.T) {
		ctx := ctxWith([]string{"GetDevice"})
		assert.NoError(t, EnforceDeviceScopeOnBaseTier(ctx, res, "GetDevice", "devY"))
	})

	t.Run("device-group-scoped confines to the scope", func(t *testing.T) {
		ctx := ctxWith([]string{"GetDevice"}, ScopedGrant{Permission: "GetDevice", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"})
		assert.NoError(t, EnforceDeviceScopeOnBaseTier(ctx, res, "GetDevice", "devX"))
		err := EnforceDeviceScopeOnBaseTier(ctx, res, "GetDevice", "devY")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	// :assigned-only callers do NOT hold the base permission, so device-group
	// scope does not apply here — the assigned-owner SQL filter confines them.
	t.Run("assigned-only tier passes through (owner filter handles it)", func(t *testing.T) {
		ctx := ctxWith([]string{"GetDevice:assigned"})
		assert.NoError(t, EnforceDeviceScopeOnBaseTier(ctx, res, "GetDevice", "devY"))
	})

	// Defense-in-depth: a base holder with a wrong-kind scoped grant (a
	// user_group grant on a device-target perm) fails CLOSED.
	t.Run("wrong-kind scoped grant fails closed (not unrestricted)", func(t *testing.T) {
		ctx := ctxWith([]string{"GetDevice"}, ScopedGrant{Permission: "GetDevice", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"})
		err := EnforceDeviceScopeOnBaseTier(ctx, res, "GetDevice", "devX")
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, codeOf(err))
	})

	t.Run("unauthenticated is denied", func(t *testing.T) {
		err := EnforceDeviceScopeOnBaseTier(context.Background(), res, "GetDevice", "devX")
		require.Error(t, err)
		assert.Equal(t, connect.CodeUnauthenticated, codeOf(err))
	})
}
