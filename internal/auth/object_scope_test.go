package auth

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ObjectScopeListFilter reduces the caller's JWT scoped grants to the union of
// device-group + user-group ids that confine their object access (#7 spec 14).
// It must read ONLY the JWT-backed context (UserContext.ScopedGrants) — never a
// DB lookup — so a scoped Search slices objects with zero round-trips.
func TestObjectScopeListFilter(t *testing.T) {
	t.Run("no caller in context fails closed (restricted, empty)", func(t *testing.T) {
		ids, restricted := ObjectScopeListFilter(context.Background())
		assert.True(t, restricted, "missing caller must restrict, never fail open")
		assert.Empty(t, ids)
	})

	t.Run("no scoped grants is unrestricted (global admin)", func(t *testing.T) {
		ctx := ctxWithGrants(
			ScopedGrant{Permission: "ListActionSets"},
			ScopedGrant{Permission: "GetAction"},
		)
		ids, restricted := ObjectScopeListFilter(ctx)
		assert.False(t, restricted, "an operator with only unscoped grants sees everything")
		assert.Empty(t, ids)
	})

	t.Run("device-group scope confines to that group", func(t *testing.T) {
		ctx := ctxWithGrants(
			ScopedGrant{Permission: "ListDevices", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"},
		)
		ids, restricted := ObjectScopeListFilter(ctx)
		assert.True(t, restricted)
		assert.Equal(t, []string{"dg1"}, ids)
	})

	t.Run("union of device- and user-group scope ids across grants", func(t *testing.T) {
		ctx := ctxWithGrants(
			ScopedGrant{Permission: "ListDevices", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"},
			ScopedGrant{Permission: "GetDevice", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg2"},
			ScopedGrant{Permission: "ListUsers", ScopeKind: ScopeKindUserGroup, ScopeID: "ug1"},
			ScopedGrant{Permission: "Whatever"}, // unscoped grant contributes nothing
		)
		ids, restricted := ObjectScopeListFilter(ctx)
		assert.True(t, restricted)
		sort.Strings(ids)
		assert.Equal(t, []string{"dg1", "dg2", "ug1"}, ids)
	})

	t.Run("duplicate scope ids are de-duplicated", func(t *testing.T) {
		ctx := ctxWithGrants(
			ScopedGrant{Permission: "ListDevices", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"},
			ScopedGrant{Permission: "GetDevice", ScopeKind: ScopeKindDeviceGroup, ScopeID: "dg1"},
		)
		ids, restricted := ObjectScopeListFilter(ctx)
		assert.True(t, restricted)
		assert.Equal(t, []string{"dg1"}, ids)
	})

	t.Run("a malformed scoped grant (kind set, id empty) fails CLOSED, never open", func(t *testing.T) {
		// A group-kind scoped grant with an empty id must NOT fall through to
		// unrestricted (org-wide) access — that would turn a malformed JWT into a
		// scope escalation (CR finding). The caller IS scoped, just to nothing.
		ctx := ctxWithGrants(
			ScopedGrant{Permission: "ListDevices", ScopeKind: ScopeKindDeviceGroup, ScopeID: ""},
		)
		ids, restricted := ObjectScopeListFilter(ctx)
		assert.True(t, restricted, "malformed scoped grant must restrict (fail closed), not grant global access")
		assert.Empty(t, ids)
	})
}
