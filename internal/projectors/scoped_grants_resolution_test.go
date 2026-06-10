package projectors_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// plantRoleWithPerms creates a role granting the given permissions and
// returns its id.
func plantRoleWithPerms(t *testing.T, st *store.Store, ctx context.Context, perms ...string) string {
	t.Helper()
	id := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: id, EventType: "RoleCreated",
		Data:      map[string]any{"name": "role-" + id, "permissions": perms},
		ActorType: "user", ActorID: "u",
	}))
	return id
}

func assignUserRole(t *testing.T, st *store.Store, ctx context.Context, userID, roleID string, scope map[string]any) {
	t.Helper()
	data := map[string]any{"user_id": userID, "role_id": roleID}
	for k, v := range scope {
		data[k] = v
	}
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role", StreamID: userID + ":" + roleID + scopeSuffix(scope),
		EventType: "UserRoleAssigned", Data: data, ActorType: "user", ActorID: "u",
	}))
}

func scopeSuffix(scope map[string]any) string {
	if id, ok := scope["scope_id"].(string); ok {
		return ":" + id
	}
	return ""
}

// grantKey renders a (permission, scope) tuple for set comparison.
func grantKey(g store.ScopedGrant) string {
	return g.Permission + "|" + g.ScopeKind + "|" + g.ScopeID
}

func grantKeys(grants []store.ScopedGrant) map[string]bool {
	out := make(map[string]bool, len(grants))
	for _, g := range grants {
		out[grantKey(g)] = true
	}
	return out
}

// countPerm counts grants for a specific permission, so assertions are
// robust against any unrelated grants the test-user factory plants.
func countPerm(grants []store.ScopedGrant, perm string) int {
	n := 0
	for _, g := range grants {
		if g.Permission == perm {
			n++
		}
	}
	return n
}

// TestScopedGrantsResolution exercises User.ScopedGrants — the
// hand-maintained GetUserScopedGrants query that drives the JWT sgrants
// claim (#7 S2b). One container, a user per scenario.
func TestScopedGrantsResolution(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	t.Run("direct unscoped grant has empty scope", func(t *testing.T) {
		uid := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pw", "user")
		role := plantRoleWithPerms(t, st, ctx, "perm.a", "perm.b")
		assignUserRole(t, st, ctx, uid, role, nil)

		grants, err := st.Repos().User.ScopedGrants(ctx, uid)
		require.NoError(t, err)
		keys := grantKeys(grants)
		assert.True(t, keys["perm.a||"], "unscoped grant must carry empty scope")
		assert.True(t, keys["perm.b||"])
		assert.Equal(t, 1, countPerm(grants, "perm.a"))
		assert.Equal(t, 1, countPerm(grants, "perm.b"))
	})

	t.Run("direct device_group-scoped grant carries the scope tuple", func(t *testing.T) {
		uid := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pw", "user")
		role := plantRoleWithPerms(t, st, ctx, "perm.c")
		assignUserRole(t, st, ctx, uid, role, map[string]any{"scope_kind": "device_group", "scope_id": "dg-1"})

		grants, err := st.Repos().User.ScopedGrants(ctx, uid)
		require.NoError(t, err)
		require.Equal(t, 1, countPerm(grants, "perm.c"))
		assert.Contains(t, grants, store.ScopedGrant{Permission: "perm.c", ScopeKind: "device_group", ScopeID: "dg-1"})
	})

	t.Run("grant inherited via user-group membership is resolved with its scope", func(t *testing.T) {
		uid := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pw", "user")
		role := plantRoleWithPerms(t, st, ctx, "perm.d")
		gid := testutil.NewID()
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user_group", StreamID: gid, EventType: "UserGroupCreated",
			Data: map[string]any{"name": "ug-" + gid, "description": "x"}, ActorType: "user", ActorID: "u",
		}))
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user_group", StreamID: gid, EventType: "UserGroupMemberAdded",
			Data: map[string]any{"group_id": gid, "user_id": uid}, ActorType: "user", ActorID: "u",
		}))
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user_group", StreamID: gid, EventType: "UserGroupRoleAssigned",
			Data:      map[string]any{"group_id": gid, "role_id": role, "scope_kind": "device_group", "scope_id": "dg-2"},
			ActorType: "user", ActorID: "u",
		}))

		grants, err := st.Repos().User.ScopedGrants(ctx, uid)
		require.NoError(t, err)
		require.Equal(t, 1, countPerm(grants, "perm.d"))
		assert.Contains(t, grants, store.ScopedGrant{Permission: "perm.d", ScopeKind: "device_group", ScopeID: "dg-2"})
	})

	t.Run("user_group scope kind is preserved", func(t *testing.T) {
		uid := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pw", "user")
		role := plantRoleWithPerms(t, st, ctx, "perm.e")
		assignUserRole(t, st, ctx, uid, role, map[string]any{"scope_kind": "user_group", "scope_id": "ug-9"})

		grants, err := st.Repos().User.ScopedGrants(ctx, uid)
		require.NoError(t, err)
		require.Equal(t, 1, countPerm(grants, "perm.e"))
		assert.Contains(t, grants, store.ScopedGrant{Permission: "perm.e", ScopeKind: "user_group", ScopeID: "ug-9"})
	})

	t.Run("same permission at the same scope via two roles is deduped", func(t *testing.T) {
		uid := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pw", "user")
		r1 := plantRoleWithPerms(t, st, ctx, "perm.dup")
		r2 := plantRoleWithPerms(t, st, ctx, "perm.dup")
		assignUserRole(t, st, ctx, uid, r1, map[string]any{"scope_kind": "device_group", "scope_id": "dg-3"})
		assignUserRole(t, st, ctx, uid, r2, map[string]any{"scope_kind": "device_group", "scope_id": "dg-3"})

		grants, err := st.Repos().User.ScopedGrants(ctx, uid)
		require.NoError(t, err)
		assert.Equal(t, 1, countPerm(grants, "perm.dup"), "DISTINCT must collapse the same (permission, scope) from two roles")
	})

	t.Run("scoped and unscoped grants of the same permission coexist", func(t *testing.T) {
		uid := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pw", "user")
		role := plantRoleWithPerms(t, st, ctx, "perm.both")
		assignUserRole(t, st, ctx, uid, role, nil)
		assignUserRole(t, st, ctx, uid, role, map[string]any{"scope_kind": "device_group", "scope_id": "dg-4"})

		grants, err := st.Repos().User.ScopedGrants(ctx, uid)
		require.NoError(t, err)
		keys := grantKeys(grants)
		assert.True(t, keys["perm.both||"], "unscoped (global) grant present")
		assert.True(t, keys["perm.both|device_group|dg-4"], "scoped grant present")
		assert.Equal(t, 2, countPerm(grants, "perm.both"))
	})

	t.Run("no grants returns empty, not error", func(t *testing.T) {
		uid := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pw", "user")
		grants, err := st.Repos().User.ScopedGrants(ctx, uid)
		require.NoError(t, err)
		assert.Empty(t, grants)
	})
}
