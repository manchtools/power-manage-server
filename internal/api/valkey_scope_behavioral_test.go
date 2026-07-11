package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestValkeySearch_ObjectScope_ConfinesOutOfScope validates the spec 29 S1 /
// spec 30 test foundation: FT.SEARCH @scope_group_ids filtering, driven through
// the REAL search handler against a REAL valkey-search backend, actually confines
// a scope-restricted caller to in-scope objects. Until now this path was only
// clause-string ("does the query contain @scope_group_ids") unit-tested — a
// presence check, not behavior. This is the behavioral proof, and the template
// the Valkey-scoped List* behavioral tests build on.
func TestValkeySearch_ObjectScope_ConfinesOutOfScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	admin := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")
	dgA := testutil.CreateTestDeviceGroup(t, st, admin, "Fleet A") // caller is scoped here
	dgB := testutil.CreateTestDeviceGroup(t, st, admin, "Fleet B") // out of scope

	actionA := testutil.CreateTestAction(t, st, admin, "in-scope-action", int(pm.ActionType_ACTION_TYPE_SHELL))
	testutil.CreateTestAssignment(t, st, admin, "action", actionA, "device_group", dgA, 0)
	actionB := testutil.CreateTestAction(t, st, admin, "out-of-scope-action", int(pm.ActionType_ACTION_TYPE_SHELL))
	testutil.CreateTestAssignment(t, st, admin, "action", actionB, "device_group", dgB, 0)

	// Real valkey-search index, backfilled from Postgres (Rebuild computes each
	// object's scope_group_ids from its assignments).
	idx := testutil.SetupValkeySearch(t, st)
	require.NoError(t, idx.Rebuild(ctx), "backfill the search index")

	sh := api.NewSearchHandler(slog.Default())
	sh.SetSearchIndex(idx)

	search := func(c context.Context) map[string]bool {
		resp, err := sh.Search(c, connect.NewRequest(&pm.SearchRequest{
			Scope:    pm.SearchScope_SEARCH_SCOPE_ACTIONS,
			PageSize: 100,
		}))
		require.NoError(t, err)
		ids := map[string]bool{}
		for _, r := range resp.Msg.Results {
			ids[r.Id] = true
		}
		return ids
	}

	scopedToA := testutil.AuthContextScoped(testutil.NewID(), "scoped@test.com",
		[]string{"Search"},
		[]auth.ScopedGrant{{Permission: "Search", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgA}})
	globalCaller := testutil.AuthContextScoped(admin, "g@test.com",
		[]string{"Search"}, []auth.ScopedGrant{{Permission: "Search"}})

	t.Run("scope-restricted caller sees only the in-scope object", func(t *testing.T) {
		got := search(scopedToA)
		assert.True(t, got[actionA], "in-scope action must be visible")
		assert.False(t, got[actionB], "out-of-scope action must be confined by @scope_group_ids")
	})

	t.Run("global caller sees both", func(t *testing.T) {
		got := search(globalCaller)
		assert.True(t, got[actionA])
		assert.True(t, got[actionB])
	})
}

// TestValkeyList_ObjectScope_ConfinesOutOfScope is the S1 regression: ListActions
// (the leaking read surface) must confine a scope-restricted caller to in-scope
// actions — resolved from the search index, hydrated from Postgres — and never
// return an out-of-scope action's script/file contents. Drives the REAL handler
// against the REAL index; pre-fix ListActions returned the whole catalog.
func TestValkeyList_ObjectScope_ConfinesOutOfScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	admin := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")
	dgA := testutil.CreateTestDeviceGroup(t, st, admin, "Fleet A") // caller scoped here
	dgB := testutil.CreateTestDeviceGroup(t, st, admin, "Fleet B") // out of scope

	inScope := testutil.CreateTestAction(t, st, admin, "in-scope", int(pm.ActionType_ACTION_TYPE_SHELL))
	testutil.CreateTestAssignment(t, st, admin, "action", inScope, "device_group", dgA, 0)
	outScope := testutil.CreateTestAction(t, st, admin, "out-of-scope", int(pm.ActionType_ACTION_TYPE_SHELL))
	testutil.CreateTestAssignment(t, st, admin, "action", outScope, "device_group", dgB, 0)

	idx := testutil.SetupValkeySearch(t, st)
	require.NoError(t, idx.Rebuild(ctx))

	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
	h.SetSearchIndex(idx)

	list := func(c context.Context) (map[string]bool, int32) {
		resp, err := h.ListActions(c, connect.NewRequest(&pm.ListActionsRequest{PageSize: 100}))
		require.NoError(t, err)
		ids := map[string]bool{}
		for _, a := range resp.Msg.Actions {
			ids[a.Id] = true
		}
		return ids, resp.Msg.TotalCount
	}

	t.Run("scope-restricted caller lists only the in-scope action", func(t *testing.T) {
		got, total := list(testutil.AuthContextScoped(testutil.NewID(), "s@test.com",
			[]string{"ListActions"},
			[]auth.ScopedGrant{{Permission: "ListActions", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgA}}))
		assert.True(t, got[inScope], "in-scope action must be listed")
		assert.False(t, got[outScope], "out-of-scope action (and its script) must NOT be listed — this is the S1 leak")
		assert.Equal(t, int32(1), total, "TotalCount reflects the scoped set")
	})

	t.Run("global caller lists both", func(t *testing.T) {
		got, _ := list(testutil.AuthContextScoped(admin, "g@test.com",
			[]string{"ListActions"}, []auth.ScopedGrant{{Permission: "ListActions"}}))
		assert.True(t, got[inScope])
		assert.True(t, got[outScope])
	})
}
