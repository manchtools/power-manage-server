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
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestValkeySearch_FacetScope_ConfinesAndGates is the H4 behavioral regression:
// the executions / device_groups / user_groups facets used to leak fleet-wide via
// Search (no scope_group_ids field → no confining clause), and audit_events had
// no permission gate at all (a Search-only holder read the whole audit log). This
// drives the REAL search handler against a REAL valkey-search backend and proves
// each facet is now confined (groups/executions) or gated (audit_events).
//
// Pre-fix this test fails: device_groups/user_groups/executions return the
// out-of-scope object, and the audit_events sub-test returns the log to a caller
// without ListAuditEvents.
func TestValkeySearch_FacetScope_ConfinesAndGates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping valkey-search integration test in short mode")
	}
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	admin := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	// Device groups: caller is scoped to dgA; dgB is out of scope.
	dgA := testutil.CreateTestDeviceGroup(t, st, admin, "Fleet A")
	dgB := testutil.CreateTestDeviceGroup(t, st, admin, "Fleet B")

	// A device in each group, and an execution targeting each device. An
	// execution inherits its target device's device-group scope (H4).
	deviceA := testutil.CreateTestDevice(t, st, "host-a")
	deviceB := testutil.CreateTestDevice(t, st, "host-b")
	testutil.AddDeviceToTestGroup(t, st, admin, dgA, deviceA)
	testutil.AddDeviceToTestGroup(t, st, admin, dgB, deviceB)
	execA := createTestExecution(t, st, admin, deviceA)
	execB := createTestExecution(t, st, admin, deviceB)

	// User groups: a separate caller is scoped to ugA; ugB is out of scope.
	ugA := testutil.CreateTestUserGroup(t, st, admin, "Eng")
	ugB := testutil.CreateTestUserGroup(t, st, admin, "Ops")

	idx := testutil.SetupValkeySearch(t, st)
	require.NoError(t, idx.Rebuild(ctx), "backfill the search index")

	sh := api.NewSearchHandler(slog.Default())
	sh.SetSearchIndex(idx)

	search := func(c context.Context, scope pm.SearchScope) map[string]bool {
		resp, err := sh.Search(c, connect.NewRequest(&pm.SearchRequest{Scope: scope, PageSize: 200}))
		require.NoError(t, err)
		ids := map[string]bool{}
		for _, r := range resp.Msg.Results {
			ids[r.Id] = true
		}
		return ids
	}

	scopedToDgA := testutil.AuthContextScoped(testutil.NewID(), "dev@test.com",
		[]string{"Search"},
		[]auth.ScopedGrant{{Permission: "Search", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgA}})
	scopedToUgA := testutil.AuthContextScoped(testutil.NewID(), "usr@test.com",
		[]string{"Search"},
		[]auth.ScopedGrant{{Permission: "Search", ScopeKind: auth.ScopeKindUserGroup, ScopeID: ugA}})

	t.Run("device_groups facet confines to the caller's scope group", func(t *testing.T) {
		got := search(scopedToDgA, pm.SearchScope_SEARCH_SCOPE_DEVICE_GROUPS)
		assert.True(t, got[dgA], "in-scope device group must be visible")
		assert.False(t, got[dgB], "out-of-scope device group must be confined")
	})

	t.Run("executions facet confines to the target device's scope group", func(t *testing.T) {
		got := search(scopedToDgA, pm.SearchScope_SEARCH_SCOPE_EXECUTIONS)
		assert.True(t, got[execA], "execution on an in-scope device must be visible")
		assert.False(t, got[execB], "execution on an out-of-scope device must be confined")
	})

	t.Run("user_groups facet confines to the caller's scope group", func(t *testing.T) {
		got := search(scopedToUgA, pm.SearchScope_SEARCH_SCOPE_USER_GROUPS)
		assert.True(t, got[ugA], "in-scope user group must be visible")
		assert.False(t, got[ugB], "out-of-scope user group must be confined")
	})

	t.Run("audit_events facet is gated by ListAuditEvents", func(t *testing.T) {
		// Every state change above wrote an event, all indexed as audit_events.
		denied := testutil.AuthContextScoped(testutil.NewID(), "d@test.com",
			[]string{"Search"}, []auth.ScopedGrant{{Permission: "Search"}})
		allowed := testutil.AuthContextScoped(testutil.NewID(), "a@test.com",
			[]string{"Search", "ListAuditEvents"}, []auth.ScopedGrant{{Permission: "Search"}})

		assert.Empty(t, search(denied, pm.SearchScope_SEARCH_SCOPE_AUDIT_EVENTS),
			"a Search holder without ListAuditEvents must NOT read the audit log via Search")
		assert.NotEmpty(t, search(allowed, pm.SearchScope_SEARCH_SCOPE_AUDIT_EVENTS),
			"a caller with ListAuditEvents sees audit events (gate must not block a permitted caller)")
	})
}

// createTestExecution appends an ExecutionCreated event so the executions
// projection (and, after Rebuild, the search index) carries a row targeting
// deviceID. Returns the execution id.
func createTestExecution(t *testing.T, st *store.Store, actorID, deviceID string) string {
	t.Helper()
	execID := testutil.NewID()
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   execID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":     deviceID,
			"action_type":   1,
			"desired_state": 1,
			"params":        map[string]any{"name": "nginx"},
		},
		ActorType: "user",
		ActorID:   actorID,
	}))
	return execID
}
