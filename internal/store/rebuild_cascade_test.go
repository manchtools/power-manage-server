package store_test

// Spec 21 (F-03 / manchtools/power-manage-server#506): a PARTIAL rebuild
// must never TRUNCATE a table it will not replay. `RebuildAll("users")`
// TRUNCATEs users_projection CASCADE, which the live FK graph fans out
// to totp_projection, identity_links_projection, and
// user_group_members_projection — tables replayed by OTHER targets
// (totp, identity_providers, user_groups). Without cascade-safe target
// expansion those rows are silently destroyed: the #497 data-loss class
// through the partial path.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// seedUsersCascadeChildren creates one user plus one row in each FK child
// table that `TRUNCATE users_projection CASCADE` wipes: a TOTP enrollment,
// an identity link, and a user-group membership. Returns the ids needed
// for the survival assertions.
func seedUsersCascadeChildren(t *testing.T, st *store.Store) (userID, linkID, groupID string) {
	t.Helper()
	ctx := context.Background()

	userID = testutil.CreateTestUser(t, st, "cascade-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPSetupInitiated",
		Data: map[string]any{
			"secret_encrypted":  "enc:v2:fixture",
			"backup_codes_hash": []string{"h1", "h2"},
		},
		ActorType: "user",
		ActorID:   userID,
	}))

	// identity_links_projection FKs onto identity_providers_projection,
	// so the link needs a real provider row.
	enc := testutil.NewEncryptor(t)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, userID, "Cascade IdP", "cascade-"+testutil.NewID()[:8])

	linkID = testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   linkID,
		EventType:  "IdentityLinked",
		Data: map[string]any{
			"user_id":        userID,
			"provider_id":    providerID,
			"external_id":    "ext-" + linkID,
			"external_email": "cascade@example.com",
		},
		ActorType: "system",
		ActorID:   "sso",
	}))

	groupID = testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   groupID,
		EventType:  "UserGroupCreated",
		Data:       map[string]any{"name": "cascade-grp-" + groupID[:8], "description": ""},
		ActorType:  "user",
		ActorID:    userID,
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   groupID + ":" + userID,
		EventType:  "UserGroupMemberAdded",
		Data:       map[string]any{"group_id": groupID, "user_id": userID},
		ActorType:  "user",
		ActorID:    userID,
	}))

	return userID, linkID, groupID
}

func countRows(t *testing.T, st *store.Store, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, st.TestingPool().QueryRow(context.Background(), query, args...).Scan(&n))
	return n
}

// findTargetResult returns the named entry of a RebuildResult. The run
// set may be wider than the requested targets (cascade-safe expansion),
// so callers must locate their target rather than index by position.
func findTargetResult(t *testing.T, res store.RebuildResult, name string) store.TargetResult {
	t.Helper()
	for _, tr := range res.Targets {
		if tr.Name == name {
			return tr
		}
	}
	t.Fatalf("target %q missing from rebuild result: %v", name, res.Targets)
	return store.TargetResult{}
}

// TestRebuildAll_PartialUsers_CascadeChildrenSurvive pins spec 21 AC 4/5:
// a users-only rebuild auto-includes every target needed to re-derive the
// tables its CASCADE wipes, so TOTP enrollments, identity links, and
// group memberships survive — and the result names the expanded set.
func TestRebuildAll_PartialUsers_CascadeChildrenSurvive(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	userID, linkID, groupID := seedUsersCascadeChildren(t, st)

	// Seed sanity — each child row exists before the rebuild.
	require.Equal(t, 1, countRows(t, st, `SELECT COUNT(*) FROM totp_projection WHERE user_id = $1`, userID))
	require.Equal(t, 1, countRows(t, st, `SELECT COUNT(*) FROM identity_links_projection WHERE id = $1`, linkID))
	require.Equal(t, 1, countRows(t, st, `SELECT COUNT(*) FROM user_group_members_projection WHERE group_id = $1 AND user_id = $2`, groupID, userID))

	res, err := st.RebuildAll(ctx, "users")
	require.NoError(t, err)

	assert.Equal(t, 1, countRows(t, st, `SELECT COUNT(*) FROM totp_projection WHERE user_id = $1`, userID),
		"TOTP enrollment must survive a users-only rebuild (F-03)")
	assert.Equal(t, 1, countRows(t, st, `SELECT COUNT(*) FROM identity_links_projection WHERE id = $1`, linkID),
		"identity link must survive a users-only rebuild (F-03)")
	assert.Equal(t, 1, countRows(t, st, `SELECT COUNT(*) FROM user_group_members_projection WHERE group_id = $1 AND user_id = $2`, groupID, userID),
		"user-group membership must survive a users-only rebuild (second-order cascade: membership rows FK onto users_projection but are replayed by the user_groups target)")

	ran := make(map[string]bool, len(res.Targets))
	for _, tr := range res.Targets {
		ran[tr.Name] = true
	}
	for _, want := range []string{"users", "totp", "identity_providers", "user_groups"} {
		assert.Truef(t, ran[want], "expected auto-included target %q in the run set, got %v", want, res.Targets)
	}
}

// TestResolveTargets_ExpandsCascadeClosure pins the CLI-preview contract:
// ResolveTargets reports the same expanded, canonical-order set that
// RebuildAll would run, without touching any data.
func TestResolveTargets_ExpandsCascadeClosure(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	names, err := st.ResolveTargets(ctx, "users")
	require.NoError(t, err)
	assert.Contains(t, names, "users")
	assert.Contains(t, names, "totp", "cascade child totp_projection is owned by the totp target")
	assert.Contains(t, names, "identity_providers", "cascade child identity_links_projection is owned by the identity_providers target")
	assert.Contains(t, names, "user_groups", "unowned cascade child user_group_members_projection is re-derived by its FK parent's target")

	// Canonical order: expansion must preserve AllRebuildTargets order.
	idx := map[string]int{}
	for i, tgt := range store.AllRebuildTargets {
		idx[tgt.Name] = i
	}
	for i := 1; i < len(names); i++ {
		assert.Less(t, idx[names[i-1]], idx[names[i]],
			"resolved targets must be in canonical declaration order: %v", names)
	}

	// A no-arg resolve returns every target unchanged.
	all, err := st.ResolveTargets(ctx)
	require.NoError(t, err)
	require.Len(t, all, len(store.AllRebuildTargets))

	// Unknown names still reject.
	_, err = st.ResolveTargets(ctx, "nope")
	require.ErrorIs(t, err, store.ErrUnknownTarget)
}
