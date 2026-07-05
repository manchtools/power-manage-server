package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 19 AC 16 — the pre-prune snapshot: a projection state equal to
// the DETERMINISTIC REPLAY of events ≤ N, captured WITHOUT disturbing
// the live projection (which reflects events > N too).

// TestCaptureProjectionSnapshot_IsStateAtN pins that the snapshot holds
// state @ N — a user created at seq ≤ N appears, a user created AFTER N
// does NOT — while the live projection still shows both.
func TestCaptureProjectionSnapshot_IsStateAtN(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	early := testutil.CreateTestUser(t, st, "early-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	checkpoint := maxSeq(t, st)
	late := testutil.CreateTestUser(t, st, "late-"+testutil.NewID()[:8]+"@test.com", "pass", "user")

	snap, err := st.CaptureProjectionSnapshot(ctx, checkpoint)
	require.NoError(t, err)

	users := snap.Rows("users_projection")
	require.NotEmpty(t, users)
	ids := map[string]bool{}
	for _, r := range users {
		ids[snapID(t, r)] = true
	}
	assert.True(t, ids[early], "a user created ≤ N must be in the snapshot")
	assert.False(t, ids[late], "a user created AFTER N must NOT be in the snapshot")

	// The LIVE projection is untouched — both users still resolve.
	_, err = st.Repos().User.Get(ctx, early)
	assert.NoError(t, err)
	_, err = st.Repos().User.Get(ctx, late)
	assert.NoError(t, err, "capturing a snapshot must not disturb the live projection")
}

// TestCaptureProjectionSnapshot_CoversEveryTarget pins that the
// snapshot is column-complete over every AllRebuildTargets table
// (self-discovering — a new target is covered automatically).
func TestCaptureProjectionSnapshot_CoversEveryTarget(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	testutil.CreateTestUser(t, st, "cov-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")

	snap, err := st.CaptureProjectionSnapshot(ctx, maxSeq(t, st))
	require.NoError(t, err)

	for _, tgt := range store.AllRebuildTargets {
		for _, tbl := range tgt.Tables {
			_, present := snap.Tables()[tbl]
			assert.Truef(t, present, "snapshot must include rebuild-target table %q", tbl)
		}
	}
}

// snapID pulls the "id" field out of a to_jsonb-serialized projection row.
func snapID(t *testing.T, raw []byte) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	id, _ := m["id"].(string)
	return id
}
