package store_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// WS2 #3 — the events table is the audit trail and the single source of truth
// every projection rebuilds from. Append-only is enforced at the DB level
// (migration 011), not only in app code, so a compromised gateway / buggy
// query / operator with DB access cannot rewrite or erase history. These tests
// drive the REAL trigger on a live Postgres and prove the rejection path is the
// point — the invariant survives even a malicious raw query, not just the
// absence of such a query today.

func appendAuditEvent(t *testing.T, st *store.Store) string {
	t.Helper()
	streamID := testutil.NewID()
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "device",
		StreamID:   streamID,
		EventType:  "DeviceRegistered",
		Data:       map[string]any{"hostname": "append-only-host"},
		ActorType:  "system",
		ActorID:    "system",
	}))
	return streamID
}

func totalEvents(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	require.NoError(t, st.TestingPool().QueryRow(context.Background(), "SELECT count(*) FROM public.events").Scan(&n))
	return n
}

func TestEvents_RejectsUpdate(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	streamID := appendAuditEvent(t, st)

	var before string
	require.NoError(t, st.TestingPool().QueryRow(ctx, "SELECT data::text FROM public.events WHERE stream_id=$1", streamID).Scan(&before))

	_, err := st.TestingPool().Exec(ctx, `UPDATE public.events SET data='{"tampered":true}'::jsonb WHERE stream_id=$1`, streamID)
	require.Error(t, err, "UPDATE on the append-only events table must be rejected by the DB trigger")
	assert.Contains(t, err.Error(), "append-only")

	var after string
	require.NoError(t, st.TestingPool().QueryRow(ctx, "SELECT data::text FROM public.events WHERE stream_id=$1", streamID).Scan(&after))
	assert.Equal(t, before, after, "the row's data must be byte-for-byte unchanged after the rejected UPDATE")
}

func TestEvents_RejectsDelete(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	streamID := appendAuditEvent(t, st)

	_, err := st.TestingPool().Exec(ctx, "DELETE FROM public.events WHERE stream_id=$1", streamID)
	require.Error(t, err, "DELETE on the append-only events table must be rejected")
	assert.Contains(t, err.Error(), "append-only")

	var n int
	require.NoError(t, st.TestingPool().QueryRow(ctx, "SELECT count(*) FROM public.events WHERE stream_id=$1", streamID).Scan(&n))
	assert.Equal(t, 1, n, "the event row must still be present after the rejected DELETE")
}

func TestEvents_RejectsTruncate(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	appendAuditEvent(t, st)
	before := totalEvents(t, st)
	require.Positive(t, before)

	// A plain TRUNCATE is already blocked by the FK from child tables; CASCADE
	// bypasses that barrier and exercises the append-only trigger itself, which
	// must RAISE before anything is truncated.
	_, err := st.TestingPool().Exec(ctx, "TRUNCATE public.events CASCADE")
	require.Error(t, err, "TRUNCATE on the append-only events table must be rejected")
	assert.Contains(t, err.Error(), "append-only",
		"TRUNCATE must be rejected by the append-only trigger, not (only) the FK constraint")
	assert.Equal(t, before, totalEvents(t, st), "TRUNCATE must be rejected and leave every event in place")
}

// TestEvents_AppendAndRebuildStillWork proves the guard is INSERT/SELECT-only:
// normal appends succeed and RebuildAll (which TRUNCATEs only *_projection, never
// events) is unaffected by the trigger.
func TestEvents_AppendAndRebuildStillWork(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	streamID := appendAuditEvent(t, st) // append must still succeed with the trigger installed
	require.NotEmpty(t, streamID)

	res, err := st.RebuildAll(ctx, "users")
	require.NoError(t, err, "RebuildAll must still succeed — it TRUNCATEs only *_projection, never the events table")
	require.NotNil(t, res)
}

// TestNoSQLCQueryMutatesEvents is the self-discovering app-layer half of the
// invariant: scan the SQL sources + generated query code for any statement that
// UPDATEs/DELETEs/TRUNCATEs the BARE events table (*_projection and events_*
// identifiers are legitimately mutated). The DB trigger would reject such a query
// at runtime; this keeps it from being introduced silently in the first place.
func TestNoSQLCQueryMutatesEvents(t *testing.T) {
	// `events\b` matches only the bare table: `events_foo` has no word boundary
	// after `events` (the `_` is a word char), and `*_projection` never ends in
	// `events`.
	re := regexp.MustCompile(`(?is)(update\s+(public\.)?events\b|delete\s+from\s+(public\.)?events\b|truncate\s+(table\s+)?(public\.)?events\b)`)

	scanned := 0
	var violations []string
	for _, dir := range []string{"queries", "generated"} {
		entries, err := os.ReadDir(dir)
		require.NoErrorf(t, err, "read %s", dir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".sql") && !strings.HasSuffix(name, ".sql.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, name))
			require.NoError(t, err)
			scanned++
			for _, m := range re.FindAllString(string(data), -1) {
				violations = append(violations, name+": "+strings.Join(strings.Fields(m), " "))
			}
		}
	}
	require.Positive(t, scanned, "matches-zero guard: scanned no SQL files — the events-mutation check is mis-scoped")
	assert.Empty(t, violations, "no query may UPDATE/DELETE/TRUNCATE the append-only events table: %v", violations)
}
