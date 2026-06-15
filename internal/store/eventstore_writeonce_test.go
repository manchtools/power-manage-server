package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestEvents_RowIsWriteOnce pins the event store's append-only invariant at the
// DATABASE layer (migration 011's BEFORE UPDATE/DELETE/TRUNCATE trigger), not
// just in application code. Threat: a compromised relay or a SQL-capable insider
// must not be able to rewrite history or forge actor attribution — only INSERT
// (append) and SELECT succeed. Each mutation is driven via raw SQL on the pool
// (bypassing the app layer) so it actually exercises the trigger.
func TestEvents_RowIsWriteOnce(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()
	pool := st.TestingPool()

	streamID := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "test",
		StreamID:   streamID,
		EventType:  "WriteOnceProbe",
		Data:       map[string]any{"original": true},
		ActorType:  "system",
		ActorID:    "orig-actor",
	}))

	var id string
	require.NoError(t, pool.QueryRow(ctx, "SELECT id FROM events WHERE stream_id = $1", streamID).Scan(&id))

	// Each forbidden mutation must (a) error with an append-only message and
	// (b) leave the row untouched.
	mutations := []struct {
		name   string
		sql    string
		verify func(t *testing.T)
	}{
		{
			name: "forge actor_id",
			sql:  "UPDATE events SET actor_id = 'forged' WHERE id = $1",
			verify: func(t *testing.T) {
				var got string
				require.NoError(t, pool.QueryRow(ctx, "SELECT actor_id FROM events WHERE id = $1", id).Scan(&got))
				assert.Equal(t, "orig-actor", got, "actor attribution must be immutable")
			},
		},
		{
			name: "tamper payload",
			sql:  `UPDATE events SET data = '{"tampered":true}' WHERE id = $1`,
			verify: func(t *testing.T) {
				var original bool
				require.NoError(t, pool.QueryRow(ctx, "SELECT (data->>'original')::bool FROM events WHERE id = $1", id).Scan(&original))
				assert.True(t, original, "event payload must be immutable")
			},
		},
		{
			name: "move stream_id",
			sql:  "UPDATE events SET stream_id = 'other' WHERE id = $1",
			verify: func(t *testing.T) {
				var got string
				require.NoError(t, pool.QueryRow(ctx, "SELECT stream_id FROM events WHERE id = $1", id).Scan(&got))
				assert.Equal(t, streamID, got, "stream binding must be immutable")
			},
		},
		{
			name: "delete row",
			sql:  "DELETE FROM events WHERE id = $1",
			verify: func(t *testing.T) {
				var n int
				require.NoError(t, pool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE id = $1", id).Scan(&n))
				assert.Equal(t, 1, n, "a committed event must not be deletable")
			},
		},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, m.sql, id)
			require.Error(t, err, "the append-only trigger must reject this mutation")
			assert.Contains(t, strings.ToLower(err.Error()), "append-only",
				"the rejection must come from the append-only guard")
			m.verify(t)
		})
	}

	// Correct path: append still works (the guard blocks mutation, not append).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "test",
		StreamID:   streamID,
		EventType:  "WriteOnceProbe2",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "orig-actor",
	}), "append must still succeed — the guard blocks mutation, not INSERT")
}
