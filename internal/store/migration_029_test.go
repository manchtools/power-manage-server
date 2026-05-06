package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestMigration029_TableRenamedAndCommented — migration 029 renames
// the projection_errors table to plpgsql_projection_errors so its
// scope (PL/pgSQL projectors only — Go listeners use slog.Warn) is
// visible at every observation point. Asserts the rename happened,
// the old name is gone, and the COMMENT is in place so `\d+` and
// audit dashboards surface the scope warning.
func TestMigration029_TableRenamedAndCommented(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	var newExists bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'plpgsql_projection_errors')`,
	).Scan(&newExists))
	assert.True(t, newExists, "plpgsql_projection_errors must exist after migration 029")

	var oldExists bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'projection_errors')`,
	).Scan(&oldExists))
	assert.False(t, oldExists, "projection_errors must be gone after rename — readers of the old name need to be updated")

	var comment *string
	require.NoError(t, st.Pool().QueryRow(ctx,
		`SELECT obj_description('plpgsql_projection_errors'::regclass, 'pg_class')`,
	).Scan(&comment))
	require.NotNil(t, comment, "plpgsql_projection_errors must carry a COMMENT explaining its narrowed scope")
	assert.Contains(t, *comment, "Go projectors",
		"COMMENT must call out that Go projectors do NOT write here, so an empty table is not 'no projector errors'")

	// End-to-end behavioural assertion. Pinning the rename + COMMENT
	// catches schema drift but a future edit could still drop a CASE
	// arm or leave a stale `INSERT INTO projection_errors` somewhere
	// in project_event() and these checks would pass while the
	// operator trap silently regressed. Force a PL/pgSQL projector
	// to raise (duplicate users_projection PK on a second
	// UserCreated event for the same stream_id) and verify the row
	// lands in the renamed table — proves the trigger body was
	// actually rewritten.
	t.Run("trigger writes failures to the renamed table", func(t *testing.T) {
		userID := testutil.NewID()
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  "UserCreated",
			Data: map[string]any{
				"email":         testutil.NewID() + "@test.example",
				"password_hash": "h",
				"role":          "admin",
			},
			ActorType: "system",
			ActorID:   "test",
		}))

		// Second UserCreated for the same stream_id: the PL/pgSQL
		// projector tries an INSERT into users_projection and the
		// PRIMARY KEY violation propagates to project_event()'s
		// EXCEPTION handler, which writes a row to the renamed
		// table.
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  "UserCreated",
			Data: map[string]any{
				"email":         testutil.NewID() + "@test.example",
				"password_hash": "h",
				"role":          "admin",
			},
			ActorType: "system",
			ActorID:   "test",
		}))

		var n int
		require.NoError(t, st.Pool().QueryRow(ctx,
			`SELECT COUNT(*) FROM plpgsql_projection_errors
			  WHERE stream_type = 'user' AND event_type = 'UserCreated'`,
		).Scan(&n))
		assert.GreaterOrEqual(t, n, 1,
			"project_event() must route PL/pgSQL projector failures to plpgsql_projection_errors after migration 029 — finding zero means a stale INSERT INTO projection_errors slipped past the rewrite")
	})
}
