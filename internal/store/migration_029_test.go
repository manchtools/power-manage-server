package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	// End-to-end behavioural assertion historically forced a PL/pgSQL
	// projector to raise (duplicate users_projection PK on a second
	// UserCreated event) so the row landed in plpgsql_projection_errors
	// and we could verify project_event()'s EXCEPTION handler wrote to
	// the renamed table.
	//
	// Removed in #136 along with the user projector port: every
	// domain projector now lives in Go, every project_<X>_event()
	// PL/pgSQL function is a no-op stub, so there is no remaining
	// reproducer that lands in plpgsql_projection_errors via the
	// dispatcher. Go-listener errors go through slog.Warn, not the
	// renamed table. The schema-level rename + COMMENT checks above
	// still pin the operator-trap fix from migration 029; the
	// follow-up Phase 2 cleanup drops project_event() and this
	// table-rename concern entirely.
}
