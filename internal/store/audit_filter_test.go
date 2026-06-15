package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestListAuditEvents_EventTypeFilterIsLiteralMatch pins WS14 #11: the audit
// event_type filter is a literal substring match — `%`/`_` typed in the filter
// value match those exact characters, not as SQL wildcards. The two seeded types
// differ only at the position a LIKE `_` would wildcard-match, so a raw-ILIKE
// filter ("User_Created") would wrongly return both; with the wildcard escaped,
// only the literal-underscore row matches.
func TestListAuditEvents_EventTypeFilterIsLiteralMatch(t *testing.T) {
	st := testutil.SetupPostgresWithoutProjectors(t)
	ctx := context.Background()

	for _, et := range []string{"User_Created", "UserXCreated"} {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "test", StreamID: testutil.NewID(), EventType: et,
			Data: map[string]any{}, ActorType: "system", ActorID: "a",
		}))
	}

	rows, err := st.Queries().ListAuditEvents(ctx, db.ListAuditEventsParams{
		Column3: "User_Created", Limit: 100, Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, rows, 1, "the '_' in the filter must match literally, not as a wildcard (raw ILIKE would also return UserXCreated)")
	assert.Equal(t, "User_Created", rows[0].EventType)

	// And a literal substring still matches (the outer %-wrap is intentional).
	rows, err = st.Queries().ListAuditEvents(ctx, db.ListAuditEventsParams{
		Column3: "Created", Limit: 100, Offset: 0,
	})
	require.NoError(t, err)
	assert.Len(t, rows, 2, "a normal substring filter still matches both Created events")
}
