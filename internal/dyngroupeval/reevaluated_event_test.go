package dyngroupeval_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/dyngroupeval"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// #7 spec 14: dynamic membership is event-driven. The evaluator emits a
// DeviceGroupMembersReevaluated event carrying the delta; the projector applies
// it (proven by the membership-correctness tests). This test pins the OTHER half:
// the event is in the log (auditability) with the correct delta, so the audit
// trail can never drift from membership.
func TestEvaluateDeviceGroup_EmitsReevaluatedEventWithDelta(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	dMatch := testutil.CreateTestDevice(t, st, "prod-host")
	dStale := testutil.CreateTestDevice(t, st, "dev-host")
	execSQL(t, st, `INSERT INTO device_labels (device_id, key, value) VALUES ($1, 'env', 'prod')`, dMatch)

	groupID := testutil.NewID()
	execSQL(t, st, `INSERT INTO device_groups_projection (id, name, is_dynamic, dynamic_query) VALUES ($1, 'dyn', TRUE, $2)`,
		groupID, `labels.env equals "prod"`)
	execSQL(t, st, `INSERT INTO device_group_members_projection (group_id, device_id) VALUES ($1, $2)`, groupID, dStale)
	enqueueDeviceGroup(t, st, groupID)

	require.NoError(t, dyngroupeval.New(st, slog.Default()).EvaluateDeviceGroup(ctx, groupID))

	// Membership applied via the projector (the event is the source of truth).
	assert.Equal(t, []string{dMatch}, deviceMembers(t, st, groupID))

	// AND the delta is recorded as an event for the audit trail.
	p := findReevaluatedDelta(t, st, "device_group", groupID, string(eventtypes.DeviceGroupMembersReevaluated))
	assert.Equal(t, []string{dMatch}, p.AddedDeviceIDs, "added device recorded in the event")
	assert.Equal(t, []string{dStale}, p.RemovedDeviceIDs, "removed device recorded in the event")
}

// No membership change → no event (don't pollute the log / trigger empty reindexes).
func TestEvaluateDeviceGroup_NoDeltaEmitsNoEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	groupID := testutil.NewID()
	execSQL(t, st, `INSERT INTO device_groups_projection (id, name, is_dynamic, dynamic_query) VALUES ($1, 'dyn', TRUE, $2)`,
		groupID, `labels.env equals "prod"`) // matches nothing; no current members
	enqueueDeviceGroup(t, st, groupID)

	require.NoError(t, dyngroupeval.New(st, slog.Default()).EvaluateDeviceGroup(ctx, groupID))

	assert.Equal(t, 0, countReevaluatedEvents(t, st, "device_group", groupID, string(eventtypes.DeviceGroupMembersReevaluated)),
		"an evaluation that changes nothing must not emit a reevaluated event")
}

func findReevaluatedDelta(t *testing.T, st *store.Store, streamType, groupID, eventType string) payloads.DeviceGroupMembersReevaluated {
	t.Helper()
	events, err := st.Queries().LoadEventsByStreamType(context.Background(), db.LoadEventsByStreamTypeParams{
		StreamType: streamType, Limit: 1000, Offset: 0,
	})
	require.NoError(t, err)
	for _, e := range events {
		if e.EventType == eventType && e.StreamID == groupID {
			var p payloads.DeviceGroupMembersReevaluated
			require.NoError(t, json.Unmarshal(e.Data, &p))
			return p
		}
	}
	t.Fatalf("no %s event found for group %s", eventType, groupID)
	return payloads.DeviceGroupMembersReevaluated{}
}

func countReevaluatedEvents(t *testing.T, st *store.Store, streamType, groupID, eventType string) int {
	t.Helper()
	events, err := st.Queries().LoadEventsByStreamType(context.Background(), db.LoadEventsByStreamTypeParams{
		StreamType: streamType, Limit: 1000, Offset: 0,
	})
	require.NoError(t, err)
	n := 0
	for _, e := range events {
		if e.EventType == eventType && e.StreamID == groupID {
			n++
		}
	}
	return n
}
