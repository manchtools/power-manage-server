package api

// systemActionStore tests — closes the test acceptance bullet of
// manchtools/power-manage-server#154 ("event shapes are
// deterministic"). Each method emits one or two events with a
// fixed-shape payload; the test seeds + replays the event store
// and asserts the payload landed exactly as the manager expects.
//
// Lives in the api package (internal) to access the unexported
// systemActionStore type. Manager-level tests for #151 will live
// alongside this file in a follow-up.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// loadEvents pulls every event in a stream as raw db.Event records
// so tests can assert the typed payload shape.
func loadEvents(t *testing.T, st *store.Store, streamType, streamID string) []db.Event {
	t.Helper()
	events, err := st.Queries().LoadStream(context.Background(), db.LoadStreamParams{
		StreamType: streamType,
		StreamID:   streamID,
	})
	require.NoError(t, err)
	return events
}

// =============================================================================
// CreateAction
// =============================================================================

func TestSystemActionStore_CreateAction_EmitsActionCreatedWithIsSystem(t *testing.T) {
	st := testutil.SetupPostgres(t)
	s := newSystemActionStore(st, NoOpSigner{})

	id, err := s.CreateAction(context.Background(),
		"system-user-alice",
		600, // ACTION_TYPE_USER
		1,   // DESIRED_STATE_PRESENT
		[]byte(`{"username":"alice","action":"create_or_update"}`))
	require.NoError(t, err)
	require.NotEmpty(t, id)

	events := loadEvents(t, st, "action", id)
	require.Len(t, events, 1, "CreateAction emits exactly one event")
	assert.Equal(t, string(eventtypes.ActionCreated), events[0].EventType)

	var data map[string]any
	require.NoError(t, json.Unmarshal(events[0].Data, &data))
	assert.Equal(t, "system-user-alice", data["name"])
	assert.Equal(t, true, data["is_system"], "is_system MUST be true so the projector flags the row as system-managed")
	assert.Equal(t, float64(600), data["action_type"]) // JSON numbers decode as float64
	assert.Equal(t, "system", events[0].ActorType)
	assert.Equal(t, "system", events[0].ActorID)
}

func TestSystemActionStore_CreateAction_RejectsInvalidJSON(t *testing.T) {
	st := testutil.SetupPostgres(t)
	s := newSystemActionStore(st, NoOpSigner{})

	_, err := s.CreateAction(context.Background(), "bad", 600, 1, []byte(`{not json`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid JSON",
		"malformed JSON must fail-closed — silently storing it would only surface at projector time")
}

// =============================================================================
// AssignActionToUser
// =============================================================================

func TestSystemActionStore_AssignActionToUser_EmitsAssignmentCreated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	s := newSystemActionStore(st, NoOpSigner{})

	require.NoError(t, s.AssignActionToUser(context.Background(), "act-1", "user-1"))

	// The assignment stream id is generated; we have to find it via
	// the projection rather than by stream lookup. Use the assignments
	// projection: source_id = act-1, target_id = user-1.
	rows, err := st.Pool().Query(context.Background(),
		`SELECT source_type, target_type, mode FROM assignments_projection
		 WHERE source_id = $1 AND target_id = $2`, "act-1", "user-1")
	require.NoError(t, err)
	defer rows.Close()
	var sourceType, targetType string
	var mode int32
	require.True(t, rows.Next())
	require.NoError(t, rows.Scan(&sourceType, &targetType, &mode))
	assert.Equal(t, "action", sourceType)
	assert.Equal(t, "user", targetType)
	assert.Equal(t, int32(0), mode, "system actions are REQUIRED (mode=0)")
}

// =============================================================================
// UpdateAction
// =============================================================================

func TestSystemActionStore_UpdateAction_EmitsActionParamsUpdated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	s := newSystemActionStore(st, NoOpSigner{})

	id, err := s.CreateAction(context.Background(), "act", 600, 1, []byte(`{"v":1}`))
	require.NoError(t, err)

	require.NoError(t, s.UpdateAction(context.Background(), id, 1, []byte(`{"v":2}`)))

	events := loadEvents(t, st, "action", id)
	require.Len(t, events, 2)
	assert.Equal(t, string(eventtypes.ActionParamsUpdated), events[1].EventType)
}

func TestSystemActionStore_UpdateAction_RejectsInvalidJSON(t *testing.T) {
	st := testutil.SetupPostgres(t)
	s := newSystemActionStore(st, NoOpSigner{})

	err := s.UpdateAction(context.Background(), "act-1", 1, []byte(`{not json`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid JSON")
}

// =============================================================================
// DeleteAction
// =============================================================================

func TestSystemActionStore_DeleteAction_EmitsActionDeleted(t *testing.T) {
	st := testutil.SetupPostgres(t)
	s := newSystemActionStore(st, NoOpSigner{})

	id, err := s.CreateAction(context.Background(), "act", 600, 1, []byte(`{}`))
	require.NoError(t, err)

	require.NoError(t, s.DeleteAction(context.Background(), id))

	events := loadEvents(t, st, "action", id)
	require.Len(t, events, 2)
	assert.Equal(t, string(eventtypes.ActionDeleted), events[1].EventType)
}

// =============================================================================
// LinkAction
// =============================================================================

func TestSystemActionStore_LinkAction_EmitsUserSystemActionLinked(t *testing.T) {
	st := testutil.SetupPostgres(t)
	s := newSystemActionStore(st, NoOpSigner{})

	require.NoError(t, s.LinkAction(context.Background(), "user-1", "system_user_action_id", "act-1"))

	events := loadEvents(t, st, "user", "user-1")
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	assert.Equal(t, string(eventtypes.UserSystemActionLinked), last.EventType)

	var data map[string]any
	require.NoError(t, json.Unmarshal(last.Data, &data))
	assert.Equal(t, "system_user_action_id", data["field"])
	assert.Equal(t, "act-1", data["action_id"])
}

// =============================================================================
// SignActionByID — fail-closed on nil signer
// =============================================================================

func TestSystemActionStore_SignActionByID_NilSignerHardFails(t *testing.T) {
	// nil signer is a wiring bug; the store must reject the call
	// rather than silently land an unsigned action that the agent
	// would drop on dispatch (audit F033's #137 reference).
	st := testutil.SetupPostgres(t)
	s := newSystemActionStore(st, nil)

	err := s.SignActionByID(context.Background(), "nonexistent-action")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signer not configured")
}

func TestSystemActionStore_SignActionByID_HappyPath(t *testing.T) {
	st := testutil.SetupPostgres(t)
	s := newSystemActionStore(st, NoOpSigner{})

	id, err := s.CreateAction(context.Background(), "to-sign", 600, 1, []byte(`{"x":1}`))
	require.NoError(t, err)

	require.NoError(t, s.SignActionByID(context.Background(), id))

	// Projection must now have a non-empty signature column.
	row, err := st.Queries().GetActionByID(context.Background(), id)
	require.NoError(t, err)
	assert.NotEmpty(t, row.Signature, "SignActionByID must persist the signature on the action row")
	assert.NotEmpty(t, row.ParamsCanonical, "ParamsCanonical must be set so the agent can verify")
}
