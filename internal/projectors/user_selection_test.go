package projectors_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestUserSelectionChangedFromEvent_Pure exercises the decoder.
// PL/pgSQL projector required device_id/source_type/source_id and
// defaulted selected to FALSE on missing/non-bool.
func TestUserSelectionChangedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with selected=true", func(t *testing.T) {
		got, err := projectors.UserSelectionChangedFromEvent(store.PersistedEvent{
			StreamType: "user_selection", StreamID: "sel-1",
			EventType: "UserSelectionChanged", ActorID: "actor-1",
			Data: jsonOrFail(t, map[string]any{
				"device_id":   "dev-1",
				"source_type": "user",
				"source_id":   "user-1",
				"selected":    true,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "sel-1", got.ID)
		assert.Equal(t, "dev-1", got.DeviceID)
		assert.Equal(t, "user", got.SourceType)
		assert.Equal(t, "user-1", got.SourceID)
		assert.True(t, got.Selected)
		assert.Equal(t, "actor-1", got.CreatedBy)
	})

	t.Run("missing selected defaults to false", func(t *testing.T) {
		got, err := projectors.UserSelectionChangedFromEvent(store.PersistedEvent{
			StreamType: "user_selection", StreamID: "sel-2",
			EventType: "UserSelectionChanged", ActorID: "actor-1",
			Data: jsonOrFail(t, map[string]any{
				"device_id":   "dev-2",
				"source_type": "user_group",
				"source_id":   "ug-1",
			}),
		})
		require.NoError(t, err)
		assert.False(t, got.Selected, "missing selected → false (matches PL/pgSQL COALESCE default)")
	})

	t.Run("required fields validated", func(t *testing.T) {
		base := map[string]any{
			"device_id":   "d",
			"source_type": "user",
			"source_id":   "s",
		}
		for _, drop := range []string{"device_id", "source_type", "source_id"} {
			t.Run("missing "+drop, func(t *testing.T) {
				payload := map[string]any{}
				for k, v := range base {
					if k == drop {
						continue
					}
					payload[k] = v
				}
				_, err := projectors.UserSelectionChangedFromEvent(store.PersistedEvent{
					StreamType: "user_selection", StreamID: "s", EventType: "UserSelectionChanged", ActorID: "a",
					Data: jsonOrFail(t, payload),
				})
				require.Error(t, err)
				assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
				assert.Contains(t, err.Error(), drop)
			})
		}
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.UserSelectionChangedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "UserSelectionChanged",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.UserSelectionChangedFromEvent(store.PersistedEvent{
			StreamType: "user_selection", EventType: "Whatever",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.UserSelectionChangedFromEvent(store.PersistedEvent{
			StreamType: "user_selection", EventType: "UserSelectionChanged",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("non-boolean selected is a validation error", func(t *testing.T) {
		// Pins the contract documented on UserSelectionChangedPayload:
		// the deleted PL/pgSQL projector silently coerced non-bool
		// values via `::BOOLEAN` → NULL → COALESCE → FALSE. The Go
		// decoder deliberately rejects them at json.Unmarshal time
		// so malformed payloads fail loudly instead of producing
		// silently-defaulted projection rows.
		for _, badSelected := range []any{"true", "false", 1, 0, []any{}, map[string]any{}} {
			_, err := projectors.UserSelectionChangedFromEvent(store.PersistedEvent{
				StreamType: "user_selection", EventType: "UserSelectionChanged",
				Data: jsonOrFail(t, map[string]any{
					"device_id": "d", "source_type": "user", "source_id": "s",
					"selected": badSelected,
				}),
			})
			require.Errorf(t, err, "non-bool selected=%v should be rejected", badSelected)
			assert.Falsef(t, errors.Is(err, projectors.ErrIgnoredEvent),
				"non-bool selected=%v must NOT be silently swallowed as ErrIgnoredEvent", badSelected)
		}
	})
}

// TestUserSelectionListener_UpsertSelectThenDeselect walks the
// flip-flop path. UPSERT semantics matter: the second event for the
// same (device, source_type, source_id) must update the existing row,
// not insert a duplicate.
func TestUserSelectionListener_UpsertSelectThenDeselect(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := "dev-" + testutil.NewID()
	sourceID := "user-" + testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_selection", StreamID: testutil.NewID(),
		EventType: "UserSelectionChanged",
		Data: map[string]any{
			"device_id": deviceID, "source_type": "user", "source_id": sourceID,
			"selected": true,
		},
		ActorType: "user", ActorID: "u",
	}))

	var selected bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT selected FROM user_selections_projection WHERE device_id=$1 AND source_type='user' AND source_id=$2",
		deviceID, sourceID,
	).Scan(&selected))
	assert.True(t, selected, "first UserSelectionChanged inserts with selected=true")

	// Flip to false (UPSERT path).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_selection", StreamID: testutil.NewID(),
		EventType: "UserSelectionChanged",
		Data: map[string]any{
			"device_id": deviceID, "source_type": "user", "source_id": sourceID,
			"selected": false,
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT selected FROM user_selections_projection WHERE device_id=$1 AND source_type='user' AND source_id=$2",
		deviceID, sourceID,
	).Scan(&selected))
	assert.False(t, selected, "second UserSelectionChanged with selected=false flips the existing row")

	// Confirm exactly one row (UPSERT, not duplicate insert).
	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM user_selections_projection WHERE device_id=$1 AND source_type='user' AND source_id=$2",
		deviceID, sourceID,
	).Scan(&count))
	assert.Equal(t, 1, count, "ON CONFLICT (device_id, source_type, source_id) keeps the row unique")
}

// TestUserSelectionListener_PerSourceTypeScope confirms (device, user)
// and (device, user_group) selections coexist independently. A
// regression that drops source_type from the UPSERT key would silently
// merge them.
func TestUserSelectionListener_PerSourceTypeScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := "dev-" + testutil.NewID()

	for _, st_ := range []string{"user", "user_group"} {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user_selection", StreamID: testutil.NewID(),
			EventType: "UserSelectionChanged",
			Data: map[string]any{
				"device_id": deviceID, "source_type": st_, "source_id": "src-" + st_,
				"selected": true,
			},
			ActorType: "user", ActorID: "u",
		}))
	}

	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM user_selections_projection WHERE device_id=$1", deviceID,
	).Scan(&count))
	assert.Equal(t, 2, count, "different source_types must NOT collapse into one row")
}

// TestUserSelectionListener_StaleReplayRejected confirms the
// projection_version guard on the UPSERT's update path. PR description
// flags this as the key tightening over the PL/pgSQL original (which
// had no guard).
func TestUserSelectionListener_StaleReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := "dev-" + testutil.NewID()
	sourceID := "user-" + testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_selection", StreamID: testutil.NewID(),
		EventType: "UserSelectionChanged",
		Data: map[string]any{
			"device_id": deviceID, "source_type": "user", "source_id": sourceID,
			"selected": true,
		},
		ActorType: "user", ActorID: "u",
	}))
	// Apply a "current" deselect (version advances).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_selection", StreamID: testutil.NewID(),
		EventType: "UserSelectionChanged",
		Data: map[string]any{
			"device_id": deviceID, "source_type": "user", "source_id": sourceID,
			"selected": false,
		},
		ActorType: "user", ActorID: "u",
	}))

	var currentVer int64
	var currentSelected bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT projection_version, selected FROM user_selections_projection WHERE device_id=$1 AND source_type='user' AND source_id=$2",
		deviceID, sourceID,
	).Scan(&currentVer, &currentSelected))
	require.False(t, currentSelected)

	// Stale replay would re-set selected=TRUE; the guard must reject.
	older := currentVer - 5
	staleID := testutil.NewID()
	require.NoError(t, st.Queries().UpsertUserSelectionProjection(ctx, db.UpsertUserSelectionProjectionParams{
		ID:                staleID,
		DeviceID:          deviceID,
		SourceType:        "user",
		SourceID:          sourceID,
		Selected:          true,
		UpdatedAt:         time.Now().UTC(),
		CreatedBy:         "stale",
		ProjectionVersion: older,
	}))

	var afterVer int64
	var afterSelected bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT projection_version, selected FROM user_selections_projection WHERE device_id=$1 AND source_type='user' AND source_id=$2",
		deviceID, sourceID,
	).Scan(&afterVer, &afterSelected))
	assert.False(t, afterSelected, "stale projection_version must NOT clobber fresher selected=false state")
	assert.Equal(t, currentVer, afterVer)
}

// TestUserSelectionListener_IgnoresWrongStreamType — defensive.
func TestUserSelectionListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := "dev-" + testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", // wrong
		StreamID:   testutil.NewID(),
		EventType:  "UserSelectionChanged",
		Data: map[string]any{
			"device_id": deviceID, "source_type": "user", "source_id": "x", "selected": true,
		},
		ActorType: "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM user_selections_projection WHERE device_id=$1", deviceID,
	).Scan(&count))
	assert.Equal(t, 0, count, "wrong-stream-type UserSelectionChanged must NOT create a row")
}
