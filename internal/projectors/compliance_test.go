package projectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// setupComplianceResultStore wraps testutil.SetupPostgres so the
// listener tests can grow extra fixture knobs (e.g. seeding a real
// devices_projection row) without touching every call site.
func setupComplianceResultStore(t *testing.T) *store.Store {
	t.Helper()
	return testutil.SetupPostgres(t)
}

// TestComplianceResultUpdatedFromEvent_Pure pins the decoder defaults
// against the deleted PL/pgSQL projector: device_id and action_id are
// required (the composite PK columns the UPSERT keys on); action_name
// defaults to "" (matches PL/pgSQL `COALESCE(payload, "")` for the
// NOT NULL column); compliant defaults to false (matches PL/pgSQL
// `COALESCE((payload)::boolean, false)`); detection_output is a raw
// JSONB sub-tree (PL/pgSQL stored `event.data->'detection_output'`
// verbatim, so a missing key collapses to NULL via json.RawMessage's
// nil zero value).
func TestComplianceResultUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.ComplianceResultUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance", StreamID: "dev-1_act-1", EventType: "ComplianceResultUpdated",
			Data: jsonOrFail(t, map[string]any{
				"device_id":        "dev-1",
				"action_id":        "act-1",
				"action_name":      "ssh-disabled",
				"compliant":        true,
				"detection_output": map[string]any{"stdout": "ok"},
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
		assert.Equal(t, "act-1", got.ActionID)
		assert.Equal(t, "ssh-disabled", got.ActionName)
		assert.True(t, got.Compliant)
		// detection_output round-trips as raw JSON bytes.
		var parsed map[string]any
		require.NoError(t, json.Unmarshal(got.DetectionOutput, &parsed))
		assert.Equal(t, "ok", parsed["stdout"])
	})

	t.Run("defaults: missing action_name → empty, missing compliant → false, missing detection_output → nil", func(t *testing.T) {
		got, err := projectors.ComplianceResultUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance", StreamID: "dev-2_act-2", EventType: "ComplianceResultUpdated",
			Data: jsonOrFail(t, map[string]any{
				"device_id": "dev-2",
				"action_id": "act-2",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.ActionName)
		assert.False(t, got.Compliant)
		assert.Nil(t, got.DetectionOutput)
	})

	t.Run("missing device_id fails", func(t *testing.T) {
		_, err := projectors.ComplianceResultUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance", StreamID: "x_y", EventType: "ComplianceResultUpdated",
			Data: jsonOrFail(t, map[string]any{"action_id": "act-1"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "device_id")
	})

	t.Run("missing action_id fails", func(t *testing.T) {
		_, err := projectors.ComplianceResultUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance", StreamID: "x_y", EventType: "ComplianceResultUpdated",
			Data: jsonOrFail(t, map[string]any{"device_id": "dev-1"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "action_id")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ComplianceResultUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "ComplianceResultUpdated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.ComplianceResultUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance", EventType: "ComplianceResultRemoved",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.ComplianceResultUpdatedFromEvent(store.PersistedEvent{
			StreamType: "compliance", EventType: "ComplianceResultUpdated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestComplianceResultRemovedFromEvent_Pure — only device_id and
// action_id are read; both are required because the DELETE filters on
// the composite PK.
func TestComplianceResultRemovedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.ComplianceResultRemovedFromEvent(store.PersistedEvent{
			StreamType: "compliance", StreamID: "dev-1_act-1", EventType: "ComplianceResultRemoved",
			Data: jsonOrFail(t, map[string]any{
				"device_id": "dev-1",
				"action_id": "act-1",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
		assert.Equal(t, "act-1", got.ActionID)
	})

	t.Run("missing device_id fails", func(t *testing.T) {
		_, err := projectors.ComplianceResultRemovedFromEvent(store.PersistedEvent{
			StreamType: "compliance", StreamID: "x_y", EventType: "ComplianceResultRemoved",
			Data: jsonOrFail(t, map[string]any{"action_id": "act-1"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "device_id")
	})

	t.Run("missing action_id fails", func(t *testing.T) {
		_, err := projectors.ComplianceResultRemovedFromEvent(store.PersistedEvent{
			StreamType: "compliance", StreamID: "x_y", EventType: "ComplianceResultRemoved",
			Data: jsonOrFail(t, map[string]any{"device_id": "dev-1"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "action_id")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ComplianceResultRemovedFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "ComplianceResultRemoved",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.ComplianceResultRemovedFromEvent(store.PersistedEvent{
			StreamType: "compliance", EventType: "ComplianceResultUpdated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// ---------------------------------------------------------------------------
// Integration tests (testcontainers-backed Postgres).
// ---------------------------------------------------------------------------

// appendComplianceResultUpdated emits one ComplianceResultUpdated
// event so each test can short-cut the boilerplate.
func appendComplianceResultUpdated(t *testing.T, st *store.Store, deviceID, actionID string, data map[string]any) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance",
		StreamID:   deviceID + "_" + actionID,
		EventType:  "ComplianceResultUpdated",
		Data:       data,
		ActorType:  "device",
		ActorID:    deviceID,
	}))
}

// TestComplianceListener_UpsertLifecycle covers the full
// insert → update cycle for a single (device, action) row. Confirms
// the row state advances and projection_version bumps monotonically.
func TestComplianceListener_UpsertLifecycle(t *testing.T) {
	st := setupComplianceResultStore(t)
	ctx := context.Background()
	deviceID := "dev-" + ulid.Make().String()
	actionID := "act-" + ulid.Make().String()

	appendComplianceResultUpdated(t, st, deviceID, actionID, map[string]any{
		"device_id":        deviceID,
		"action_id":        actionID,
		"action_name":      "first-name",
		"compliant":        false,
		"detection_output": map[string]any{"stdout": "fail"},
	})

	results, err := st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "first-name", results[0].ActionName)
	assert.False(t, results[0].Compliant)
	firstVersion := results[0].ProjectionVersion
	assert.Greater(t, firstVersion, int64(0))

	// Second event for the same (device, action) pair flips compliant
	// and the action_name. The UPSERT must overwrite, not duplicate.
	appendComplianceResultUpdated(t, st, deviceID, actionID, map[string]any{
		"device_id":        deviceID,
		"action_id":        actionID,
		"action_name":      "second-name",
		"compliant":        true,
		"detection_output": map[string]any{"stdout": "pass"},
	})

	results, err = st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, results, 1, "duplicate ComplianceResultUpdated must upsert, not insert")
	assert.Equal(t, "second-name", results[0].ActionName)
	assert.True(t, results[0].Compliant)
	assert.Greater(t, results[0].ProjectionVersion, firstVersion)
}

// TestComplianceListener_UpsertPreservesActionNameOnEmptyReplay locks
// the CR catch on PR #178: a duplicate ComplianceResultUpdated that
// omits action_name (decoder collapses missing → "") MUST NOT erase a
// previously-set action_name. The PL/pgSQL projector did
// `COALESCE(payload->>'action_name', existing.action_name)`; the Go
// port preserves that semantic via NULLIF + COALESCE in the UPSERT.
//
// compliant and detection_output are intentionally NOT preserved —
// they always overwrite, matching the PL/pgSQL projector's
// unconditional `compliant = COALESCE(..., false)` and
// `detection_output = event.data->'detection_output'` (which collapses
// a missing key to NULL).
func TestComplianceListener_UpsertPreservesActionNameOnEmptyReplay(t *testing.T) {
	st := setupComplianceResultStore(t)
	ctx := context.Background()
	deviceID := "dev-" + ulid.Make().String()
	actionID := "act-" + ulid.Make().String()

	appendComplianceResultUpdated(t, st, deviceID, actionID, map[string]any{
		"device_id":        deviceID,
		"action_id":        actionID,
		"action_name":      "named-result",
		"compliant":        true,
		"detection_output": map[string]any{"stdout": "ok"},
	})

	// Second event: action_name intentionally omitted. The COALESCE
	// + NULLIF in the UPSERT must keep the existing "named-result".
	appendComplianceResultUpdated(t, st, deviceID, actionID, map[string]any{
		"device_id": deviceID,
		"action_id": actionID,
		"compliant": false,
	})

	results, err := st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "named-result", results[0].ActionName,
		"duplicate ComplianceResultUpdated that omits action_name must preserve the existing name")
	assert.False(t, results[0].Compliant,
		"compliant always overwrites — the COALESCE is action_name-only")
}

// TestComplianceListener_DeleteLifecycle confirms
// ComplianceResultRemoved DELETEs the (device, action) row.
func TestComplianceListener_DeleteLifecycle(t *testing.T) {
	st := setupComplianceResultStore(t)
	ctx := context.Background()
	deviceID := "dev-" + ulid.Make().String()
	actionID := "act-" + ulid.Make().String()

	appendComplianceResultUpdated(t, st, deviceID, actionID, map[string]any{
		"device_id":   deviceID,
		"action_id":   actionID,
		"action_name": "to-remove",
		"compliant":   true,
	})
	results, err := st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, results, 1)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance",
		StreamID:   deviceID + "_" + actionID,
		EventType:  "ComplianceResultRemoved",
		Data: map[string]any{
			"device_id": deviceID,
			"action_id": actionID,
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))

	results, err = st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	assert.Len(t, results, 0, "ComplianceResultRemoved must DELETE the row")
}

// TestComplianceListener_StaleUpdateRejected — locks the asymmetric-
// guard discipline: a ComplianceResultUpdated re-applied with an
// older projection_version than the row currently has must NOT
// rewind the row. The UPSERT's UPDATE branch carries an explicit
// `WHERE projection_version < EXCLUDED.projection_version` predicate
// (mirrors the user_group / device_group / compliance_policy ports).
func TestComplianceListener_StaleUpdateRejected(t *testing.T) {
	st := setupComplianceResultStore(t)
	ctx := context.Background()
	deviceID := "dev-" + ulid.Make().String()
	actionID := "act-" + ulid.Make().String()

	appendComplianceResultUpdated(t, st, deviceID, actionID, map[string]any{
		"device_id":   deviceID,
		"action_id":   actionID,
		"action_name": "current",
		"compliant":   true,
	})
	results, err := st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, results, 1)
	currentVersion := results[0].ProjectionVersion

	// Drive the listener directly with a stale event (older
	// sequence_num) so the guard can be exercised without going
	// through AppendEvent (which would assign a fresh, monotonically
	// larger sequence_num).
	older := currentVersion - 5
	listener := projectors.ComplianceListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          ulid.Make().String(),
		SequenceNum: older,
		StreamType:  "compliance",
		StreamID:    deviceID + "_" + actionID,
		EventType:   "ComplianceResultUpdated",
		Data: jsonOrFail(t, map[string]any{
			"device_id":   deviceID,
			"action_id":   actionID,
			"action_name": "stale-would-set-this",
			"compliant":   false,
		}),
		ActorType:  "device",
		ActorID:    deviceID,
		OccurredAt: results[0].CheckedAt,
	})

	after, err := st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, after, 1)
	assert.Equal(t, "current", after[0].ActionName,
		"stale ComplianceResultUpdated must NOT clobber the existing action_name")
	assert.True(t, after[0].Compliant,
		"stale ComplianceResultUpdated must NOT flip compliant")
	assert.Equal(t, currentVersion, after[0].ProjectionVersion,
		"stale ComplianceResultUpdated must NOT advance projection_version")
}

// TestComplianceListener_StaleRemovedDoesNotWipeRevivedRow locks the
// CR catch on PR #179: a stale ComplianceResultRemoved replayed AFTER
// a newer ComplianceResultUpdated for the same (device, action) pair
// must NOT delete the live row. Without the projection_version guard
// on the DELETE, the older Removed would silently wipe the revived
// result and the follow-up reevaluate would compound the drift.
func TestComplianceListener_StaleRemovedDoesNotWipeRevivedRow(t *testing.T) {
	st := setupComplianceResultStore(t)
	ctx := context.Background()
	deviceID := "dev-" + ulid.Make().String()
	actionID := "act-" + ulid.Make().String()

	appendComplianceResultUpdated(t, st, deviceID, actionID, map[string]any{
		"device_id":   deviceID,
		"action_id":   actionID,
		"action_name": "v1",
		"compliant":   false,
	})
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "compliance",
		StreamID:   deviceID + "_" + actionID,
		EventType:  "ComplianceResultRemoved",
		Data:       map[string]any{"device_id": deviceID, "action_id": actionID},
		ActorType:  "device", ActorID: deviceID,
	}))
	// Capture this Removed's sequence so we can replay it later.
	var staleRemovedSeq int64
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		`SELECT sequence_num FROM events
		 WHERE stream_type = 'compliance' AND stream_id = $1
		   AND event_type = 'ComplianceResultRemoved'
		 ORDER BY sequence_num DESC LIMIT 1`,
		deviceID+"_"+actionID,
	).Scan(&staleRemovedSeq))

	// Newer Updated re-creates the row at a higher projection_version.
	appendComplianceResultUpdated(t, st, deviceID, actionID, map[string]any{
		"device_id":   deviceID,
		"action_id":   actionID,
		"action_name": "v2-revived",
		"compliant":   true,
	})
	revived, err := st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, revived, 1)
	revivedVersion := revived[0].ProjectionVersion

	// Drive the listener directly with the OLDER Removed sequence.
	listener := projectors.ComplianceListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          ulid.Make().String(),
		SequenceNum: staleRemovedSeq,
		StreamType:  "compliance",
		StreamID:    deviceID + "_" + actionID,
		EventType:   "ComplianceResultRemoved",
		Data:        jsonOrFail(t, map[string]any{"device_id": deviceID, "action_id": actionID}),
		ActorType:   "device",
		ActorID:     deviceID,
		OccurredAt:  revived[0].CheckedAt,
	})

	survivors, err := st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, survivors, 1, "stale ComplianceResultRemoved must NOT wipe the revived row")
	assert.Equal(t, "v2-revived", survivors[0].ActionName,
		"the revived row's action_name must survive the stale Removed replay")
	assert.Equal(t, revivedVersion, survivors[0].ProjectionVersion,
		"the revived row's projection_version must be unchanged")
}

// TestComplianceListener_IgnoresWrongStreamType — defensive: an event
// with the wrong stream_type must NOT touch the projection even when
// the event_type matches.
func TestComplianceListener_IgnoresWrongStreamType(t *testing.T) {
	st := setupComplianceResultStore(t)
	ctx := context.Background()
	deviceID := "dev-" + ulid.Make().String()
	actionID := "act-" + ulid.Make().String()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", // wrong stream
		StreamID:   deviceID + "_" + actionID,
		EventType:  "ComplianceResultUpdated",
		Data: map[string]any{
			"device_id":   deviceID,
			"action_id":   actionID,
			"action_name": "ghost",
			"compliant":   true,
		},
		ActorType: "device", ActorID: deviceID,
	}))

	results, err := st.Queries().GetDeviceComplianceResults(ctx, deviceID)
	require.NoError(t, err)
	assert.Len(t, results, 0, "wrong-stream-type event must NOT create a row")
}
