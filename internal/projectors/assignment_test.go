package projectors_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestAssignmentCreatedFromEvent_Pure pins the decoder defaults that
// match the deleted PL/pgSQL projector: source_type/id +
// target_type/id are required (NOT NULL columns), missing sort_order /
// mode default to 0 (matches the PL/pgSQL COALESCE-to-zero).
func TestAssignmentCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.AssignmentCreatedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-1", EventType: "AssignmentCreated", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"source_type": "action",
				"source_id":   "act-1",
				"target_type": "device",
				"target_id":   "dev-1",
				"sort_order":  5,
				"mode":        1,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "asn-1", got.ID)
		assert.Equal(t, "action", got.SourceType)
		assert.Equal(t, "act-1", got.SourceID)
		assert.Equal(t, "device", got.TargetType)
		assert.Equal(t, "dev-1", got.TargetID)
		assert.Equal(t, int32(5), got.SortOrder)
		assert.Equal(t, int32(1), got.Mode)
		assert.Equal(t, "u-1", got.CreatedBy)
	})

	t.Run("defaults: sort_order=0, mode=0", func(t *testing.T) {
		got, err := projectors.AssignmentCreatedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-2", EventType: "AssignmentCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"source_type": "action",
				"source_id":   "act-1",
				"target_type": "device",
				"target_id":   "dev-1",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.SortOrder, "missing sort_order defaults to 0 (matches PL/pgSQL COALESCE)")
		assert.Equal(t, int32(0), got.Mode, "missing mode defaults to 0 (REQUIRED)")
	})

	t.Run("source_type is required", func(t *testing.T) {
		_, err := projectors.AssignmentCreatedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-3", EventType: "AssignmentCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"source_id":   "act-1",
				"target_type": "device",
				"target_id":   "dev-1",
			}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "source_type")
	})

	t.Run("source_id is required", func(t *testing.T) {
		_, err := projectors.AssignmentCreatedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-3", EventType: "AssignmentCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"source_type": "action",
				"target_type": "device",
				"target_id":   "dev-1",
			}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "source_id")
	})

	t.Run("target_type is required", func(t *testing.T) {
		_, err := projectors.AssignmentCreatedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-3", EventType: "AssignmentCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"source_type": "action",
				"source_id":   "act-1",
				"target_id":   "dev-1",
			}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "target_type")
	})

	t.Run("target_id is required", func(t *testing.T) {
		_, err := projectors.AssignmentCreatedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-3", EventType: "AssignmentCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"source_type": "action",
				"source_id":   "act-1",
				"target_type": "device",
			}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "target_id")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.AssignmentCreatedFromEvent(store.PersistedEvent{
			StreamType: "action", EventType: "AssignmentCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.AssignmentCreatedFromEvent(store.PersistedEvent{
			StreamType: "assignment", EventType: "AssignmentDeleted",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.AssignmentCreatedFromEvent(store.PersistedEvent{
			StreamType: "assignment", EventType: "AssignmentCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestAssignmentModeChangedFromEvent_Pure covers the partial-update
// decoder for the (currently un-emitted) AssignmentModeChanged event.
// Missing mode key collapses to 0, matching the PL/pgSQL COALESCE-to-
// zero. The projector keeps parity for replay safety even though the
// handler layer doesn't emit this event today.
func TestAssignmentModeChangedFromEvent_Pure(t *testing.T) {
	t.Run("explicit mode set", func(t *testing.T) {
		got, err := projectors.AssignmentModeChangedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-1", EventType: "AssignmentModeChanged",
			Data: jsonOrFail(t, map[string]any{"mode": 2}),
		})
		require.NoError(t, err)
		assert.Equal(t, "asn-1", got.ID)
		assert.Equal(t, int32(2), got.Mode)
	})

	t.Run("missing mode key → 0", func(t *testing.T) {
		got, err := projectors.AssignmentModeChangedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-1", EventType: "AssignmentModeChanged",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.Mode, "missing mode collapses to 0 per PL/pgSQL COALESCE")
	})

	t.Run("empty payload bytes → 0", func(t *testing.T) {
		got, err := projectors.AssignmentModeChangedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-1", EventType: "AssignmentModeChanged",
			Data: nil,
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.Mode)
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.AssignmentModeChangedFromEvent(store.PersistedEvent{
			StreamType: "assignment", EventType: "AssignmentCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestAssignmentSortOrderChangedFromEvent_Pure — same shape as
// ModeChanged: missing sort_order defaults to 0.
func TestAssignmentSortOrderChangedFromEvent_Pure(t *testing.T) {
	t.Run("explicit sort_order set", func(t *testing.T) {
		got, err := projectors.AssignmentSortOrderChangedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-1", EventType: "AssignmentSortOrderChanged",
			Data: jsonOrFail(t, map[string]any{"sort_order": 7}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(7), got.SortOrder)
	})

	t.Run("missing sort_order key → 0", func(t *testing.T) {
		got, err := projectors.AssignmentSortOrderChangedFromEvent(store.PersistedEvent{
			StreamType: "assignment", StreamID: "asn-1", EventType: "AssignmentSortOrderChanged",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.SortOrder)
	})

	t.Run("wrong stream type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.AssignmentSortOrderChangedFromEvent(store.PersistedEvent{
			StreamType: "action", EventType: "AssignmentSortOrderChanged",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestAssignmentListener_CreateLifecycle drives Create end-to-end and
// asserts the projection ends in the right state.
func TestAssignmentListener_CreateLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	asnID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentCreated",
		Data: map[string]any{
			"source_type": "action",
			"source_id":   "act-1",
			"target_type": "device",
			"target_id":   "dev-1",
			"sort_order":  3,
			"mode":        1,
		},
		ActorType: "user", ActorID: "u-1",
	}))

	got, err := st.Queries().GetAssignmentByID(ctx, asnID)
	require.NoError(t, err)
	assert.Equal(t, "action", got.SourceType)
	assert.Equal(t, "act-1", got.SourceID)
	assert.Equal(t, "device", got.TargetType)
	assert.Equal(t, "dev-1", got.TargetID)
	assert.Equal(t, int32(3), got.SortOrder)
	assert.Equal(t, int32(1), got.Mode)
	assert.False(t, got.IsDeleted)
	assert.Greater(t, got.ProjectionVersion, int64(0))
}

// TestAssignmentListener_CreateRevivesSoftDeletedRow exercises the
// ON CONFLICT DO UPDATE branch: re-creating a previously-deleted
// (source, target) tuple revives the row in place rather than failing
// the unique-tuple constraint. Mirrors the PL/pgSQL projector's
// "DO UPDATE SET is_deleted = FALSE" behaviour.
func TestAssignmentListener_CreateRevivesSoftDeletedRow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	asn1 := testutil.NewID()
	asn2 := testutil.NewID()

	create := func(streamID string, mode int32) {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "assignment", StreamID: streamID, EventType: "AssignmentCreated",
			Data: map[string]any{
				"source_type": "action",
				"source_id":   "act-1",
				"target_type": "device",
				"target_id":   "dev-1",
				"mode":        mode,
			},
			ActorType: "user", ActorID: "u",
		}))
	}

	create(asn1, 0)
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asn1, EventType: "AssignmentDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	// Re-create with a new stream ID + a different mode. The ON
	// CONFLICT branch must revive the original row, flip is_deleted
	// back to false, and update mode to the new value.
	create(asn2, 2)

	row, err := st.Queries().GetAssignment(ctx, db.GetAssignmentParams{
		SourceType: "action",
		SourceID:   "act-1",
		TargetType: "device",
		TargetID:   "dev-1",
	})
	require.NoError(t, err)
	assert.False(t, row.IsDeleted, "revived assignment must have is_deleted=FALSE")
	assert.Equal(t, int32(2), row.Mode, "revived assignment must reflect the new mode")
}

// TestAssignmentListener_DeleteSoftDeletes covers AssignmentDeleted:
// the row is marked is_deleted=TRUE and queries that filter for live
// rows no longer return it.
func TestAssignmentListener_DeleteSoftDeletes(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	asnID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentCreated",
		Data: map[string]any{
			"source_type": "action",
			"source_id":   "act-1",
			"target_type": "device",
			"target_id":   "dev-1",
		},
		ActorType: "user", ActorID: "u",
	}))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	// GetAssignmentByID filters is_deleted=FALSE — the row is gone
	// from this query's view.
	_, err := st.Queries().GetAssignmentByID(ctx, asnID)
	require.Error(t, err)

	// But the row is still there with is_deleted=TRUE.
	var isDeleted bool
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT is_deleted FROM assignments_projection WHERE id = $1", asnID,
	).Scan(&isDeleted))
	assert.True(t, isDeleted)
}

// TestAssignmentListener_ModeChangedUpdatesRow covers the
// (currently un-emitted) AssignmentModeChanged event end-to-end. The
// projector keeps parity with the PL/pgSQL version for replay safety.
func TestAssignmentListener_ModeChangedUpdatesRow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	asnID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentCreated",
		Data: map[string]any{
			"source_type": "action",
			"source_id":   "act-1",
			"target_type": "device",
			"target_id":   "dev-1",
			"mode":        0,
		},
		ActorType: "user", ActorID: "u",
	}))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentModeChanged",
		Data:      map[string]any{"mode": 2},
		ActorType: "user", ActorID: "u",
	}))

	got, err := st.Queries().GetAssignmentByID(ctx, asnID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.Mode)
}

// TestAssignmentListener_SortOrderChangedUpdatesRow — same parity-
// preservation rationale as the ModeChanged test.
func TestAssignmentListener_SortOrderChangedUpdatesRow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	asnID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentCreated",
		Data: map[string]any{
			"source_type": "action",
			"source_id":   "act-1",
			"target_type": "device",
			"target_id":   "dev-1",
			"sort_order":  0,
		},
		ActorType: "user", ActorID: "u",
	}))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentSortOrderChanged",
		Data:      map[string]any{"sort_order": 42},
		ActorType: "user", ActorID: "u",
	}))

	got, err := st.Queries().GetAssignmentByID(ctx, asnID)
	require.NoError(t, err)
	assert.Equal(t, int32(42), got.SortOrder)
}

// TestAssignmentListener_StaleModeReplayRejected confirms the
// projection_version guard on AssignmentModeChanged rejects an UPDATE
// whose projection_version is older than the row's current value.
func TestAssignmentListener_StaleModeReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	asnID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentCreated",
		Data: map[string]any{
			"source_type": "action",
			"source_id":   "act-1",
			"target_type": "device",
			"target_id":   "dev-1",
			"mode":        0,
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentModeChanged",
		Data:      map[string]any{"mode": 2},
		ActorType: "user", ActorID: "u",
	}))
	current, err := st.Queries().GetAssignmentByID(ctx, asnID)
	require.NoError(t, err)
	currentVersion := current.ProjectionVersion

	older := currentVersion - 5
	n, err := st.Queries().UpdateAssignmentModeProjection(ctx, db.UpdateAssignmentModeProjectionParams{
		ID:                asnID,
		Mode:              99,
		ProjectionVersion: older,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "stale projection_version UPDATE must affect zero rows")

	after, err := st.Queries().GetAssignmentByID(ctx, asnID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), after.Mode, "stale projection_version must NOT clobber fresher mode")
	assert.Equal(t, currentVersion, after.ProjectionVersion)
}

// TestAssignmentListener_StaleDeleteReplayDoesNotCascade is a
// regression lock for the asymmetric-guard discipline on
// AssignmentDeleted: when the version-guarded SoftDelete affects zero
// rows (RETURNING produces no rows → store.IsNotFound), the compliance
// cascade MUST be skipped. Otherwise an old AssignmentDeleted
// re-applied later by the reconciler against a freshly-restored
// assignment would silently drop compliance evaluations and
// re-evaluate against a row this listener wasn't allowed to write.
func TestAssignmentListener_StaleDeleteReplayDoesNotCascade(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	asnID := testutil.NewID()
	deviceID := testutil.NewID()
	policyID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "assignment", StreamID: asnID, EventType: "AssignmentCreated",
		Data: map[string]any{
			"source_type": "compliance_policy",
			"source_id":   policyID,
			"target_type": "device",
			"target_id":   deviceID,
		},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetAssignmentByID(ctx, asnID)
	require.NoError(t, err)

	// Plant a compliance evaluation row directly so we can prove the
	// cascade DELETE is skipped on a stale replay. action_id is part
	// of the composite PK; any value will do — the cascade DELETE
	// scopes on (device_id, policy_id) only.
	_, err = st.TestingPool().Exec(ctx,
		`INSERT INTO compliance_policy_evaluation_projection
		   (device_id, policy_id, action_id, compliant, status)
		 VALUES ($1, $2, $3, TRUE, 1)`,
		deviceID, policyID, "act-cascade-canary",
	)
	require.NoError(t, err)

	// Drive the REAL listener with a synthetic PersistedEvent whose
	// SequenceNum is older than the row's current projection_version.
	older := live.ProjectionVersion - 5
	staleAt := *live.CreatedAt
	listener := projectors.AssignmentListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          ulid.Make().String(),
		SequenceNum: older,
		StreamType:  "assignment",
		StreamID:    asnID,
		EventType:   "AssignmentDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	// Assignment row is still alive.
	stillAlive, err := st.Queries().GetAssignmentByID(ctx, asnID)
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted, "stale AssignmentDeleted must NOT flip is_deleted")

	// Compliance evaluation row is still there — the cascade was
	// skipped because the guarded SoftDelete returned ErrNoRows.
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM compliance_policy_evaluation_projection WHERE device_id = $1 AND policy_id = $2",
		deviceID, policyID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale AssignmentDeleted must NOT cascade-delete compliance evaluations")
}

// TestAssignmentListener_IgnoresWrongStreamType — defensive.
func TestAssignmentListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	asnID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", // wrong stream
		StreamID:   asnID,
		EventType:  "AssignmentCreated",
		Data: map[string]any{
			"source_type": "action",
			"source_id":   "act-1",
			"target_type": "device",
			"target_id":   "dev-1",
		},
		ActorType: "user", ActorID: "u",
	}))

	_, err := st.Queries().GetAssignmentByID(ctx, asnID)
	require.Error(t, err, "wrong-stream-type AssignmentCreated must NOT create an assignments_projection row")
}
