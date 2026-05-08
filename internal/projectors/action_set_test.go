package projectors_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestActionSetCreatedFromEvent_Pure pins the decoder defaults that
// match the deleted PL/pgSQL projector: missing description → ”;
// missing schedule → '{"interval_hours": 8}'.
func TestActionSetCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with explicit description and schedule", func(t *testing.T) {
		got, err := projectors.ActionSetCreatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetCreated", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"name":        "nightly",
				"description": "runs nightly",
				"schedule":    map[string]any{"interval_hours": 24},
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "as-1", got.ID)
		assert.Equal(t, "nightly", got.Name)
		assert.Equal(t, "runs nightly", got.Description)
		assert.JSONEq(t, `{"interval_hours":24}`, string(got.Schedule))
		assert.Equal(t, "u-1", got.CreatedBy)
	})

	t.Run("defaults: description empty, schedule = {interval_hours:8}", func(t *testing.T) {
		got, err := projectors.ActionSetCreatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-2", EventType: "ActionSetCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"name": "minimal"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
		assert.JSONEq(t, `{"interval_hours":8}`, string(got.Schedule),
			"missing schedule defaults to the column default '{\"interval_hours\": 8}'")
	})

	t.Run("name is required", func(t *testing.T) {
		_, err := projectors.ActionSetCreatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-3", EventType: "ActionSetCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"description": "no name"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ActionSetCreatedFromEvent(store.PersistedEvent{
			StreamType: "action", EventType: "ActionSetCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.ActionSetCreatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", EventType: "ActionSetRenamed",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.ActionSetCreatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", EventType: "ActionSetCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestActionSetRenamedFromEvent_Pure — name is required (the PL/pgSQL
// projector would have written NULL into the NOT NULL column,
// breaking the constraint; we surface this earlier as a decode
// validation error).
func TestActionSetRenamedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.ActionSetRenamedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetRenamed",
			Data: jsonOrFail(t, map[string]any{"name": "renamed"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "renamed", got.Name)
	})

	t.Run("missing name fails", func(t *testing.T) {
		_, err := projectors.ActionSetRenamedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetRenamed",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ActionSetRenamedFromEvent(store.PersistedEvent{
			StreamType: "action_set", EventType: "ActionSetCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestActionSetDescriptionUpdatedFromEvent_Pure — empty payload OR
// missing key BOTH map to Description == "" (matches the PL/pgSQL
// `COALESCE(payload, ”)` collapse). Empty-string payload also
// becomes "".
func TestActionSetDescriptionUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("explicit description set", func(t *testing.T) {
		got, err := projectors.ActionSetDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{"description": "new desc"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "new desc", got.Description)
	})

	t.Run("missing description key → empty string", func(t *testing.T) {
		got, err := projectors.ActionSetDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description, "missing key collapses to '' per PL/pgSQL COALESCE")
	})

	t.Run("empty payload bytes → empty string", func(t *testing.T) {
		got, err := projectors.ActionSetDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetDescriptionUpdated",
			Data: nil,
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
	})
}

// TestActionSetScheduleUpdatedFromEvent_Pure — missing schedule key
// falls back to the column default, matching the PL/pgSQL COALESCE
// against `'{"interval_hours": 8}'::JSONB`.
func TestActionSetScheduleUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("explicit schedule preserved verbatim", func(t *testing.T) {
		got, err := projectors.ActionSetScheduleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetScheduleUpdated",
			Data: jsonOrFail(t, map[string]any{"schedule": map[string]any{"cron": "0 4 * * *"}}),
		})
		require.NoError(t, err)
		assert.JSONEq(t, `{"cron":"0 4 * * *"}`, string(got.Schedule))
	})

	t.Run("missing schedule key → column-default fallback", func(t *testing.T) {
		got, err := projectors.ActionSetScheduleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetScheduleUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.JSONEq(t, `{"interval_hours":8}`, string(got.Schedule))
	})

	t.Run("empty payload bytes → column-default fallback", func(t *testing.T) {
		got, err := projectors.ActionSetScheduleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetScheduleUpdated",
			Data: nil,
		})
		require.NoError(t, err)
		assert.JSONEq(t, `{"interval_hours":8}`, string(got.Schedule))
	})
}

// TestActionSetMemberAddedFromEvent_Pure — sort_order defaults to 0
// when the key is missing (matches the PL/pgSQL COALESCE-to-zero).
func TestActionSetMemberAddedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with sort_order", func(t *testing.T) {
		got, err := projectors.ActionSetMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetMemberAdded",
			Data: jsonOrFail(t, map[string]any{"action_id": "act-1", "sort_order": 5}),
		})
		require.NoError(t, err)
		assert.Equal(t, "as-1", got.SetID)
		assert.Equal(t, "act-1", got.ActionID)
		assert.Equal(t, int32(5), got.SortOrder)
	})

	t.Run("missing sort_order defaults to 0", func(t *testing.T) {
		got, err := projectors.ActionSetMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetMemberAdded",
			Data: jsonOrFail(t, map[string]any{"action_id": "act-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.SortOrder)
	})

	t.Run("missing action_id is a validation error", func(t *testing.T) {
		_, err := projectors.ActionSetMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetMemberAdded",
			Data: jsonOrFail(t, map[string]any{"sort_order": 1}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestActionSetMemberRemovedFromEvent_Pure — only action_id matters.
func TestActionSetMemberRemovedFromEvent_Pure(t *testing.T) {
	got, err := projectors.ActionSetMemberRemovedFromEvent(store.PersistedEvent{
		StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetMemberRemoved",
		Data: jsonOrFail(t, map[string]any{"action_id": "act-9"}),
	})
	require.NoError(t, err)
	assert.Equal(t, "as-1", got.SetID)
	assert.Equal(t, "act-9", got.ActionID)

	_, err = projectors.ActionSetMemberRemovedFromEvent(store.PersistedEvent{
		StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetMemberRemoved",
		Data: jsonOrFail(t, map[string]any{}),
	})
	require.Error(t, err)
}

// TestActionSetMemberReorderedFromEvent_Pure — same payload shape as
// MemberAdded (action_id + sort_order, sort_order defaults to 0).
func TestActionSetMemberReorderedFromEvent_Pure(t *testing.T) {
	got, err := projectors.ActionSetMemberReorderedFromEvent(store.PersistedEvent{
		StreamType: "action_set", StreamID: "as-1", EventType: "ActionSetMemberReordered",
		Data: jsonOrFail(t, map[string]any{"action_id": "act-1", "sort_order": 3}),
	})
	require.NoError(t, err)
	assert.Equal(t, int32(3), got.SortOrder)

	_, err = projectors.ActionSetMemberReorderedFromEvent(store.PersistedEvent{
		StreamType: "action_set", EventType: "ActionSetMemberAdded",
	})
	assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
}

// TestActionSetListener_CreateRenameDescribeSchedule covers the four
// single-statement events end-to-end. Confirms the rename / desc /
// schedule UPDATEs all land on the row and the post-event row reads
// back the right state.
func TestActionSetListener_CreateRenameDescribeSchedule(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	setID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data: map[string]any{
			"name":        "initial",
			"description": "first",
			"schedule":    map[string]any{"interval_hours": 12},
		},
		ActorType: "user", ActorID: "u-1",
	}))

	got, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, "initial", got.Name)
	assert.Equal(t, "first", got.Description)
	assert.JSONEq(t, `{"interval_hours":12}`, string(got.Schedule))
	assert.Greater(t, got.ProjectionVersion, int64(0))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetRenamed",
		Data:      map[string]any{"name": "renamed"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetDescriptionUpdated",
		Data:      map[string]any{"description": "second"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, "second", got.Description)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetScheduleUpdated",
		Data:      map[string]any{"schedule": map[string]any{"cron": "*/5 * * * *"}},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.JSONEq(t, `{"cron":"*/5 * * * *"}`, string(got.Schedule))
}

// TestActionSetListener_MemberAddRemoveRecounts covers the
// MemberAdded → MemberRemoved cycle and asserts member_count tracks
// the live row count after each.
func TestActionSetListener_MemberAddRemoveRecounts(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	setID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data:      map[string]any{"name": "members"},
		ActorType: "user", ActorID: "u",
	}))

	// Two members.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": "act-A", "sort_order": 0},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": "act-B", "sort_order": 1},
		ActorType: "user", ActorID: "u",
	}))

	got, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.MemberCount)

	// Repeat-add the same member: ON CONFLICT DO NOTHING preserves
	// idempotency; member_count stays at 2.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": "act-A", "sort_order": 99},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.MemberCount, "repeat-add of an existing member must not double-count")

	// Remove one.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberRemoved",
		Data:      map[string]any{"action_id": "act-A"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), got.MemberCount)

	// Remove the same again: DELETE no-ops, recount stays at 1.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberRemoved",
		Data:      map[string]any{"action_id": "act-A"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), got.MemberCount, "double-remove must be idempotent (DELETE-then-recount)")
}

// TestActionSetListener_MemberReorderUpdatesRow verifies the per-
// member sort_order changes and the parent's updated_at +
// projection_version bump.
func TestActionSetListener_MemberReorderUpdatesRow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	setID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data:      map[string]any{"name": "reorder"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": "act-A", "sort_order": 0},
		ActorType: "user", ActorID: "u",
	}))

	beforeReorder, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	beforeVersion := beforeReorder.ProjectionVersion

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberReordered",
		Data:      map[string]any{"action_id": "act-A", "sort_order": 42},
		ActorType: "user", ActorID: "u",
	}))

	member, err := st.Queries().GetActionSetMember(ctx, db.GetActionSetMemberParams{
		SetID: setID, ActionID: "act-A",
	})
	require.NoError(t, err)
	assert.Equal(t, int32(42), member.SortOrder)

	after, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Greater(t, after.ProjectionVersion, beforeVersion,
		"reorder bumps parent projection_version + updated_at")
}

// TestActionSetListener_DeleteCascadesMembersAndDefinitions confirms
// ActionSetDeleted soft-deletes the set, wipes every member row, AND
// (the cross-stream cascade that makes this projector trickier than
// role) decrements member_count on every parent definition that
// contained the set, then deletes the matching
// definition_members rows.
func TestActionSetListener_DeleteCascadesMembersAndDefinitions(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	setID := testutil.NewID()
	defID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data:      map[string]any{"name": "to-delete"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": "act-A"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": "act-B"},
		ActorType: "user", ActorID: "u",
	}))

	// Plant a definitions_projection row + a definition_members
	// row that references our action set. Direct SQL because the
	// definition projector is still PL/pgSQL — we don't want to
	// couple this test to its event flow.
	_, err := st.Pool().Exec(ctx,
		`INSERT INTO definitions_projection (id, name, member_count, created_at, created_by, projection_version)
		 VALUES ($1, $2, 1, NOW(), '', 0)`,
		defID, "wraps-our-set",
	)
	require.NoError(t, err)
	_, err = st.Pool().Exec(ctx,
		`INSERT INTO definition_members_projection (definition_id, action_set_id, sort_order, added_at)
		 VALUES ($1, $2, 0, NOW())`,
		defID, setID,
	)
	require.NoError(t, err)

	// Delete the set.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	// Set row marked deleted.
	var isDeleted bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT is_deleted FROM action_sets_projection WHERE id = $1", setID,
	).Scan(&isDeleted))
	assert.True(t, isDeleted)

	// Members wiped.
	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM action_set_members_projection WHERE set_id = $1", setID,
	).Scan(&count))
	assert.Equal(t, 0, count)

	// definition_members rows for this set wiped.
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM definition_members_projection WHERE action_set_id = $1", setID,
	).Scan(&count))
	assert.Equal(t, 0, count)

	// Parent definition's member_count decremented (1 → 0).
	var memberCount int32
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT member_count FROM definitions_projection WHERE id = $1", defID,
	).Scan(&memberCount))
	assert.Equal(t, int32(0), memberCount,
		"parent definitions referencing the deleted set must have member_count decremented")
}

// TestActionSetListener_StaleReplayRejected — UPDATE form (Renamed)
// doesn't clobber a fresher row when re-applied with an older
// projection_version. Mirrors the role projector's stale-replay
// regression test.
func TestActionSetListener_StaleReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	setID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data:      map[string]any{"name": "first"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetRenamed",
		Data:      map[string]any{"name": "current"},
		ActorType: "user", ActorID: "u",
	}))
	current, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	currentVersion := current.ProjectionVersion

	older := currentVersion - 5
	updatedAt := current.CreatedAt
	n, err := st.Queries().RenameActionSetProjection(ctx, db.RenameActionSetProjectionParams{
		ID:                setID,
		Name:              "stale-would-set-this",
		UpdatedAt:         updatedAt,
		ProjectionVersion: older,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "stale projection_version UPDATE must affect zero rows")

	after, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, "current", after.Name)
	assert.Equal(t, currentVersion, after.ProjectionVersion)
}

// TestActionSetListener_StaleDeleteReplayDoesNotNukeMembers locks the
// asymmetric-guard discipline for the most cascade-heavy event type:
// when the version-guarded SoftDelete affects zero rows, every
// downstream cascade (member wipe, parent-definition decrement,
// definition_members wipe) MUST be skipped.
func TestActionSetListener_StaleDeleteReplayDoesNotNukeMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	setID := testutil.NewID()
	defID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data:      map[string]any{"name": "live"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"action_id": "act-A"},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)

	_, err = st.Pool().Exec(ctx,
		`INSERT INTO definitions_projection (id, name, member_count, created_at, created_by, projection_version)
		 VALUES ($1, $2, 1, NOW(), '', 0)`,
		defID, "still-references-live-set",
	)
	require.NoError(t, err)
	_, err = st.Pool().Exec(ctx,
		`INSERT INTO definition_members_projection (definition_id, action_set_id, sort_order, added_at)
		 VALUES ($1, $2, 0, NOW())`,
		defID, setID,
	)
	require.NoError(t, err)

	// Drive the listener with a stale ActionSetDeleted (older
	// projection_version than the row currently has).
	older := live.ProjectionVersion - 5
	staleAt := *live.CreatedAt
	listener := projectors.ActionSetListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "action_set",
		StreamID:    setID,
		EventType:   "ActionSetDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	// Set still alive.
	stillAlive, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted, "stale ActionSetDeleted must NOT flip is_deleted")

	// Member still there.
	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM action_set_members_projection WHERE set_id = $1", setID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale ActionSetDeleted must NOT cascade-delete members")

	// definition_members row still there.
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM definition_members_projection WHERE action_set_id = $1", setID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale ActionSetDeleted must NOT cascade-delete definition_members")

	// Parent definition's member_count untouched.
	var memberCount int32
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT member_count FROM definitions_projection WHERE id = $1", defID,
	).Scan(&memberCount))
	assert.Equal(t, int32(1), memberCount,
		"stale ActionSetDeleted must NOT decrement live definitions' member_count")
}

// TestActionSetListener_StaleMemberAddedDoesNotRecreateMembership locks
// the Claim-first guard added as a sibling-sweep follow-up to the
// CR catch on the user_group port (PR #174). A stale
// ActionSetMemberAdded replayed after a Removed must NOT reinsert
// the membership row, even though InsertActionSetMember is
// idempotent (ON CONFLICT DO NOTHING): the version guard runs
// BEFORE the INSERT.
func TestActionSetListener_StaleMemberAddedDoesNotRecreateMembership(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	setID := testutil.NewID()
	actionID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetCreated",
		Data:      map[string]any{"name": "stale-add-set"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberAdded",
		Data:      map[string]any{"set_id": setID, "action_id": actionID, "sort_order": 0},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action_set", StreamID: setID, EventType: "ActionSetMemberRemoved",
		Data:      map[string]any{"set_id": setID, "action_id": actionID},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), live.MemberCount)

	older := live.ProjectionVersion - 5
	staleAt := *live.UpdatedAt
	listener := projectors.ActionSetListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "action_set",
		StreamID:    setID,
		EventType:   "ActionSetMemberAdded",
		Data:        jsonOrFail(t, map[string]any{"set_id": setID, "action_id": actionID, "sort_order": 0}),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM action_set_members_projection WHERE set_id = $1 AND action_id = $2",
		setID, actionID,
	).Scan(&count))
	assert.Equal(t, 0, count, "stale ActionSetMemberAdded must NOT recreate the membership row")

	after, err := st.Queries().GetActionSetByID(ctx, setID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), after.MemberCount)
	assert.Equal(t, live.ProjectionVersion, after.ProjectionVersion)
}

// TestActionSetListener_IgnoresWrongStreamType — defensive.
func TestActionSetListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	setID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", // wrong stream
		StreamID:   setID,
		EventType:  "ActionSetCreated",
		Data:       map[string]any{"name": "ghost"},
		ActorType:  "user", ActorID: "u",
	}))

	_, err := st.Queries().GetActionSetByID(ctx, setID)
	require.Error(t, err, "wrong-stream-type ActionSetCreated must NOT create a row")
}
