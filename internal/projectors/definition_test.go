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
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestDefinitionCreatedFromEvent_Pure pins the SynthesisedAction
// discriminator: presence of `action_type` (not value) flips it.
func TestDefinitionCreatedFromEvent_Pure(t *testing.T) {
	t.Run("definition branch — no action_type → SynthesisedAction=false", func(t *testing.T) {
		got, err := projectors.DefinitionCreatedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-1", EventType: "DefinitionCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"name":        "weekly",
				"description": "weekly maintenance",
				"schedule":    map[string]any{"interval_hours": 24},
			}),
		})
		require.NoError(t, err)
		assert.False(t, got.SynthesisedAction)
		assert.Equal(t, "def-1", got.ID)
		assert.Equal(t, "weekly", got.Name)
		assert.Equal(t, "weekly maintenance", got.Description)
		assert.JSONEq(t, `{"interval_hours":24}`, string(got.Schedule))
		assert.Equal(t, "u", got.CreatedBy)
	})

	t.Run("synthesis branch — action_type present → SynthesisedAction=true", func(t *testing.T) {
		got, err := projectors.DefinitionCreatedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-2", EventType: "DefinitionCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{
				"name":        "synth",
				"action_type": 5,
				"params":      map[string]any{"x": 1},
			}),
		})
		require.NoError(t, err)
		assert.True(t, got.SynthesisedAction,
			"presence of action_type triggers the synthesis branch")
		assert.Equal(t, int32(5), got.ActionType)
		assert.JSONEq(t, `{"x":1}`, string(got.Params))
	})

	t.Run("synthesis branch — explicit null action_type also counts as present", func(t *testing.T) {
		// PL/pgSQL `event.data ? 'action_type'` returns TRUE even when
		// the value is JSON null. Mirror that here so a synthesised-
		// action event with `"action_type": null` lands on the
		// synthesis branch.
		got, err := projectors.DefinitionCreatedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-3", EventType: "DefinitionCreated", ActorID: "u",
			Data: []byte(`{"name":"nullsynth","action_type":null}`),
		})
		require.NoError(t, err)
		assert.True(t, got.SynthesisedAction,
			"null-valued action_type counts as 'present' under PL/pgSQL ? operator semantics")
	})

	t.Run("defaults: description='', schedule={interval_hours:8}, params={}, timeout=300", func(t *testing.T) {
		got, err := projectors.DefinitionCreatedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-4", EventType: "DefinitionCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"name": "minimal"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
		assert.JSONEq(t, `{"interval_hours":8}`, string(got.Schedule))
		assert.JSONEq(t, `{}`, string(got.Params))
		assert.Equal(t, int32(300), got.TimeoutSeconds)
	})

	t.Run("name is required", func(t *testing.T) {
		_, err := projectors.DefinitionCreatedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-5", EventType: "DefinitionCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"description": "no name"}),
		})
		require.Error(t, err)
	})

	t.Run("accepts both stream types (action AND definition)", func(t *testing.T) {
		// The action stream invocation is how the synthesised-action
		// branch receives the event — the listener dispatches to it
		// from action_listener.go.
		_, err := projectors.DefinitionCreatedFromEvent(store.PersistedEvent{
			StreamType: "action", StreamID: "x", EventType: "DefinitionCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"name": "x"}),
		})
		require.NoError(t, err)
		_, err = projectors.DefinitionCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "DefinitionCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.DefinitionCreatedFromEvent(store.PersistedEvent{
			StreamType: "definition", EventType: "DefinitionCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDefinitionRenamedFromEvent_Pure — name is required.
func TestDefinitionRenamedFromEvent_Pure(t *testing.T) {
	got, err := projectors.DefinitionRenamedFromEvent(store.PersistedEvent{
		StreamType: "definition", StreamID: "def-1", EventType: "DefinitionRenamed",
		Data: jsonOrFail(t, map[string]any{"name": "renamed"}),
	})
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)

	_, err = projectors.DefinitionRenamedFromEvent(store.PersistedEvent{
		StreamType: "definition", StreamID: "def-1", EventType: "DefinitionRenamed",
		Data: jsonOrFail(t, map[string]any{}),
	})
	require.Error(t, err)
}

// TestDefinitionDescriptionUpdatedFromEvent_Pure — exposes BOTH the
// definition-stream collapse (Description string) AND the action-stream
// pass-through (DescriptionPtr *string).
func TestDefinitionDescriptionUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("explicit description set", func(t *testing.T) {
		got, err := projectors.DefinitionDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-1", EventType: "DefinitionDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{"description": "new"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "new", got.Description)
		require.NotNil(t, got.DescriptionPtr)
		assert.Equal(t, "new", *got.DescriptionPtr)
	})

	t.Run("missing description: Description='' AND DescriptionPtr=nil", func(t *testing.T) {
		got, err := projectors.DefinitionDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-1", EventType: "DefinitionDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description,
			"definition stream collapses missing → '' (matches PL/pgSQL COALESCE)")
		assert.Nil(t, got.DescriptionPtr,
			"action stream sees nil pointer → NULL (matches direct pass-through)")
	})
}

// TestDefinitionScheduleUpdatedFromEvent_Pure — missing → column default.
func TestDefinitionScheduleUpdatedFromEvent_Pure(t *testing.T) {
	got, err := projectors.DefinitionScheduleUpdatedFromEvent(store.PersistedEvent{
		StreamType: "definition", StreamID: "def-1", EventType: "DefinitionScheduleUpdated",
		Data: jsonOrFail(t, map[string]any{}),
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"interval_hours":8}`, string(got.Schedule))
}

// TestDefinitionMemberAddedFromEvent_Pure — sort_order defaults 0.
func TestDefinitionMemberAddedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.DefinitionMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-1", EventType: "DefinitionMemberAdded",
			Data: jsonOrFail(t, map[string]any{"action_set_id": "as-1", "sort_order": 7}),
		})
		require.NoError(t, err)
		assert.Equal(t, "def-1", got.DefinitionID)
		assert.Equal(t, "as-1", got.ActionSetID)
		assert.Equal(t, int32(7), got.SortOrder)
	})
	t.Run("sort_order missing → 0", func(t *testing.T) {
		got, err := projectors.DefinitionMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-1", EventType: "DefinitionMemberAdded",
			Data: jsonOrFail(t, map[string]any{"action_set_id": "as-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.SortOrder)
	})
	t.Run("missing action_set_id is a validation error", func(t *testing.T) {
		_, err := projectors.DefinitionMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "definition", StreamID: "def-1", EventType: "DefinitionMemberAdded",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
	})
}

// TestDefinitionMemberRemovedFromEvent_Pure
func TestDefinitionMemberRemovedFromEvent_Pure(t *testing.T) {
	got, err := projectors.DefinitionMemberRemovedFromEvent(store.PersistedEvent{
		StreamType: "definition", StreamID: "def-1", EventType: "DefinitionMemberRemoved",
		Data: jsonOrFail(t, map[string]any{"action_set_id": "as-9"}),
	})
	require.NoError(t, err)
	assert.Equal(t, "as-9", got.ActionSetID)
}

// TestDefinitionMemberReorderedFromEvent_Pure
func TestDefinitionMemberReorderedFromEvent_Pure(t *testing.T) {
	got, err := projectors.DefinitionMemberReorderedFromEvent(store.PersistedEvent{
		StreamType: "definition", StreamID: "def-1", EventType: "DefinitionMemberReordered",
		Data: jsonOrFail(t, map[string]any{"action_set_id": "as-1", "sort_order": 3}),
	})
	require.NoError(t, err)
	assert.Equal(t, int32(3), got.SortOrder)
}

// TestDefinitionDeletedFromEvent_Pure — payload-less.
func TestDefinitionDeletedFromEvent_Pure(t *testing.T) {
	id, err := projectors.DefinitionDeletedFromEvent(store.PersistedEvent{
		StreamType: "definition", StreamID: "def-1", EventType: "DefinitionDeleted",
	})
	require.NoError(t, err)
	assert.Equal(t, "def-1", id)
	_, err = projectors.DefinitionDeletedFromEvent(store.PersistedEvent{
		StreamType: "user", EventType: "DefinitionDeleted",
	})
	assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
}

// TestDefinitionListener_FullLifecycle_NoActionType covers the
// definition-stream branch end-to-end (action_type omitted, so the
// definitions_projection branch fires).
func TestDefinitionListener_FullLifecycle_NoActionType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	defID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionCreated",
		Data: map[string]any{
			"name":        "weekly",
			"description": "first",
		},
		ActorType: "user", ActorID: "u",
	}))
	got, err := st.Queries().GetDefinitionByID(ctx, defID)
	require.NoError(t, err)
	assert.Equal(t, "weekly", got.Name)
	assert.Equal(t, "first", got.Description)
	assert.JSONEq(t, `{"interval_hours":8}`, string(got.Schedule),
		"missing schedule defaults to column default")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionRenamed",
		Data:      map[string]any{"name": "biweekly"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDefinitionByID(ctx, defID)
	require.NoError(t, err)
	assert.Equal(t, "biweekly", got.Name)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionDescriptionUpdated",
		Data:      map[string]any{"description": "updated"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDefinitionByID(ctx, defID)
	require.NoError(t, err)
	assert.Equal(t, "updated", got.Description)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionScheduleUpdated",
		Data:      map[string]any{"schedule": map[string]any{"cron": "0 6 * * MON"}},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDefinitionByID(ctx, defID)
	require.NoError(t, err)
	assert.JSONEq(t, `{"cron":"0 6 * * MON"}`, string(got.Schedule))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))
	_, err = st.Queries().GetDefinitionByID(ctx, defID)
	require.Error(t, err, "soft-deleted definition is filtered out by GetDefinitionByID")
}

// TestDefinitionListener_SynthesisedActionBranch covers the action-
// stream branch: a DefinitionCreated event arriving on the action
// stream with an action_type payload INSERTs into actions_projection
// (compliance-policy bootstrap), and the same event arriving on the
// definition stream no-ops.
func TestDefinitionListener_SynthesisedActionBranch(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	id := testutil.NewID()

	// Real production flow synthesises one event per stream — both
	// stream types receive the same DefinitionCreated payload through
	// project_event() dispatch. Mirror that here by calling
	// AppendEvent twice with different StreamType, sharing the same
	// id (the payload is identical).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "action", StreamID: id, EventType: "DefinitionCreated",
		Data: map[string]any{
			"name":        "synth-action",
			"description": "compliance-policy backed",
			"action_type": 3,
			"params":      map[string]any{"k": "v"},
		},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: id, EventType: "DefinitionCreated",
		Data: map[string]any{
			"name":        "synth-action",
			"description": "compliance-policy backed",
			"action_type": 3,
			"params":      map[string]any{"k": "v"},
		},
		ActorType: "user", ActorID: "u",
	}))

	// actions_projection has the synthesised row.
	got, err := st.Queries().GetActionByID(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "synth-action", got.Name)
	assert.Equal(t, int32(3), got.ActionType)
	assert.JSONEq(t, `{"k":"v"}`, string(got.Params))

	// definitions_projection MUST NOT have a row (synthesis branch
	// is the action-stream side; definition stream no-ops).
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM definitions_projection WHERE id = $1", id,
	).Scan(&count))
	assert.Equal(t, 0, count,
		"DefinitionCreated with action_type must NOT insert into definitions_projection")
}

// TestDefinitionListener_MemberAddRemoveRecounts covers the
// MemberAdded → MemberRemoved cycle and asserts member_count tracks
// the live row count after each.
func TestDefinitionListener_MemberAddRemoveRecounts(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	defID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionCreated",
		Data:      map[string]any{"name": "with-members"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionMemberAdded",
		Data:      map[string]any{"action_set_id": "as-A", "sort_order": 0},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionMemberAdded",
		Data:      map[string]any{"action_set_id": "as-B", "sort_order": 1},
		ActorType: "user", ActorID: "u",
	}))
	got, err := st.Queries().GetDefinitionByID(ctx, defID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.MemberCount)

	// Idempotent re-add: ON CONFLICT DO NOTHING + recount keeps
	// member_count stable.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionMemberAdded",
		Data:      map[string]any{"action_set_id": "as-A", "sort_order": 99},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDefinitionByID(ctx, defID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.MemberCount, "repeat-add must not double-count")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionMemberRemoved",
		Data:      map[string]any{"action_set_id": "as-A"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDefinitionByID(ctx, defID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), got.MemberCount)
}

// TestDefinitionListener_StaleMemberAddedDoesNotRecreateMembership
// locks the Claim-first guard for DefinitionMember events: a stale
// MemberAdded replayed after a Removed must NOT reinsert the
// membership row, even though InsertDefinitionMember is idempotent
// (ON CONFLICT DO NOTHING).
func TestDefinitionListener_StaleMemberAddedDoesNotRecreateMembership(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	defID := testutil.NewID()
	actionSetID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionCreated",
		Data:      map[string]any{"name": "stale-add"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionMemberAdded",
		Data:      map[string]any{"action_set_id": actionSetID, "sort_order": 0},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "definition", StreamID: defID, EventType: "DefinitionMemberRemoved",
		Data:      map[string]any{"action_set_id": actionSetID},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetDefinitionByID(ctx, defID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), live.MemberCount)

	// Drive the listener directly with a stale MemberAdded.
	older := live.ProjectionVersion - 5
	staleAt := *live.UpdatedAt
	listener := projectors.ActionListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          ulid.Make().String(),
		SequenceNum: older,
		StreamType:  "definition",
		StreamID:    defID,
		EventType:   "DefinitionMemberAdded",
		Data:        jsonOrFail(t, map[string]any{"action_set_id": actionSetID, "sort_order": 0}),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM definition_members_projection WHERE definition_id = $1 AND action_set_id = $2",
		defID, actionSetID,
	).Scan(&count))
	assert.Equal(t, 0, count,
		"stale DefinitionMemberAdded must NOT recreate the membership row")
	after, err := st.Queries().GetDefinitionByID(ctx, defID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), after.MemberCount)
	assert.Equal(t, live.ProjectionVersion, after.ProjectionVersion)
}

// TestDefinitionListener_IgnoresOtherStreamTypes — defensive: an event
// whose stream type is neither "action" nor "definition" must be
// dropped on the floor.
func TestDefinitionListener_IgnoresOtherStreamTypes(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	id := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", // wrong
		StreamID:   id,
		EventType:  "DefinitionCreated",
		Data:       map[string]any{"name": "ghost"},
		ActorType:  "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM definitions_projection WHERE id = $1", id,
	).Scan(&count))
	assert.Equal(t, 0, count)
}
