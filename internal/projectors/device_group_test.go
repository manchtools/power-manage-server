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

// TestDeviceGroupCreatedFromEvent_Pure pins the decoder defaults that
// match the deleted PL/pgSQL projector: name is required (NOT NULL
// column), missing description → "", missing is_dynamic → FALSE,
// dynamic_query is nullable.
func TestDeviceGroupCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.DeviceGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupCreated", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"name":          "production",
				"description":   "all production hosts",
				"is_dynamic":    true,
				"dynamic_query": `(device.labels.env equals "prod")`,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dg-1", got.ID)
		assert.Equal(t, "production", got.Name)
		assert.Equal(t, "all production hosts", got.Description)
		assert.True(t, got.IsDynamic)
		require.NotNil(t, got.DynamicQuery)
		assert.Equal(t, `(device.labels.env equals "prod")`, *got.DynamicQuery)
		assert.Equal(t, "u-1", got.CreatedBy)
	})

	t.Run("defaults: description empty, is_dynamic false, dynamic_query nil", func(t *testing.T) {
		got, err := projectors.DeviceGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-2", EventType: "DeviceGroupCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"name": "minimal"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
		assert.False(t, got.IsDynamic)
		assert.Nil(t, got.DynamicQuery, "missing dynamic_query stays nil so the column collapses to SQL NULL")
	})

	t.Run("name is required", func(t *testing.T) {
		_, err := projectors.DeviceGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-3", EventType: "DeviceGroupCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"description": "no name"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceGroupCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.DeviceGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceGroupRenamed",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.DeviceGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceGroupCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceGroupRenamedFromEvent_Pure — name is required (the PL/pgSQL
// projector would have written NULL into the NOT NULL column,
// breaking the constraint; we surface this earlier as a decode
// validation error).
func TestDeviceGroupRenamedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.DeviceGroupRenamedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupRenamed",
			Data: jsonOrFail(t, map[string]any{"name": "renamed"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dg-1", got.ID)
		assert.Equal(t, "renamed", got.Name)
	})

	t.Run("missing name fails", func(t *testing.T) {
		_, err := projectors.DeviceGroupRenamedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupRenamed",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceGroupRenamedFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceGroupCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceGroupDescriptionUpdatedFromEvent_Pure — empty payload
// collapses to "" (mirrors the PL/pgSQL COALESCE-to-empty-string).
func TestDeviceGroupDescriptionUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("explicit description", func(t *testing.T) {
		got, err := projectors.DeviceGroupDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{"description": "new"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "new", got.Description)
	})

	t.Run("missing description → empty string", func(t *testing.T) {
		got, err := projectors.DeviceGroupDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupDescriptionUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description, "missing description collapses to '' per PL/pgSQL COALESCE")
	})

	t.Run("empty payload bytes → empty string", func(t *testing.T) {
		got, err := projectors.DeviceGroupDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupDescriptionUpdated",
			Data: nil,
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
	})

	t.Run("wrong stream type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceGroupDescriptionUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceGroupDescriptionUpdated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceGroupQueryUpdatedFromEvent_Pure — missing is_dynamic
// defaults to FALSE; missing dynamic_query stays nil.
func TestDeviceGroupQueryUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("flip to dynamic with query", func(t *testing.T) {
		got, err := projectors.DeviceGroupQueryUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupQueryUpdated",
			Data: jsonOrFail(t, map[string]any{
				"is_dynamic":    true,
				"dynamic_query": "(device.labels.x equals \"y\")",
			}),
		})
		require.NoError(t, err)
		assert.True(t, got.IsDynamic)
		require.NotNil(t, got.DynamicQuery)
		assert.Equal(t, "(device.labels.x equals \"y\")", *got.DynamicQuery)
	})

	t.Run("empty payload → static, no query", func(t *testing.T) {
		got, err := projectors.DeviceGroupQueryUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupQueryUpdated",
			Data: nil,
		})
		require.NoError(t, err)
		assert.False(t, got.IsDynamic)
		assert.Nil(t, got.DynamicQuery)
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceGroupQueryUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceGroupRenamed",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceGroupSyncIntervalSetFromEvent_Pure — missing key collapses
// to 0 (matches PL/pgSQL COALESCE-to-zero).
func TestDeviceGroupSyncIntervalSetFromEvent_Pure(t *testing.T) {
	t.Run("explicit value", func(t *testing.T) {
		got, err := projectors.DeviceGroupSyncIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupSyncIntervalSet",
			Data: jsonOrFail(t, map[string]any{"sync_interval_minutes": 15}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(15), got.SyncIntervalMinutes)
	})

	t.Run("missing key → 0", func(t *testing.T) {
		got, err := projectors.DeviceGroupSyncIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupSyncIntervalSet",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.SyncIntervalMinutes)
	})

	t.Run("wrong stream type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceGroupSyncIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceGroupSyncIntervalSet",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceGroupMaintenanceWindowSetFromEvent_Pure — missing key
// defaults to '{}' (matches PL/pgSQL COALESCE fallback).
func TestDeviceGroupMaintenanceWindowSetFromEvent_Pure(t *testing.T) {
	t.Run("explicit window", func(t *testing.T) {
		got, err := projectors.DeviceGroupMaintenanceWindowSetFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupMaintenanceWindowSet",
			Data: jsonOrFail(t, map[string]any{
				"maintenance_window": map[string]any{
					"schedule": []any{map[string]any{"days": []string{"mon"}, "allow": "22:00-06:00"}},
				},
			}),
		})
		require.NoError(t, err)
		assert.Contains(t, string(got.MaintenanceWindow), "schedule")
	})

	t.Run("missing key → '{}'", func(t *testing.T) {
		got, err := projectors.DeviceGroupMaintenanceWindowSetFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupMaintenanceWindowSet",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.JSONEq(t, "{}", string(got.MaintenanceWindow))
	})

	t.Run("empty payload bytes → '{}'", func(t *testing.T) {
		got, err := projectors.DeviceGroupMaintenanceWindowSetFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupMaintenanceWindowSet",
			Data: nil,
		})
		require.NoError(t, err)
		assert.JSONEq(t, "{}", string(got.MaintenanceWindow))
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceGroupMaintenanceWindowSetFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceGroupRenamed",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceGroupMemberAddedFromEvent_Pure — device_id required;
// both 'DeviceGroupMemberAdded' and 'DeviceAddedToGroup' are accepted.
func TestDeviceGroupMemberAddedFromEvent_Pure(t *testing.T) {
	t.Run("happy path: DeviceGroupMemberAdded", func(t *testing.T) {
		got, err := projectors.DeviceGroupMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupMemberAdded",
			Data: jsonOrFail(t, map[string]any{"device_id": "dev-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dg-1", got.GroupID)
		assert.Equal(t, "dev-1", got.DeviceID)
	})

	t.Run("happy path: DeviceAddedToGroup alias", func(t *testing.T) {
		got, err := projectors.DeviceGroupMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceAddedToGroup",
			Data: jsonOrFail(t, map[string]any{"device_id": "dev-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID, "DeviceAddedToGroup must decode like DeviceGroupMemberAdded")
	})

	t.Run("device_id required", func(t *testing.T) {
		_, err := projectors.DeviceGroupMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupMemberAdded",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "device_id")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceGroupMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceGroupMemberRemoved",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("wrong stream type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceGroupMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceGroupMemberAdded",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceGroupMemberRemovedFromEvent_Pure — same shape as Added
// (both DeviceGroupMemberRemoved and DeviceRemovedFromGroup accepted).
func TestDeviceGroupMemberRemovedFromEvent_Pure(t *testing.T) {
	t.Run("happy path: DeviceGroupMemberRemoved", func(t *testing.T) {
		got, err := projectors.DeviceGroupMemberRemovedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupMemberRemoved",
			Data: jsonOrFail(t, map[string]any{"device_id": "dev-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
	})

	t.Run("happy path: DeviceRemovedFromGroup alias", func(t *testing.T) {
		got, err := projectors.DeviceGroupMemberRemovedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceRemovedFromGroup",
			Data: jsonOrFail(t, map[string]any{"device_id": "dev-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
	})

	t.Run("device_id required", func(t *testing.T) {
		_, err := projectors.DeviceGroupMemberRemovedFromEvent(store.PersistedEvent{
			StreamType: "device_group", StreamID: "dg-1", EventType: "DeviceGroupMemberRemoved",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "device_id")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceGroupMemberRemovedFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceGroupMemberAdded",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceGroupListener_CreateLifecycle drives the full lifecycle of
// a static group (Created → Renamed → MemberAdded → MemberRemoved →
// Deleted) and asserts the projection lands in the right state at
// every step.
func TestDeviceGroupListener_CreateLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data:      map[string]any{"name": "lifecycle", "description": "test"},
		ActorType: "user", ActorID: "u-1",
	}))

	got, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle", got.Name)
	assert.Equal(t, "test", got.Description)
	assert.False(t, got.IsDynamic)
	assert.Equal(t, int32(0), got.MemberCount)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupRenamed",
		Data:      map[string]any{"name": "renamed"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberAdded",
		Data:      map[string]any{"device_id": "dev-A"},
		ActorType: "user", ActorID: "u-1",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberAdded",
		Data:      map[string]any{"device_id": "dev-B"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.MemberCount)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberRemoved",
		Data:      map[string]any{"device_id": "dev-A"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), got.MemberCount)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u-1",
	}))

	_, err = st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.Error(t, err, "GetDeviceGroupByID filters is_deleted=FALSE; deleted group is gone from this query")

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM device_group_members_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 0, count, "DeviceGroupDeleted cascade must wipe member rows")
}

// TestDeviceGroupListener_AliasMemberEvents asserts the alias event
// names (DeviceAddedToGroup / DeviceRemovedFromGroup) drive the same
// add/remove path as the canonical names. The PL/pgSQL projector
// dispatched both names through the same WHEN branch.
func TestDeviceGroupListener_AliasMemberEvents(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data:      map[string]any{"name": "aliases"},
		ActorType: "user", ActorID: "u",
	}))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceAddedToGroup",
		Data:      map[string]any{"device_id": "dev-A"},
		ActorType: "user", ActorID: "u",
	}))
	got, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), got.MemberCount, "DeviceAddedToGroup must drive the same Add path")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceRemovedFromGroup",
		Data:      map[string]any{"device_id": "dev-A"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), got.MemberCount, "DeviceRemovedFromGroup must drive the same Remove path")
}

// TestDeviceGroupListener_DynamicCreatedEnqueues confirms that creating
// a dynamic group inserts a row into dynamic_group_evaluation_queue
// with reason 'group_created' (the PL/pgSQL projector's behaviour).
func TestDeviceGroupListener_DynamicCreatedEnqueues(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data: map[string]any{
			"name":          "dyn",
			"is_dynamic":    true,
			"dynamic_query": `(device.labels.x equals "y")`,
		},
		ActorType: "user", ActorID: "u",
	}))

	got, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.True(t, got.IsDynamic)

	var reason *string
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT reason FROM dynamic_group_evaluation_queue WHERE group_id = $1", groupID,
	).Scan(&reason))
	require.NotNil(t, reason)
	assert.Equal(t, "group_created", *reason)
}

// TestDeviceGroupListener_QueryUpdatedFlipToDynamicCascade locks the
// flip-to-dynamic cascade: when a previously-static group with members
// gets a DeviceGroupQueryUpdated event with is_dynamic=true, the
// listener must wipe every member row, zero member_count, and queue
// the group for evaluation with reason 'query_updated'.
func TestDeviceGroupListener_QueryUpdatedFlipToDynamicCascade(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data:      map[string]any{"name": "static-then-dynamic"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberAdded",
		Data:      map[string]any{"device_id": "dev-A"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberAdded",
		Data:      map[string]any{"device_id": "dev-B"},
		ActorType: "user", ActorID: "u",
	}))
	beforeFlip, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), beforeFlip.MemberCount)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupQueryUpdated",
		Data: map[string]any{
			"is_dynamic":    true,
			"dynamic_query": `(device.labels.env equals "prod")`,
		},
		ActorType: "user", ActorID: "u",
	}))

	afterFlip, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.True(t, afterFlip.IsDynamic, "group must be marked dynamic after flip")
	assert.Equal(t, int32(0), afterFlip.MemberCount, "flip-to-dynamic must zero member_count")

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM device_group_members_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 0, count, "flip-to-dynamic must wipe every static member row")

	var reason *string
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT reason FROM dynamic_group_evaluation_queue WHERE group_id = $1", groupID,
	).Scan(&reason))
	require.NotNil(t, reason)
	assert.Equal(t, "query_updated", *reason, "flip-to-dynamic must enqueue with reason 'query_updated'")
}

// TestDeviceGroupListener_DynamicGroupRejectsMemberMutations confirms
// the parent-is-dynamic gate: member-mutation events are no-ops on
// dynamic groups (the dynamic-query evaluator owns the member set).
// Mirrors the PL/pgSQL `IF NOT EXISTS (... is_dynamic = TRUE)` guard.
func TestDeviceGroupListener_DynamicGroupRejectsMemberMutations(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data: map[string]any{
			"name":          "dyn",
			"is_dynamic":    true,
			"dynamic_query": `(device.labels.x equals "y")`,
		},
		ActorType: "user", ActorID: "u",
	}))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberAdded",
		Data:      map[string]any{"device_id": "dev-X"},
		ActorType: "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM device_group_members_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 0, count, "DeviceGroupMemberAdded against a dynamic group must be a no-op")

	got, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), got.MemberCount, "member_count must stay at 0 — dynamic group's evaluator owns the count")
}

// TestDeviceGroupListener_StaleReplayRejected — UPDATE form (Renamed)
// does not clobber a fresher row when re-applied with an older
// projection_version. Mirrors the role/action_set/assignment pattern.
func TestDeviceGroupListener_StaleReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data:      map[string]any{"name": "first"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupRenamed",
		Data:      map[string]any{"name": "current"},
		ActorType: "user", ActorID: "u",
	}))
	current, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	currentVersion := current.ProjectionVersion

	older := currentVersion - 5
	n, err := st.Queries().RenameDeviceGroupProjection(ctx, db.RenameDeviceGroupProjectionParams{
		ID:                groupID,
		Name:              "stale-would-set-this",
		ProjectionVersion: older,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "stale projection_version UPDATE must affect zero rows")

	after, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, "current", after.Name)
	assert.Equal(t, currentVersion, after.ProjectionVersion)
}

// TestDeviceGroupListener_StaleDeleteReplayDoesNotNukeMembers locks the
// asymmetric-guard discipline for the most cascade-heavy event type:
// when the version-guarded SoftDelete affects zero rows, every
// downstream cascade (member wipe + dynamic-queue cleanup) MUST be
// skipped. Otherwise an old DeviceGroupDeleted re-applied later would
// silently drop a freshly-restored group's members.
func TestDeviceGroupListener_StaleDeleteReplayDoesNotNukeMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data:      map[string]any{"name": "live"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberAdded",
		Data:      map[string]any{"device_id": "dev-A"},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)

	// Drive the listener with a stale DeviceGroupDeleted (older
	// projection_version than the row currently has).
	older := live.ProjectionVersion - 5
	staleAt := *live.CreatedAt
	listener := projectors.DeviceGroupListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "device_group",
		StreamID:    groupID,
		EventType:   "DeviceGroupDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	// Group still alive.
	stillAlive, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted, "stale DeviceGroupDeleted must NOT flip is_deleted")

	// Member still there.
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM device_group_members_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale DeviceGroupDeleted must NOT cascade-delete members")
}

// TestDeviceGroupListener_StaleQueryUpdatedDoesNotNukeMembers locks
// the asymmetric-guard discipline for the QueryUpdated flip-to-
// dynamic cascade: when the version-guarded UpdateDeviceGroupQuery
// affects zero rows, the cascade (member wipe + member_count reset +
// re-enqueue) MUST be skipped. Otherwise an old QueryUpdated
// re-applied by the reconciler against a live static group would
// silently nuke its members and re-enqueue a group whose query has
// already changed downstream.
func TestDeviceGroupListener_StaleQueryUpdatedDoesNotNukeMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data:      map[string]any{"name": "live-static"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberAdded",
		Data:      map[string]any{"device_id": "dev-A"},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)

	older := live.ProjectionVersion - 5
	staleAt := *live.CreatedAt
	listener := projectors.DeviceGroupListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "device_group",
		StreamID:    groupID,
		EventType:   "DeviceGroupQueryUpdated",
		Data:        jsonOrFail(t, map[string]any{"is_dynamic": true, "dynamic_query": "(x equals \"y\")"}),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	// Group must still be static — the guarded UPDATE rejected the
	// stale flip-to-dynamic event.
	stillStatic, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.False(t, stillStatic.IsDynamic, "stale QueryUpdated must NOT flip is_dynamic")

	// Member still there because the cascade was skipped.
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM device_group_members_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale QueryUpdated must NOT cascade-wipe static members")

	// No queue entry — the cascade was skipped.
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM dynamic_group_evaluation_queue WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 0, count, "stale QueryUpdated must NOT enqueue the group")
}

// TestDeviceGroupListener_StaleMemberAddedDoesNotRecreateMembership
// locks the same Claim-first hole CR caught on the user_group port
// (PR #174). A stale DeviceGroupMemberAdded replayed after a Removed
// must NOT reinsert the membership row, even though the INSERT
// itself is idempotent: the version guard now runs BEFORE the
// INSERT.
func TestDeviceGroupListener_StaleMemberAddedDoesNotRecreateMembership(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()
	deviceID := "dev-stale-add"

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data:      map[string]any{"name": "stale-add-grp"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberAdded",
		Data:      map[string]any{"device_id": deviceID},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupMemberRemoved",
		Data:      map[string]any{"device_id": deviceID},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), live.MemberCount)

	older := live.ProjectionVersion - 5
	staleAt := *live.CreatedAt
	listener := projectors.DeviceGroupListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "device_group",
		StreamID:    groupID,
		EventType:   "DeviceGroupMemberAdded",
		Data:        jsonOrFail(t, map[string]any{"device_id": deviceID}),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM device_group_members_projection WHERE group_id = $1 AND device_id = $2",
		groupID, deviceID,
	).Scan(&count))
	assert.Equal(t, 0, count, "stale DeviceGroupMemberAdded must NOT recreate the membership row")

	after, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), after.MemberCount)
	assert.Equal(t, live.ProjectionVersion, after.ProjectionVersion)
}

// TestDeviceGroupListener_QueryUpdatedSteadyStateDynamicEditPreservesMembers
// is the device_group sibling of the user_group regression that
// CR caught on PR #174: editing the dynamic_query of an already-
// dynamic group must NOT trigger the cascade. The cascade (member
// wipe + member_count zero + re-enqueue) is for the static→dynamic
// transition only — the evaluator owns the member set in steady
// state and re-evaluates on its own schedule.
func TestDeviceGroupListener_QueryUpdatedSteadyStateDynamicEditPreservesMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupCreated",
		Data:      map[string]any{"name": "dyn", "is_dynamic": true, "dynamic_query": "(env equals \"prod\")"},
		ActorType: "user", ActorID: "u",
	}))
	_, err := st.TestingPool().Exec(ctx, `
		INSERT INTO device_group_members_projection (group_id, device_id, added_at, projection_version)
		VALUES ($1, 'dev-evaluator-populated', now(), 0)`, groupID)
	require.NoError(t, err)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device_group", StreamID: groupID, EventType: "DeviceGroupQueryUpdated",
		Data:      map[string]any{"is_dynamic": true, "dynamic_query": "(env equals \"staging\")"},
		ActorType: "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM device_group_members_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 1, count, "steady-state dynamic-query edit must NOT wipe evaluator-populated members")
}

// TestDeviceGroupListener_IgnoresWrongStreamType — defensive.
func TestDeviceGroupListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", // wrong stream
		StreamID:   groupID,
		EventType:  "DeviceGroupCreated",
		Data:       map[string]any{"name": "should-not-write"},
		ActorType:  "user", ActorID: "u",
	}))

	_, err := st.Queries().GetDeviceGroupByID(ctx, groupID)
	require.Error(t, err, "wrong-stream-type DeviceGroupCreated must NOT create a device_groups_projection row")
}
