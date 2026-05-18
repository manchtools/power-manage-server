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

// TestUserGroupCreatedFromEvent_Pure pins the decoder defaults that
// match the deleted PL/pgSQL projector: name is required (NOT NULL
// column), missing description → "", missing is_dynamic → FALSE,
// dynamic_query is nullable.
func TestUserGroupCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.UserGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupCreated", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"name":          "engineers",
				"description":   "all engineers",
				"is_dynamic":    true,
				"dynamic_query": `(user.email contains "@example.com")`,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "ug-1", got.ID)
		assert.Equal(t, "engineers", got.Name)
		assert.Equal(t, "all engineers", got.Description)
		assert.True(t, got.IsDynamic)
		require.NotNil(t, got.DynamicQuery)
		assert.Equal(t, `(user.email contains "@example.com")`, *got.DynamicQuery)
		assert.Equal(t, "u-1", got.CreatedBy)
	})

	t.Run("defaults: description empty, is_dynamic false, dynamic_query nil", func(t *testing.T) {
		got, err := projectors.UserGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-2", EventType: "UserGroupCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"name": "minimal"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
		assert.False(t, got.IsDynamic)
		assert.Nil(t, got.DynamicQuery, "missing dynamic_query stays nil so the column collapses to SQL NULL")
	})

	t.Run("name is required", func(t *testing.T) {
		_, err := projectors.UserGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-3", EventType: "UserGroupCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"description": "no name"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.UserGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "UserGroupCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.UserGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", EventType: "UserGroupUpdated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.UserGroupCreatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", EventType: "UserGroupCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestUserGroupUpdatedFromEvent_Pure — name is required (the PL/pgSQL
// projector would have written NULL into the NOT NULL column). The
// description field uses the "pointer to distinguish present-from-
// absent" pattern from the role projector.
func TestUserGroupUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with description set", func(t *testing.T) {
		got, err := projectors.UserGroupUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupUpdated",
			Data: jsonOrFail(t, map[string]any{"name": "renamed", "description": "new desc"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "renamed", got.Name)
		require.NotNil(t, got.Description)
		assert.Equal(t, "new desc", *got.Description)
	})

	t.Run("missing description → nil (preserve existing)", func(t *testing.T) {
		got, err := projectors.UserGroupUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupUpdated",
			Data: jsonOrFail(t, map[string]any{"name": "only-name"}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.Description, "missing description must collapse to nil so SQL COALESCE preserves existing")
	})

	t.Run("explicit empty description → present-with-empty-string", func(t *testing.T) {
		got, err := projectors.UserGroupUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupUpdated",
			Data: jsonOrFail(t, map[string]any{"name": "name", "description": ""}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Description)
		assert.Equal(t, "", *got.Description, "explicit empty-string description blanks the column")
	})

	t.Run("missing name fails", func(t *testing.T) {
		_, err := projectors.UserGroupUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupUpdated",
			Data: jsonOrFail(t, map[string]any{"description": "x"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestUserGroupQueryUpdatedFromEvent_Pure — both is_dynamic and
// dynamic_query are nullable / defaulted; missing payload bytes are
// not an error.
func TestUserGroupQueryUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path: dynamic flip on", func(t *testing.T) {
		got, err := projectors.UserGroupQueryUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupQueryUpdated",
			Data: jsonOrFail(t, map[string]any{
				"is_dynamic":    true,
				"dynamic_query": `(user.disabled = false)`,
			}),
		})
		require.NoError(t, err)
		assert.True(t, got.IsDynamic)
		require.NotNil(t, got.DynamicQuery)
		assert.Equal(t, `(user.disabled = false)`, *got.DynamicQuery)
	})

	t.Run("missing is_dynamic → false (matches PL/pgSQL COALESCE)", func(t *testing.T) {
		got, err := projectors.UserGroupQueryUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupQueryUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.False(t, got.IsDynamic)
		assert.Nil(t, got.DynamicQuery)
	})

	t.Run("empty payload bytes → defaults", func(t *testing.T) {
		got, err := projectors.UserGroupQueryUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupQueryUpdated",
			Data: nil,
		})
		require.NoError(t, err)
		assert.False(t, got.IsDynamic)
	})
}

// TestUserGroupMaintenanceWindowSetFromEvent_Pure — missing key
// collapses to '{}' (matches the PL/pgSQL `COALESCE(payload, '{}'::JSONB)`).
func TestUserGroupMaintenanceWindowSetFromEvent_Pure(t *testing.T) {
	t.Run("explicit window preserved verbatim", func(t *testing.T) {
		got, err := projectors.UserGroupMaintenanceWindowSetFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupMaintenanceWindowSet",
			Data: jsonOrFail(t, map[string]any{
				"maintenance_window": map[string]any{"days": []string{"sat"}},
			}),
		})
		require.NoError(t, err)
		assert.JSONEq(t, `{"days":["sat"]}`, string(got.MaintenanceWindow))
	})

	t.Run("missing window key → '{}' fallback", func(t *testing.T) {
		got, err := projectors.UserGroupMaintenanceWindowSetFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupMaintenanceWindowSet",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.JSONEq(t, `{}`, string(got.MaintenanceWindow))
	})

	t.Run("empty payload bytes → '{}' fallback", func(t *testing.T) {
		got, err := projectors.UserGroupMaintenanceWindowSetFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupMaintenanceWindowSet",
			Data: nil,
		})
		require.NoError(t, err)
		assert.JSONEq(t, `{}`, string(got.MaintenanceWindow))
	})
}

// TestUserGroupMemberFromEvent_Pure — both group_id and user_id are
// required (NOT NULL columns). Empty payload, missing keys, wrong
// stream/event type all fail in the documented way.
func TestUserGroupMemberFromEvent_Pure(t *testing.T) {
	t.Run("MemberAdded happy path", func(t *testing.T) {
		got, err := projectors.UserGroupMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "stream-id", EventType: "UserGroupMemberAdded",
			Data: jsonOrFail(t, map[string]any{"group_id": "g-1", "user_id": "u-1"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "g-1", got.GroupID)
		assert.Equal(t, "u-1", got.UserID)
	})

	t.Run("MemberRemoved happy path", func(t *testing.T) {
		got, err := projectors.UserGroupMemberRemovedFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "stream-id", EventType: "UserGroupMemberRemoved",
			Data: jsonOrFail(t, map[string]any{"group_id": "g-2", "user_id": "u-2"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "g-2", got.GroupID)
		assert.Equal(t, "u-2", got.UserID)
	})

	t.Run("missing group_id fails", func(t *testing.T) {
		_, err := projectors.UserGroupMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "user_group", EventType: "UserGroupMemberAdded",
			Data: jsonOrFail(t, map[string]any{"user_id": "u"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "group_id")
	})

	t.Run("missing user_id fails", func(t *testing.T) {
		_, err := projectors.UserGroupMemberRemovedFromEvent(store.PersistedEvent{
			StreamType: "user_group", EventType: "UserGroupMemberRemoved",
			Data: jsonOrFail(t, map[string]any{"group_id": "g"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user_id")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.UserGroupMemberAddedFromEvent(store.PersistedEvent{
			StreamType: "user_group", EventType: "UserGroupCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestUserGroupRoleFromEvent_Pure — both group_id and role_id are
// required.
func TestUserGroupRoleFromEvent_Pure(t *testing.T) {
	t.Run("RoleAssigned happy path", func(t *testing.T) {
		got, err := projectors.UserGroupRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "user_group", EventType: "UserGroupRoleAssigned",
			Data: jsonOrFail(t, map[string]any{"group_id": "g", "role_id": "r"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "g", got.GroupID)
		assert.Equal(t, "r", got.RoleID)
	})

	t.Run("RoleRevoked happy path", func(t *testing.T) {
		got, err := projectors.UserGroupRoleRevokedFromEvent(store.PersistedEvent{
			StreamType: "user_group", EventType: "UserGroupRoleRevoked",
			Data: jsonOrFail(t, map[string]any{"group_id": "g2", "role_id": "r2"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "g2", got.GroupID)
		assert.Equal(t, "r2", got.RoleID)
	})

	t.Run("missing role_id fails", func(t *testing.T) {
		_, err := projectors.UserGroupRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "user_group", EventType: "UserGroupRoleAssigned",
			Data: jsonOrFail(t, map[string]any{"group_id": "g"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role_id")
	})
}

// TestUserGroupMembersRebuiltFromEvent_Pure — empty user_ids collapses
// to an empty slice (matches the PL/pgSQL `jsonb_array_length(... 'user_ids') -> 0`
// fallback). Stream id propagates as the GroupID.
func TestUserGroupMembersRebuiltFromEvent_Pure(t *testing.T) {
	t.Run("happy path with user_ids", func(t *testing.T) {
		got, err := projectors.UserGroupMembersRebuiltFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupMembersRebuilt",
			Data: jsonOrFail(t, map[string]any{"user_ids": []string{"u-1", "u-2"}}),
		})
		require.NoError(t, err)
		assert.Equal(t, "ug-1", got.GroupID)
		assert.Equal(t, []string{"u-1", "u-2"}, got.UserIDs)
	})

	t.Run("missing user_ids → empty slice", func(t *testing.T) {
		got, err := projectors.UserGroupMembersRebuiltFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupMembersRebuilt",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Empty(t, got.UserIDs)
	})

	t.Run("empty payload bytes → empty slice", func(t *testing.T) {
		got, err := projectors.UserGroupMembersRebuiltFromEvent(store.PersistedEvent{
			StreamType: "user_group", StreamID: "ug-1", EventType: "UserGroupMembersRebuilt",
			Data: nil,
		})
		require.NoError(t, err)
		assert.Empty(t, got.UserIDs)
	})
}

// TestUserGroupListener_CreateUpdateMaintenanceWindow covers the three
// single-statement events end-to-end (Create + Update + MaintenanceWindowSet).
// Confirms the row state advances and projection_version bumps.
func TestUserGroupListener_CreateUpdateMaintenanceWindow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupCreated",
		Data: map[string]any{
			"name":        "initial",
			"description": "first desc",
		},
		ActorType: "user", ActorID: "u-1",
	}))

	got, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, "initial", got.Name)
	assert.Equal(t, "first desc", got.Description)
	assert.Equal(t, int32(0), got.MemberCount)
	assert.False(t, got.IsDynamic)
	assert.Greater(t, got.ProjectionVersion, int64(0))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupUpdated",
		Data:      map[string]any{"name": "renamed", "description": "second desc"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)
	assert.Equal(t, "second desc", got.Description)

	// Update with no description preserves the existing value (PL/pgSQL
	// COALESCE(payload, description) semantics).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupUpdated",
		Data:      map[string]any{"name": "renamed-again"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, "renamed-again", got.Name)
	assert.Equal(t, "second desc", got.Description, "missing description must preserve existing")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupMaintenanceWindowSet",
		Data: map[string]any{
			"maintenance_window": map[string]any{"days": []string{"sat", "sun"}},
		},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.JSONEq(t, `{"days":["sat","sun"]}`, string(got.MaintenanceWindow))
}

// TestUserGroupListener_MemberAddRemoveCounter covers the
// MemberAdded → MemberRemoved cycle and asserts member_count tracks
// the +/-1 increment shape verbatim (not a recount), matching the
// PL/pgSQL projector. Idempotent re-add is ON CONFLICT DO NOTHING so
// the INSERT is a no-op, but the UPDATE half of the listener still
// increments — this is a deliberate parity quirk with the legacy
// projector, which suffered the same drift; the periodic reconciler
// is the safety net.
func TestUserGroupListener_MemberAddRemoveCounter(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.CreateTestUserGroup(t, st, "u", "members-grp")
	userA := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")
	userB := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userA, EventType: "UserGroupMemberAdded",
		Data:      map[string]any{"group_id": groupID, "user_id": userA},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userB, EventType: "UserGroupMemberAdded",
		Data:      map[string]any{"group_id": groupID, "user_id": userB},
		ActorType: "user", ActorID: "u",
	}))

	got, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.MemberCount)

	// Verify the membership rows exist.
	memberIDs, err := st.Queries().ListUserGroupMemberIDs(ctx, groupID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{userA, userB}, memberIDs)

	// Remove one. member_count drops to 1.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userA, EventType: "UserGroupMemberRemoved",
		Data:      map[string]any{"group_id": groupID, "user_id": userA},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), got.MemberCount)

	memberIDs, err = st.Queries().ListUserGroupMemberIDs(ctx, groupID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{userB}, memberIDs)
}

// TestUserGroupListener_MemberMutationsSkippedForDynamicGroup locks the
// IF-NOT-EXISTS-dynamic guard from the PL/pgSQL projector. A dynamic
// group's member set is owned by the evaluator, so MemberAdded /
// MemberRemoved events targeting a dynamic group must be no-ops at
// the listener.
func TestUserGroupListener_MemberMutationsSkippedForDynamicGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupCreated",
		Data: map[string]any{
			"name":          "dyn",
			"is_dynamic":    true,
			"dynamic_query": `(user.email contains "@x.com")`,
		},
		ActorType: "user", ActorID: "u",
	}))

	// The dynamic flip enqueues an evaluation row.
	var queueCount int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM dynamic_user_group_evaluation_queue WHERE group_id = $1", groupID,
	).Scan(&queueCount))
	assert.Equal(t, 1, queueCount, "UserGroupCreated for a dynamic group enqueues an evaluation row")

	// MemberAdded against a dynamic group is a no-op.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userID, EventType: "UserGroupMemberAdded",
		Data:      map[string]any{"group_id": groupID, "user_id": userID},
		ActorType: "user", ActorID: "u",
	}))
	got, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), got.MemberCount, "MemberAdded against a dynamic group must NOT increment member_count")

	memberIDs, err := st.Queries().ListUserGroupMemberIDs(ctx, groupID)
	require.NoError(t, err)
	assert.Empty(t, memberIDs, "MemberAdded against a dynamic group must NOT insert a static-membership row")

	// MemberRemoved against a dynamic group is also a no-op.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userID, EventType: "UserGroupMemberRemoved",
		Data:      map[string]any{"group_id": groupID, "user_id": userID},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), got.MemberCount)
}

// TestUserGroupListener_QueryUpdatedFlipToDynamicWipesMembers covers
// the cascade half of UserGroupQueryUpdated: when is_dynamic flips
// ON, every static-membership row is wiped, member_count zeroed, and
// the group is enqueued for the evaluator.
func TestUserGroupListener_QueryUpdatedFlipToDynamicWipesMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.CreateTestUserGroup(t, st, "u", "static-grp")
	userA := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")
	userB := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")

	for _, uid := range []string{userA, userB} {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user_group", StreamID: groupID + ":" + uid, EventType: "UserGroupMemberAdded",
			Data:      map[string]any{"group_id": groupID, "user_id": uid},
			ActorType: "user", ActorID: "u",
		}))
	}
	got, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.MemberCount)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupQueryUpdated",
		Data: map[string]any{
			"is_dynamic":    true,
			"dynamic_query": `(user.disabled = false)`,
		},
		ActorType: "user", ActorID: "u",
	}))

	got, err = st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.True(t, got.IsDynamic)
	assert.Equal(t, int32(0), got.MemberCount, "flip-to-dynamic must zero member_count")

	memberIDs, err := st.Queries().ListUserGroupMemberIDs(ctx, groupID)
	require.NoError(t, err)
	assert.Empty(t, memberIDs, "flip-to-dynamic must wipe every static-membership row")

	var queueCount int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM dynamic_user_group_evaluation_queue WHERE group_id = $1", groupID,
	).Scan(&queueCount))
	assert.Equal(t, 1, queueCount, "flip-to-dynamic must (re-)enqueue the group for the evaluator")
}

// TestUserGroupListener_RoleAssignRevoke covers the two role-
// assignment events end-to-end. No parent-row update — role
// assignments are independent of member_count.
func TestUserGroupListener_RoleAssignRevoke(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.CreateTestUserGroup(t, st, "u", "role-grp")
	roleID := testutil.CreateTestRole(t, st, "u", "test-role-"+testutil.NewID(), []string{"GetUser"})

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":role:" + roleID, EventType: "UserGroupRoleAssigned",
		Data:      map[string]any{"group_id": groupID, "role_id": roleID},
		ActorType: "user", ActorID: "u",
	}))

	roles, err := st.Queries().GetUserGroupRoles(ctx, groupID)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, roleID, roles[0].ID)

	// Idempotent re-assign: composite-PK ON CONFLICT DO NOTHING; still
	// only one row.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":role:" + roleID, EventType: "UserGroupRoleAssigned",
		Data:      map[string]any{"group_id": groupID, "role_id": roleID},
		ActorType: "user", ActorID: "u",
	}))
	roles, err = st.Queries().GetUserGroupRoles(ctx, groupID)
	require.NoError(t, err)
	require.Len(t, roles, 1, "duplicate RoleAssigned must be idempotent")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":role:" + roleID, EventType: "UserGroupRoleRevoked",
		Data:      map[string]any{"group_id": groupID, "role_id": roleID},
		ActorType: "user", ActorID: "u",
	}))
	roles, err = st.Queries().GetUserGroupRoles(ctx, groupID)
	require.NoError(t, err)
	assert.Empty(t, roles)
}

// TestUserGroupListener_MembersRebuilt covers the wipe + bulk-insert
// flow for the (un-emitted) UserGroupMembersRebuilt event. The
// projector keeps parity for replay safety even though no current
// caller emits this event.
func TestUserGroupListener_MembersRebuilt(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.CreateTestUserGroup(t, st, "u", "rebuild-grp")
	userA := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")
	userB := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")
	userC := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")

	// Seed two static members.
	for _, uid := range []string{userA, userB} {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user_group", StreamID: groupID + ":" + uid, EventType: "UserGroupMemberAdded",
			Data:      map[string]any{"group_id": groupID, "user_id": uid},
			ActorType: "user", ActorID: "u",
		}))
	}

	// Rebuild the membership to {B, C}: A is removed, C is added.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupMembersRebuilt",
		Data:      map[string]any{"user_ids": []string{userB, userC}},
		ActorType: "user", ActorID: "u",
	}))

	got, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), got.MemberCount, "MembersRebuilt sets member_count to the new list length")

	memberIDs, err := st.Queries().ListUserGroupMemberIDs(ctx, groupID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{userB, userC}, memberIDs)
}

// TestUserGroupListener_DeleteCascadesMembersAndRoles confirms
// UserGroupDeleted soft-deletes the group, wipes every member row,
// every role-assignment row, the dynamic-evaluation-queue entry, AND
// downstream scim_group_mapping_projection rows pointing at it.
func TestUserGroupListener_DeleteCascadesMembersAndRoles(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.CreateTestUserGroup(t, st, "u", "to-delete")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")
	roleID := testutil.CreateTestRole(t, st, "u", "delete-role-"+testutil.NewID(), []string{"GetUser"})

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userID, EventType: "UserGroupMemberAdded",
		Data:      map[string]any{"group_id": groupID, "user_id": userID},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":role:" + roleID, EventType: "UserGroupRoleAssigned",
		Data:      map[string]any{"group_id": groupID, "role_id": roleID},
		ActorType: "user", ActorID: "u",
	}))

	// Plant a dynamic-queue entry directly so we can confirm the
	// cleanup half of UserGroupDeleted wipes it.
	_, err := st.TestingPool().Exec(ctx,
		`INSERT INTO dynamic_user_group_evaluation_queue (group_id, queued_at, reason)
		 VALUES ($1, NOW(), 'test-seed')
		 ON CONFLICT (group_id) DO NOTHING`,
		groupID,
	)
	require.NoError(t, err)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	// Group row marked deleted.
	var isDeleted bool
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT is_deleted FROM user_groups_projection WHERE id = $1", groupID,
	).Scan(&isDeleted))
	assert.True(t, isDeleted)

	// Members wiped.
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_group_members_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 0, count)

	// Roles wiped.
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_group_roles_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 0, count)

	// Dynamic-evaluation-queue row wiped.
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM dynamic_user_group_evaluation_queue WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 0, count)
}

// TestUserGroupListener_StaleReplayRejected — the UPDATE form (Updated)
// doesn't clobber a fresher row when re-applied with an older
// projection_version. Mirrors the role projector's stale-replay
// regression test.
func TestUserGroupListener_StaleReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupCreated",
		Data:      map[string]any{"name": "first"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupUpdated",
		Data:      map[string]any{"name": "current"},
		ActorType: "user", ActorID: "u",
	}))
	current, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	currentVersion := current.ProjectionVersion

	older := currentVersion - 5
	n, err := st.Queries().UpdateUserGroupProjection(ctx, db.UpdateUserGroupProjectionParams{
		ID:                groupID,
		Name:              "stale-would-set-this",
		Description:       nil,
		UpdatedAt:         current.UpdatedAt,
		ProjectionVersion: older,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "stale projection_version UPDATE must affect zero rows")

	after, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, "current", after.Name)
	assert.Equal(t, currentVersion, after.ProjectionVersion)
}

// TestUserGroupListener_StaleDeleteReplayDoesNotNukeMembers locks the
// asymmetric-guard discipline for the most cascade-heavy event type:
// when the version-guarded SoftDelete affects zero rows, every
// downstream cascade (member wipe, role wipe, scim_group_mapping
// cleanup, dynamic-queue cleanup) MUST be skipped.
func TestUserGroupListener_StaleDeleteReplayDoesNotNukeMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.CreateTestUserGroup(t, st, "u", "live-grp")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")
	roleID := testutil.CreateTestRole(t, st, "u", "live-role-"+testutil.NewID(), []string{"GetUser"})

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userID, EventType: "UserGroupMemberAdded",
		Data:      map[string]any{"group_id": groupID, "user_id": userID},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":role:" + roleID, EventType: "UserGroupRoleAssigned",
		Data:      map[string]any{"group_id": groupID, "role_id": roleID},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)

	// Drive the listener with a stale UserGroupDeleted (older
	// projection_version than the row currently has).
	older := live.ProjectionVersion - 5
	listener := projectors.UserGroupListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "user_group",
		StreamID:    groupID,
		EventType:   "UserGroupDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  live.UpdatedAt,
	})

	// Group still alive.
	stillAlive, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted, "stale UserGroupDeleted must NOT flip is_deleted")

	// Member still there.
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_group_members_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale UserGroupDeleted must NOT cascade-delete members")

	// Role still there.
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_group_roles_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 1, count, "stale UserGroupDeleted must NOT cascade-delete role assignments")
}

// TestUserGroupListener_StaleMemberAddedDoesNotRecreateMembership locks
// the CR finding on PR #174: a stale UserGroupMemberAdded replayed
// after a Removed must not reinsert the member row, even though the
// INSERT itself is idempotent. The Claim guard runs FIRST so a stale
// version short-circuits before the INSERT.
func TestUserGroupListener_StaleMemberAddedDoesNotRecreateMembership(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.CreateTestUserGroup(t, st, "u", "stale-add-grp")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userID, EventType: "UserGroupMemberAdded",
		Data:      map[string]any{"group_id": groupID, "user_id": userID},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userID, EventType: "UserGroupMemberRemoved",
		Data:      map[string]any{"group_id": groupID, "user_id": userID},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), live.MemberCount)

	older := live.ProjectionVersion - 5
	listener := projectors.UserGroupListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "user_group",
		StreamID:    groupID + ":" + userID,
		EventType:   "UserGroupMemberAdded",
		Data:        jsonOrFail(t, map[string]any{"group_id": groupID, "user_id": userID}),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  live.UpdatedAt,
	})

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_group_members_projection WHERE group_id = $1 AND user_id = $2",
		groupID, userID,
	).Scan(&count))
	assert.Equal(t, 0, count, "stale UserGroupMemberAdded must NOT recreate the membership row")

	after, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), after.MemberCount, "member_count stays at 0 after stale replay")
	assert.Equal(t, live.ProjectionVersion, after.ProjectionVersion, "projection_version unchanged")
}

// TestUserGroupListener_StaleMembersRebuiltDoesNotOverwrite locks the
// second CR finding on PR #174: a stale UserGroupMembersRebuilt
// replayed after later membership changes must not wipe the live
// member set, even when the eventual count update affects 0 rows.
// The Claim guard runs FIRST so a stale rebuild short-circuits
// before the WIPE.
func TestUserGroupListener_StaleMembersRebuiltDoesNotOverwrite(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.CreateTestUserGroup(t, st, "u", "stale-rebuilt-grp")
	userA := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")
	userB := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userA, EventType: "UserGroupMemberAdded",
		Data:      map[string]any{"group_id": groupID, "user_id": userA},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":" + userB, EventType: "UserGroupMemberAdded",
		Data:      map[string]any{"group_id": groupID, "user_id": userB},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), live.MemberCount)

	older := live.ProjectionVersion - 5
	listener := projectors.UserGroupListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "user_group",
		StreamID:    groupID,
		EventType:   "UserGroupMembersRebuilt",
		Data:        jsonOrFail(t, map[string]any{"user_ids": []string{}}),
		ActorType:   "system",
		ActorID:     "s",
		OccurredAt:  live.UpdatedAt,
	})

	memberIDs, err := st.Queries().ListUserGroupMemberIDs(ctx, groupID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{userA, userB}, memberIDs,
		"stale UserGroupMembersRebuilt must NOT wipe live members")

	after, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), after.MemberCount, "member_count unchanged after stale replay")
	assert.Equal(t, live.ProjectionVersion, after.ProjectionVersion)
}

// TestUserGroupListener_QueryUpdatedSteadyStateDynamicEditPreservesMembers
// locks the CR catch on PR #174 (line 234): editing the dynamic_query
// of an already-dynamic group must NOT trigger the cascade. The
// cascade (member wipe + member_count zero + re-enqueue) is for the
// static→dynamic transition only — the evaluator owns the member
// set in steady state and re-evaluates on its own schedule.
func TestUserGroupListener_QueryUpdatedSteadyStateDynamicEditPreservesMembers(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupCreated",
		Data:      map[string]any{"name": "dyn", "is_dynamic": true, "dynamic_query": "(role equals \"admin\")"},
		ActorType: "user", ActorID: "u",
	}))
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@x.com", "pass", "user")
	_, err := st.TestingPool().Exec(ctx, `
		INSERT INTO user_group_members_projection (group_id, user_id, added_at, added_by, projection_version)
		VALUES ($1, $2, now(), 'system', 0)`, groupID, userID)
	require.NoError(t, err)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupQueryUpdated",
		Data:      map[string]any{"is_dynamic": true, "dynamic_query": "(role equals \"superuser\")"},
		ActorType: "user", ActorID: "u",
	}))

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_group_members_projection WHERE group_id = $1", groupID,
	).Scan(&count))
	assert.Equal(t, 1, count, "steady-state dynamic-query edit must NOT wipe evaluator-populated members")
}

// TestUserGroupListener_StaleRoleAssignedDoesNotReinsertRevoked locks
// the CR catch on PR #174 (line 319): role mutations must be guarded
// against stale replay. A stale UserGroupRoleAssigned replayed after
// a Revoked must NOT silently re-grant the inherited permissions.
func TestUserGroupListener_StaleRoleAssignedDoesNotReinsertRevoked(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.CreateTestUserGroup(t, st, "u", "stale-role-grp")
	roleID := testutil.CreateTestRole(t, st, "u", "stale-role-"+testutil.NewID(), []string{"GetUser"})

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":role:" + roleID, EventType: "UserGroupRoleAssigned",
		Data:      map[string]any{"group_id": groupID, "role_id": roleID},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID + ":role:" + roleID, EventType: "UserGroupRoleRevoked",
		Data:      map[string]any{"group_id": groupID, "role_id": roleID},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)

	older := live.ProjectionVersion - 5
	listener := projectors.UserGroupListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "user_group",
		StreamID:    groupID + ":role:" + roleID,
		EventType:   "UserGroupRoleAssigned",
		Data:        jsonOrFail(t, map[string]any{"group_id": groupID, "role_id": roleID}),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  live.UpdatedAt,
	})

	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_group_roles_projection WHERE group_id = $1 AND role_id = $2",
		groupID, roleID,
	).Scan(&count))
	assert.Equal(t, 0, count, "stale UserGroupRoleAssigned must NOT reinsert the revoked role")

	after, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, live.ProjectionVersion, after.ProjectionVersion)
}

// TestUserGroupListener_IgnoresWrongStreamType — defensive.
func TestUserGroupListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	groupID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", // wrong stream
		StreamID:   groupID,
		EventType:  "UserGroupCreated",
		Data:       map[string]any{"name": "ghost"},
		ActorType:  "user", ActorID: "u",
	}))

	_, err := st.Queries().GetUserGroupByID(ctx, groupID)
	require.Error(t, err, "wrong-stream-type UserGroupCreated must NOT create a row")
}
