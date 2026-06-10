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

// TestRoleCreatedFromEvent_Pure exercises the decoder for RoleCreated.
// The PL/pgSQL projector defaulted description to "", permissions to
// '{}', is_system to FALSE — Go shape mirrors via zero values + an
// explicit empty-slice for permissions when the payload omits the key.
func TestRoleCreatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.RoleCreatedFromEvent(store.PersistedEvent{
			StreamType: "role",
			StreamID:   "role-1",
			EventType:  "RoleCreated",
			ActorID:    "user-1",
			Data: jsonOrFail(t, map[string]any{
				"name":        "admin",
				"description": "Administrator role",
				"permissions": []string{"users.read", "users.write"},
				"is_system":   false,
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "role-1", got.ID)
		assert.Equal(t, "admin", got.Name)
		assert.Equal(t, "Administrator role", got.Description)
		assert.Equal(t, []string{"users.read", "users.write"}, got.Permissions)
		assert.False(t, got.IsSystem)
		assert.Equal(t, "user-1", got.CreatedBy)
	})

	t.Run("defaults: description empty, permissions empty, is_system false", func(t *testing.T) {
		got, err := projectors.RoleCreatedFromEvent(store.PersistedEvent{
			StreamType: "role", StreamID: "role-2", EventType: "RoleCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"name": "viewer"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
		assert.Equal(t, []string{}, got.Permissions, "missing permissions defaults to empty slice (matches PL/pgSQL '{}'::TEXT[])")
		assert.False(t, got.IsSystem)
	})

	t.Run("name is required", func(t *testing.T) {
		_, err := projectors.RoleCreatedFromEvent(store.PersistedEvent{
			StreamType: "role", StreamID: "role-3", EventType: "RoleCreated", ActorID: "u",
			Data: jsonOrFail(t, map[string]any{"description": "no name"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.RoleCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "RoleCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.RoleCreatedFromEvent(store.PersistedEvent{
			StreamType: "role", EventType: "RoleUpdated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.RoleCreatedFromEvent(store.PersistedEvent{
			StreamType: "role", EventType: "RoleCreated",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestRoleUpdatedFromEvent_Pure covers the partial-update decoder.
// PL/pgSQL semantics:
//   - name uses `COALESCE(NULLIF(payload, ""), existing)` — empty
//     string is "no update"; missing field is also "no update".
//   - description uses `COALESCE(payload, existing)` — empty string
//     IS an update; missing field is "no update".
//   - permissions uses array COALESCE — missing field is "no update";
//     empty array IS an update.
//
// Pointer fields distinguish "field present" from "field omitted".
func TestRoleUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("all fields present", func(t *testing.T) {
		got, err := projectors.RoleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "role", StreamID: "r-1", EventType: "RoleUpdated",
			Data: jsonOrFail(t, map[string]any{
				"name":        "admin-v2",
				"description": "updated desc",
				"permissions": []string{"perm.x"},
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Name)
		assert.Equal(t, "admin-v2", *got.Name)
		require.NotNil(t, got.Description)
		assert.Equal(t, "updated desc", *got.Description)
		require.NotNil(t, got.Permissions)
		assert.Equal(t, []string{"perm.x"}, *got.Permissions)
	})

	t.Run("only description present", func(t *testing.T) {
		got, err := projectors.RoleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "role", StreamID: "r-1", EventType: "RoleUpdated",
			Data: jsonOrFail(t, map[string]any{"description": "only desc changed"}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.Name, "missing name → omitted")
		require.NotNil(t, got.Description)
		assert.Equal(t, "only desc changed", *got.Description)
		assert.Nil(t, got.Permissions)
	})

	t.Run("explicit empty description IS an update (vs missing-field)", func(t *testing.T) {
		got, err := projectors.RoleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "role", StreamID: "r-1", EventType: "RoleUpdated",
			Data: jsonOrFail(t, map[string]any{"description": ""}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Description, "explicit \"\" must be a present-with-empty-value, NOT omitted")
		assert.Equal(t, "", *got.Description)
	})

	t.Run("explicit empty permissions IS an update", func(t *testing.T) {
		got, err := projectors.RoleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "role", StreamID: "r-1", EventType: "RoleUpdated",
			Data: jsonOrFail(t, map[string]any{"permissions": []string{}}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.Permissions)
		assert.Equal(t, []string{}, *got.Permissions, "explicit empty array clears permissions")
	})

	t.Run("name=\"\" → preserved-via-NULLIF (treated as missing)", func(t *testing.T) {
		// PL/pgSQL: `NULLIF(event.data->>'name', "")` collapses
		// empty-string to NULL, then COALESCE keeps existing.
		got, err := projectors.RoleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "role", StreamID: "r-1", EventType: "RoleUpdated",
			Data: jsonOrFail(t, map[string]any{"name": "", "description": "x"}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.Name, "empty-string name treated as missing per PL/pgSQL NULLIF semantics")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.RoleUpdatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "RoleUpdated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestRoleListener_CreateUpdateLifecycle drives Create → Update
// through the listener and asserts the projection ends in the right
// state. Confirms the partial-update semantics are wired correctly:
// only the fields present in the Update payload should change.
func TestRoleListener_CreateUpdateLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	roleID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data: map[string]any{
			"name":        "admin",
			"description": "initial",
			"permissions": []string{"a", "b"},
		},
		ActorType: "user", ActorID: "u-1",
	}))

	got, err := st.Queries().GetRoleByID(ctx, roleID)
	require.NoError(t, err)
	assert.Equal(t, "admin", got.Name)
	assert.Equal(t, "initial", got.Description)
	assert.Equal(t, []string{"a", "b"}, got.Permissions)
	assert.False(t, got.IsSystem)
	assert.Greater(t, got.ProjectionVersion, int64(0))

	// Partial update: only description.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleUpdated",
		Data:      map[string]any{"description": "updated"},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetRoleByID(ctx, roleID)
	require.NoError(t, err)
	assert.Equal(t, "admin", got.Name, "name preserved (omitted)")
	assert.Equal(t, "updated", got.Description, "description updated")
	assert.Equal(t, []string{"a", "b"}, got.Permissions, "permissions preserved (omitted)")

	// Update permissions to an explicit empty array (clear).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleUpdated",
		Data:      map[string]any{"permissions": []string{}},
		ActorType: "user", ActorID: "u-1",
	}))
	got, err = st.Queries().GetRoleByID(ctx, roleID)
	require.NoError(t, err)
	assert.Equal(t, []string{}, got.Permissions, "explicit empty permissions clears the column")
	assert.Equal(t, "updated", got.Description, "description preserved across this update")
}

// TestRoleListener_DeleteCascadesUserRoles confirms RoleDeleted
// flips is_deleted=TRUE AND removes every user_roles_projection
// entry for the role. Both writes happen inside store.WithTx so the
// projection never observes "role marked deleted but user-role
// memberships still exist".
func TestRoleListener_DeleteCascadesUserRoles(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	roleID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data:      map[string]any{"name": "tmp", "permissions": []string{"x"}},
		ActorType: "user", ActorID: "u-1",
	}))

	// Plant 2 user_roles_projection rows for this role via a direct
	// insert (bypassing the user_role projector since #102 hasn't
	// landed yet). The role projector only cares about cleanup, not
	// who put them there.
	_, err := st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, assigned_at, assigned_by) VALUES ($1,$2,NOW(),''),($3,$2,NOW(),'')",
		"user-A", roleID, "user-B",
	)
	require.NoError(t, err)

	// Verify pre-delete state.
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_roles_projection WHERE role_id = $1", roleID,
	).Scan(&count))
	require.Equal(t, 2, count)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u-1",
	}))

	// Role row marked deleted (won't show up via GetRoleByID which
	// filters is_deleted=FALSE — query directly).
	var isDeleted bool
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT is_deleted FROM roles_projection WHERE id = $1", roleID,
	).Scan(&isDeleted))
	assert.True(t, isDeleted, "RoleDeleted flips is_deleted=TRUE")

	// Cascade cleared the user-role memberships.
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_roles_projection WHERE role_id = $1", roleID,
	).Scan(&count))
	assert.Equal(t, 0, count, "user_roles_projection rows for the deleted role are removed")
}

// TestRoleListener_StaleReplayRejected confirms the projection_version
// guard on RoleUpdated rejects an UPDATE whose projection_version is
// older than the row's current value. Without the guard, a reconciler
// replay of an old event would overwrite a fresher state.
func TestRoleListener_StaleReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	roleID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data:      map[string]any{"name": "first"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleUpdated",
		Data:      map[string]any{"description": "current state"},
		ActorType: "user", ActorID: "u",
	}))
	current, err := st.Queries().GetRoleByID(ctx, roleID)
	require.NoError(t, err)
	currentVersion := current.ProjectionVersion

	// Apply an UPDATE directly with an older projection_version.
	desc := "stale replay would set this"
	older := currentVersion - 5
	updatedAt := current.CreatedAt
	require.NoError(t, st.Queries().UpdateRoleProjection(ctx, db.UpdateRoleProjectionParams{
		ID:                roleID,
		Description:       &desc,
		UpdatedAt:         &updatedAt,
		ProjectionVersion: older,
	}))

	after, err := st.Queries().GetRoleByID(ctx, roleID)
	require.NoError(t, err)
	assert.Equal(t, "current state", after.Description, "stale projection_version must NOT clobber fresher state")
	assert.Equal(t, currentVersion, after.ProjectionVersion)
}

// TestRoleListener_StaleDeleteReplayDoesNotNukeMemberships is a
// regression lock for a CR Major on PR #123: when the
// projection_version guard rejects a stale RoleDeleted UPDATE, the
// cascade DeleteUserRolesByRole MUST be skipped. Otherwise an old
// RoleDeleted re-applied later (e.g. by the reconciler against a
// freshly-restored or never-actually-deleted role) would silently
// nuke live memberships.
func TestRoleListener_StaleDeleteReplayDoesNotNukeMemberships(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	roleID := testutil.NewID()

	// Land a role + an UPDATE so projection_version > 0.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data:      map[string]any{"name": "live"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleUpdated",
		Data:      map[string]any{"description": "still alive"},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetRoleByID(ctx, roleID)
	require.NoError(t, err)

	// Plant 2 memberships.
	_, err = st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, assigned_at, assigned_by) VALUES ($1,$2,NOW(),''),($3,$2,NOW(),'')",
		"user-A", roleID, "user-B",
	)
	require.NoError(t, err)

	// Drive the REAL listener with a synthetic PersistedEvent whose
	// SequenceNum is older than the row's current projection_version.
	// Calling the public projector entrypoint exercises the
	// applyRoleDeleted bug-fix branch (rows-affected check skips the
	// cascade) — duplicating the SQL inline would have left the
	// branch untested even if it was deleted.
	older := live.ProjectionVersion - 5
	staleAt := live.CreatedAt
	listener := projectors.RoleListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: older,
		StreamType:  "role",
		StreamID:    roleID,
		EventType:   "RoleDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	// Memberships still there.
	count := 0
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_roles_projection WHERE role_id = $1", roleID,
	).Scan(&count))
	assert.Equal(t, 2, count, "stale RoleDeleted replay must NOT cascade-delete live memberships")

	// And the role row is still alive.
	stillAlive, err := st.Queries().GetRoleByID(ctx, roleID)
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted)
}

// TestRoleListener_IgnoresWrongStreamType — defensive.
func TestRoleListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	roleID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", // wrong
		StreamID:   roleID,
		EventType:  "RoleCreated",
		Data:       map[string]any{"name": "ghost"},
		ActorType:  "user", ActorID: "u",
	}))

	_, err := st.Queries().GetRoleByID(ctx, roleID)
	require.Error(t, err, "wrong-stream-type RoleCreated must NOT create a roles_projection row")
}
