package projectors_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestUserRoleAssignedFromEvent_Pure exercises the decoder for
// UserRoleAssigned. The PL/pgSQL projector required user_id and
// role_id; the Go decoder mirrors that with explicit validation
// instead of silently writing rows with empty composite-key columns.
func TestUserRoleAssignedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "user_role",
			EventType:  "UserRoleAssigned",
			ActorID:    "actor-1",
			Data: jsonOrFail(t, map[string]any{
				"user_id": "user-A",
				"role_id": "role-X",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "user-A", got.UserID)
		assert.Equal(t, "role-X", got.RoleID)
		assert.Equal(t, "actor-1", got.AssignedBy)
	})

	t.Run("missing user_id", func(t *testing.T) {
		_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "user_role", EventType: "UserRoleAssigned",
			Data: jsonOrFail(t, map[string]any{"role_id": "r"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "user_id")
	})

	t.Run("missing role_id", func(t *testing.T) {
		_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "user_role", EventType: "UserRoleAssigned",
			Data: jsonOrFail(t, map[string]any{"user_id": "u"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "role_id")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "role", EventType: "UserRoleAssigned",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "user_role", EventType: "UserRoleRevoked",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "user_role", EventType: "UserRoleAssigned",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestUserRoleRevokedFromEvent_Pure mirrors the assigned suite for
// the revoke variant.
func TestUserRoleRevokedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.UserRoleRevokedFromEvent(store.PersistedEvent{
			StreamType: "user_role",
			EventType:  "UserRoleRevoked",
			Data: jsonOrFail(t, map[string]any{
				"user_id": "user-A",
				"role_id": "role-X",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "user-A", got.UserID)
		assert.Equal(t, "role-X", got.RoleID)
	})

	t.Run("missing user_id is a validation error", func(t *testing.T) {
		_, err := projectors.UserRoleRevokedFromEvent(store.PersistedEvent{
			StreamType: "user_role", EventType: "UserRoleRevoked",
			Data: jsonOrFail(t, map[string]any{"role_id": "r"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user_id")
	})

	t.Run("missing role_id is a validation error", func(t *testing.T) {
		_, err := projectors.UserRoleRevokedFromEvent(store.PersistedEvent{
			StreamType: "user_role", EventType: "UserRoleRevoked",
			Data: jsonOrFail(t, map[string]any{"user_id": "u"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role_id")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.UserRoleRevokedFromEvent(store.PersistedEvent{
			StreamType: "user_role", EventType: "UserRoleAssigned",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestUserRoleListener_AssignAndRevoke walks Assign → Revoke through
// the listener and asserts the projection ends with no row for the
// (user, role) pair.
func TestUserRoleListener_AssignAndRevoke(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	roleID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")

	// Plant a role row so the FK-less projection writes don't surprise us.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data:      map[string]any{"name": "tmp", "permissions": []string{"x"}},
		ActorType: "user", ActorID: "u",
	}))

	// Assign the role.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID,
		EventType:  "UserRoleAssigned",
		Data: map[string]any{
			"user_id": userID,
			"role_id": roleID,
		},
		ActorType: "user", ActorID: "u",
	}))

	hasRole, err := st.Queries().UserHasRole(ctx, dbUserHasRoleParams(userID, roleID))
	require.NoError(t, err)
	assert.True(t, hasRole, "UserRoleAssigned must create a user_roles_projection row")

	// Revoke it.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID,
		EventType:  "UserRoleRevoked",
		Data: map[string]any{
			"user_id": userID,
			"role_id": roleID,
		},
		ActorType: "user", ActorID: "u",
	}))

	hasRole, err = st.Queries().UserHasRole(ctx, dbUserHasRoleParams(userID, roleID))
	require.NoError(t, err)
	assert.False(t, hasRole, "UserRoleRevoked must remove the user_roles_projection row")
}

// TestUserRoleListener_AssignReplayIsIdempotent confirms that
// re-applying the same UserRoleAssigned event (e.g. via the
// reconciler) doesn't error or duplicate. The PL/pgSQL projector
// used `ON CONFLICT (user_id, role_id) DO NOTHING`; the Go listener
// must preserve that.
func TestUserRoleListener_AssignReplayIsIdempotent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	roleID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data:      map[string]any{"name": "tmp", "permissions": []string{"x"}},
		ActorType: "user", ActorID: "u",
	}))

	for i := 0; i < 3; i++ {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user_role",
			StreamID:   userID + ":" + roleID,
			EventType:  "UserRoleAssigned",
			Data: map[string]any{
				"user_id": userID,
				"role_id": roleID,
			},
			ActorType: "user", ActorID: "u",
		}), "replay %d", i)
	}

	// Confirm exactly one row.
	count := 0
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT count(*) FROM user_roles_projection WHERE user_id=$1 AND role_id=$2",
		userID, roleID,
	).Scan(&count))
	assert.Equal(t, 1, count, "ON CONFLICT DO NOTHING keeps assignment row unique despite replays")
}

// TestUserRoleListener_RevokeWhenAbsentIsNoop — defensive: a Revoke
// event with no matching row must not error. The PL/pgSQL projector
// used a plain DELETE which silently affects zero rows on a miss;
// the Go listener must preserve that.
func TestUserRoleListener_RevokeWhenAbsentIsNoop(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   "ghost:role",
		EventType:  "UserRoleRevoked",
		Data: map[string]any{
			"user_id": "ghost-user",
			"role_id": "ghost-role",
		},
		ActorType: "user", ActorID: "u",
	}))
	// No assertion needed — the test passes as long as AppendEvent
	// returns without error.
}

// TestUserRoleListener_IgnoresWrongStreamType — defensive.
func TestUserRoleListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	roleID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", // wrong
		StreamID:   userID + ":" + roleID,
		EventType:  "UserRoleAssigned",
		Data: map[string]any{
			"user_id": userID,
			"role_id": roleID,
		},
		ActorType: "user", ActorID: "u",
	}))

	hasRole, err := st.Queries().UserHasRole(ctx, dbUserHasRoleParams(userID, roleID))
	require.NoError(t, err)
	assert.False(t, hasRole, "wrong-stream-type UserRoleAssigned must NOT create a user_roles_projection row")
}

// dbUserHasRoleParams wraps the generated sqlc params struct so the
// test bodies stay readable without repeating field names.
func dbUserHasRoleParams(userID, roleID string) db.UserHasRoleParams {
	return db.UserHasRoleParams{UserID: userID, RoleID: roleID}
}
