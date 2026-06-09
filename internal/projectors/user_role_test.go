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
	require.NoError(t, st.TestingPool().QueryRow(ctx,
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

// =============================================================================
// server #7 S2 — scope decoding + projector wiring (T-S3 / T-S4).
//
// Tests pin the (scope_kind, scope_id) contract end-to-end:
//   - both nil  → unscoped grant (backward-compat with pre-#7 events)
//   - both set → scoped grant; values round-trip verbatim into the
//                projection (T-S3 no-remapping invariant)
//   - half-set → projector rejects at decode (T-S4 defense in depth
//                on top of the DB CHECK)
//   - unknown scope_kind → projector rejects
//   - multiple scoped grants of (user, role) at different scopes
//     coexist in the projection (the partial unique index allows it)
// =============================================================================

func TestUserRoleAssignedFromEvent_AcceptsScopedPayload(t *testing.T) {
	got, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
		StreamType: "user_role",
		EventType:  "UserRoleAssigned",
		ActorID:    "actor-1",
		Data: jsonOrFail(t, map[string]any{
			"user_id":    "u",
			"role_id":    "r",
			"scope_kind": "device_group",
			"scope_id":   "g1",
		}),
	})
	require.NoError(t, err)
	require.NotNil(t, got.ScopeKind)
	require.NotNil(t, got.ScopeID)
	assert.Equal(t, "device_group", *got.ScopeKind)
	assert.Equal(t, "g1", *got.ScopeID)
}

func TestUserRoleAssignedFromEvent_RejectsScopeKindWithoutScopeID(t *testing.T) {
	_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
		StreamType: "user_role", EventType: "UserRoleAssigned",
		Data: jsonOrFail(t, map[string]any{
			"user_id":    "u",
			"role_id":    "r",
			"scope_kind": "device_group",
		}),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope_id")
}

func TestUserRoleAssignedFromEvent_RejectsScopeIDWithoutScopeKind(t *testing.T) {
	_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
		StreamType: "user_role", EventType: "UserRoleAssigned",
		Data: jsonOrFail(t, map[string]any{
			"user_id":  "u",
			"role_id":  "r",
			"scope_id": "g1",
		}),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope_kind")
}

func TestUserRoleAssignedFromEvent_RejectsEmptyScopeStrings(t *testing.T) {
	t.Run("empty scope_kind", func(t *testing.T) {
		_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "user_role", EventType: "UserRoleAssigned",
			Data: jsonOrFail(t, map[string]any{
				"user_id":    "u",
				"role_id":    "r",
				"scope_kind": "",
				"scope_id":   "g1",
			}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope_kind")
	})
	t.Run("empty scope_id", func(t *testing.T) {
		_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
			StreamType: "user_role", EventType: "UserRoleAssigned",
			Data: jsonOrFail(t, map[string]any{
				"user_id":    "u",
				"role_id":    "r",
				"scope_kind": "device_group",
				"scope_id":   "",
			}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope_id")
	})
}

func TestUserRoleAssignedFromEvent_RejectsUnknownScopeKind(t *testing.T) {
	_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
		StreamType: "user_role", EventType: "UserRoleAssigned",
		Data: jsonOrFail(t, map[string]any{
			"user_id":    "u",
			"role_id":    "r",
			"scope_kind": "garbage_kind",
			"scope_id":   "g1",
		}),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scope_kind")
}

// TestUserRoleAssignedFromEvent_LegacyEventDecodesAsUnscoped pins
// the backward-compat contract: an event JSON without scope keys
// decodes to nil pointers (an unscoped grant).
func TestUserRoleAssignedFromEvent_LegacyEventDecodesAsUnscoped(t *testing.T) {
	got, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
		StreamType: "user_role",
		EventType:  "UserRoleAssigned",
		Data:       jsonOrFail(t, map[string]any{"user_id": "u", "role_id": "r"}),
	})
	require.NoError(t, err)
	assert.Nil(t, got.ScopeKind)
	assert.Nil(t, got.ScopeID)
}

// TestUserRoleListener_WritesScopeFields drives the full pipeline:
// an UserRoleAssigned event with scope fields lands in the
// projection with EXACTLY the emitted scope_kind + scope_id. T-S3
// no-remapping invariant.
func TestUserRoleListener_WritesScopeFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	roleID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	scopeID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data:      map[string]any{"name": "tmp", "permissions": []string{"x"}},
		ActorType: "user", ActorID: "u",
	}))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":" + scopeID,
		EventType:  "UserRoleAssigned",
		Data: map[string]any{
			"user_id":    userID,
			"role_id":    roleID,
			"scope_kind": "device_group",
			"scope_id":   scopeID,
		},
		ActorType: "user", ActorID: "u",
	}))

	var (
		gotKind *string
		gotID   *string
	)
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT scope_kind, scope_id FROM user_roles_projection WHERE user_id=$1 AND role_id=$2 AND scope_id=$3",
		userID, roleID, scopeID,
	).Scan(&gotKind, &gotID))
	require.NotNil(t, gotKind)
	require.NotNil(t, gotID)
	assert.Equal(t, "device_group", *gotKind, "T-S3: projector must write exactly the event's scope_kind, no remapping")
	assert.Equal(t, scopeID, *gotID, "T-S3: projector must write exactly the event's scope_id")
}

// TestUserRoleListener_UnscopedAndScopedGrantsCoexist proves that
// the new partial-unique-index scheme lets ONE unscoped grant +
// MULTIPLE scoped grants of the same (user, role) coexist in the
// projection. The previous PK (user_id, role_id) would have made
// this impossible.
func TestUserRoleListener_UnscopedAndScopedGrantsCoexist(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	roleID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	scopeAID := testutil.NewID()
	scopeBID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data:      map[string]any{"name": "tmp", "permissions": []string{"x"}},
		ActorType: "user", ActorID: "u",
	}))

	// Unscoped grant.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":global",
		EventType:  "UserRoleAssigned",
		Data: map[string]any{
			"user_id": userID,
			"role_id": roleID,
		},
		ActorType: "user", ActorID: "u",
	}))
	// Scoped grant A.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":" + scopeAID,
		EventType:  "UserRoleAssigned",
		Data: map[string]any{
			"user_id":    userID,
			"role_id":    roleID,
			"scope_kind": "device_group",
			"scope_id":   scopeAID,
		},
		ActorType: "user", ActorID: "u",
	}))
	// Scoped grant B.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":" + scopeBID,
		EventType:  "UserRoleAssigned",
		Data: map[string]any{
			"user_id":    userID,
			"role_id":    roleID,
			"scope_kind": "device_group",
			"scope_id":   scopeBID,
		},
		ActorType: "user", ActorID: "u",
	}))

	var count int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_roles_projection WHERE user_id=$1 AND role_id=$2",
		userID, roleID,
	).Scan(&count))
	assert.Equal(t, 3, count, "one unscoped + two scoped grants must all coexist (partial unique indexes)")
}

// TestUserRoleListener_RevokeScoped_LeavesOtherScopesIntact pins
// the 4-tuple revoke grammar (server #7 S5): revoking ONE scoped
// grant leaves the other scoped grants and the unscoped grant
// intact.
func TestUserRoleListener_RevokeScoped_LeavesOtherScopesIntact(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	roleID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	scopeA := testutil.NewID()
	scopeB := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data:      map[string]any{"name": "tmp", "permissions": []string{"x"}},
		ActorType: "user", ActorID: "u",
	}))
	for _, e := range []map[string]any{
		{"user_id": userID, "role_id": roleID},
		{"user_id": userID, "role_id": roleID, "scope_kind": "device_group", "scope_id": scopeA},
		{"user_id": userID, "role_id": roleID, "scope_kind": "device_group", "scope_id": scopeB},
	} {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user_role",
			StreamID:   userID + ":" + roleID + ":mixed",
			EventType:  "UserRoleAssigned",
			Data:       e,
			ActorType:  "user", ActorID: "u",
		}))
	}

	// Revoke ONLY scope A.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":mixed",
		EventType:  "UserRoleRevoked",
		Data: map[string]any{
			"user_id":    userID,
			"role_id":    roleID,
			"scope_kind": "device_group",
			"scope_id":   scopeA,
		},
		ActorType: "user", ActorID: "u",
	}))

	// scope A gone, unscoped + scope B intact.
	var remaining int
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT count(*) FROM user_roles_projection WHERE user_id=$1 AND role_id=$2",
		userID, roleID,
	).Scan(&remaining))
	assert.Equal(t, 2, remaining, "after revoking scope A, unscoped + scope B must remain")

	var scopeAStillThere bool
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM user_roles_projection WHERE user_id=$1 AND role_id=$2 AND scope_id=$3)",
		userID, roleID, scopeA,
	).Scan(&scopeAStillThere))
	assert.False(t, scopeAStillThere, "scope A grant must be gone")
}

// TestUserRoleListener_RevokeUnscoped_LeavesScopedIntact mirrors
// the previous test for the reverse direction: revoking the
// unscoped grant must not touch scoped grants. Tests the
// IS NOT DISTINCT FROM NULL targeting.
func TestUserRoleListener_RevokeUnscoped_LeavesScopedIntact(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	roleID := testutil.NewID()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	scopeA := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: roleID, EventType: "RoleCreated",
		Data:      map[string]any{"name": "tmp", "permissions": []string{"x"}},
		ActorType: "user", ActorID: "u",
	}))
	for _, e := range []map[string]any{
		{"user_id": userID, "role_id": roleID},
		{"user_id": userID, "role_id": roleID, "scope_kind": "device_group", "scope_id": scopeA},
	} {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "user_role",
			StreamID:   userID + ":" + roleID + ":mixed",
			EventType:  "UserRoleAssigned",
			Data:       e,
			ActorType:  "user", ActorID: "u",
		}))
	}

	// Revoke ONLY the unscoped grant (no scope fields).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":mixed",
		EventType:  "UserRoleRevoked",
		Data: map[string]any{
			"user_id": userID,
			"role_id": roleID,
		},
		ActorType: "user", ActorID: "u",
	}))

	// scope A intact, unscoped gone.
	var unscopedStillThere bool
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM user_roles_projection WHERE user_id=$1 AND role_id=$2 AND scope_id IS NULL)",
		userID, roleID,
	).Scan(&unscopedStillThere))
	assert.False(t, unscopedStillThere, "unscoped grant must be gone after the unscoped revoke")

	var scopedStillThere bool
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM user_roles_projection WHERE user_id=$1 AND role_id=$2 AND scope_id=$3)",
		userID, roleID, scopeA,
	).Scan(&scopedStillThere))
	assert.True(t, scopedStillThere, "scoped grant must remain — unscoped revoke targets scope_id IS NULL specifically")
}

// =============================================================================
// Schema-level CHECK constraints (migration 010).
//
// These tests hit the projection directly with raw SQL so the DB
// constraint behaviour is pinned independent of the projector. T-S4
// defense in depth: even if a future projector regression let
// half-scoped data through, the DB CHECK still rejects.
// =============================================================================

func TestSchema_ScopeCheckConstraint_BothNull_Accepted(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	roleID := plantTestRole(t, st, ctx)

	_, err := st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, assigned_at, assigned_by, projection_version, scope_kind, scope_id) VALUES ($1, $2, NOW(), 'u', 0, NULL, NULL)",
		userID, roleID,
	)
	require.NoError(t, err, "both-NULL must satisfy the paired-or-neither CHECK")
}

func TestSchema_ScopeCheckConstraint_BothSet_Accepted(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	roleID := plantTestRole(t, st, ctx)

	_, err := st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, assigned_at, assigned_by, projection_version, scope_kind, scope_id) VALUES ($1, $2, NOW(), 'u', 0, 'device_group', $3)",
		userID, roleID, testutil.NewID(),
	)
	require.NoError(t, err, "both-set with a valid kind must satisfy both CHECKs")
}

func TestSchema_ScopeCheckConstraint_OnlyKind_Rejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	roleID := plantTestRole(t, st, ctx)

	_, err := st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, assigned_at, assigned_by, projection_version, scope_kind, scope_id) VALUES ($1, $2, NOW(), 'u', 0, 'device_group', NULL)",
		userID, roleID,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user_roles_scope_pair_or_neither")
}

func TestSchema_ScopeCheckConstraint_OnlyID_Rejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	roleID := plantTestRole(t, st, ctx)

	_, err := st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, assigned_at, assigned_by, projection_version, scope_kind, scope_id) VALUES ($1, $2, NOW(), 'u', 0, NULL, $3)",
		userID, roleID, testutil.NewID(),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user_roles_scope_pair_or_neither")
}

func TestSchema_ScopeKindValidConstraint_RejectsGarbage(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	roleID := plantTestRole(t, st, ctx)

	_, err := st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, assigned_at, assigned_by, projection_version, scope_kind, scope_id) VALUES ($1, $2, NOW(), 'u', 0, 'random_thing', $3)",
		userID, roleID, testutil.NewID(),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user_roles_scope_kind_valid")
}

// TestSchema_UnscopedUniqueIndex_OneRowOnly pins the partial unique
// index for unscoped grants: only ONE unscoped grant per
// (user, role) pair is allowed.
func TestSchema_UnscopedUniqueIndex_OneRowOnly(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	roleID := plantTestRole(t, st, ctx)

	_, err := st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, assigned_at, assigned_by, projection_version) VALUES ($1, $2, NOW(), 'u', 0)",
		userID, roleID,
	)
	require.NoError(t, err)
	_, err = st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, assigned_at, assigned_by, projection_version) VALUES ($1, $2, NOW(), 'u', 1)",
		userID, roleID,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user_roles_unscoped_unique",
		"the partial unique index must reject a second unscoped grant of (user, role)")
}

// TestSchema_ScopedUniqueIndex_OneRowPerScope pins the scoped
// partial unique index: at most ONE row per (user, role, scope-tuple).
func TestSchema_ScopedUniqueIndex_OneRowPerScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	roleID := plantTestRole(t, st, ctx)
	scopeID := testutil.NewID()

	_, err := st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, scope_kind, scope_id, assigned_at, assigned_by, projection_version) VALUES ($1, $2, 'device_group', $3, NOW(), 'u', 0)",
		userID, roleID, scopeID,
	)
	require.NoError(t, err)
	_, err = st.TestingPool().Exec(ctx,
		"INSERT INTO user_roles_projection (user_id, role_id, scope_kind, scope_id, assigned_at, assigned_by, projection_version) VALUES ($1, $2, 'device_group', $3, NOW(), 'u', 1)",
		userID, roleID, scopeID,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user_roles_scoped_unique",
		"the scoped partial unique index must reject a second grant of the same (user, role, scope) tuple")
}

// TestProjector_AcceptsExactlyKnownScopeKinds is the self-
// discovering coverage guard: any new lowercase string kind added
// to the DB CHECK constraint MUST also be accepted by the projector
// validator (and vice versa). The two lists are kept in sync here.
// A drift means a future kind value silently rejects at one layer
// or the other.
func TestProjector_AcceptsExactlyKnownScopeKinds(t *testing.T) {
	knownAccepted := []string{"device_group", "user_group"}
	knownRejected := []string{"", "unknown_kind", "device", "user", "Device_Group"}

	require.NotEmpty(t, knownAccepted, "matches-zero guard: accepted-set must not be empty")
	require.NotEmpty(t, knownRejected, "matches-zero guard: rejected-set must not be empty")

	for _, kind := range knownAccepted {
		t.Run("accept_"+kind, func(t *testing.T) {
			_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
				StreamType: "user_role", EventType: "UserRoleAssigned",
				Data: jsonOrFail(t, map[string]any{
					"user_id":    "u",
					"role_id":    "r",
					"scope_kind": kind,
					"scope_id":   "g1",
				}),
			})
			require.NoError(t, err, "kind %q must be accepted (drift vs DB CHECK)", kind)
		})
	}
	for _, kind := range knownRejected {
		t.Run("reject_"+kind, func(t *testing.T) {
			_, err := projectors.UserRoleAssignedFromEvent(store.PersistedEvent{
				StreamType: "user_role", EventType: "UserRoleAssigned",
				Data: jsonOrFail(t, map[string]any{
					"user_id":    "u",
					"role_id":    "r",
					"scope_kind": kind,
					"scope_id":   "g1",
				}),
			})
			require.Error(t, err, "kind %q must be rejected (drift vs DB CHECK)", kind)
		})
	}
}

// TestUserGroupRoleListener_WritesScopeFields — symmetric with the
// user_role version, covers the user-group → role projection.
func TestUserGroupRoleListener_WritesScopeFields(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	groupID := testutil.NewID()
	roleID := plantTestRole(t, st, ctx)
	scopeID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group", StreamID: groupID, EventType: "UserGroupCreated",
		Data:      map[string]any{"name": "ug-" + groupID, "description": "x"},
		ActorType: "user", ActorID: "u",
	}))

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   groupID,
		EventType:  "UserGroupRoleAssigned",
		Data: map[string]any{
			"group_id":   groupID,
			"role_id":    roleID,
			"scope_kind": "user_group",
			"scope_id":   scopeID,
		},
		ActorType: "user", ActorID: "u",
	}))

	var (
		gotKind *string
		gotID   *string
	)
	require.NoError(t, st.TestingPool().QueryRow(ctx,
		"SELECT scope_kind, scope_id FROM user_group_roles_projection WHERE group_id=$1 AND role_id=$2 AND scope_id=$3",
		groupID, roleID, scopeID,
	).Scan(&gotKind, &gotID))
	require.NotNil(t, gotKind)
	require.NotNil(t, gotID)
	assert.Equal(t, "user_group", *gotKind)
	assert.Equal(t, scopeID, *gotID)
}

func TestUserGroupRoleDecoder_RejectsPartialScope(t *testing.T) {
	_, err := projectors.UserGroupRoleAssignedFromEvent(store.PersistedEvent{
		StreamType: "user_group",
		EventType:  "UserGroupRoleAssigned",
		Data: jsonOrFail(t, map[string]any{
			"group_id":   "g",
			"role_id":    "r",
			"scope_kind": "device_group",
			// scope_id intentionally missing
		}),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope_id")
}

func plantTestRole(t *testing.T, st *store.Store, ctx context.Context) string {
	t.Helper()
	id := testutil.NewID()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "role", StreamID: id, EventType: "RoleCreated",
		Data:      map[string]any{"name": "tmp-" + id, "permissions": []string{"x"}},
		ActorType: "user", ActorID: "u",
	}))
	return id
}
