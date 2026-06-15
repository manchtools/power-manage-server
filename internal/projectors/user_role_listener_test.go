package projectors_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// WS16 #7: applyUserRoleRevoked deletes the grant row with no projection_version
// guard (unlike sibling delete listeners e.g. DeleteDeviceAssignedUser). A
// UserRoleRevoked replayed out of order after a re-grant would wipe the newer
// grant. These pin the asymmetric-guard fix.

// seedUserRoleGrant inserts a user_roles_projection row directly at a chosen
// projection_version so the stale-replay scenarios are fully controlled.
func seedUserRoleGrant(t *testing.T, st *store.Store, ctx context.Context, userID, roleID string, version int64) {
	t.Helper()
	require.NoError(t, st.Queries().InsertUserRoleProjection(ctx, db.InsertUserRoleProjectionParams{
		UserID:            userID,
		RoleID:            roleID,
		AssignedAt:        time.Unix(0, 0).UTC(),
		AssignedBy:        "seed",
		ProjectionVersion: version,
	}))
}

func TestApplyUserRoleRevoked_StaleReplayDoesNotDeleteNewerGrant(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	revoke := func(userID, roleID string, seq int64) {
		projectors.UserRoleListener(st, logger)(ctx, store.PersistedEvent{
			StreamType:  "user_role",
			EventType:   "UserRoleRevoked",
			SequenceNum: seq,
			Data:        jsonOrFail(t, map[string]any{"user_id": userID, "role_id": roleID}),
		})
	}

	t.Run("stale revoke (seq < grant version) must NOT delete", func(t *testing.T) {
		userID := testutil.NewID()
		roleID := testutil.NewID()
		seedUserRoleGrant(t, st, ctx, userID, roleID, 100)

		revoke(userID, roleID, 50) // replayed out of order, older than the grant

		has, err := st.Queries().UserHasRole(ctx, dbUserHasRoleParams(userID, roleID))
		require.NoError(t, err)
		assert.True(t, has, "a stale UserRoleRevoked (seq 50 < grant version 100) must not wipe the newer grant")
	})

	t.Run("current revoke (seq >= grant version) deletes", func(t *testing.T) {
		userID := testutil.NewID()
		roleID := testutil.NewID()
		seedUserRoleGrant(t, st, ctx, userID, roleID, 100)

		revoke(userID, roleID, 100)

		has, err := st.Queries().UserHasRole(ctx, dbUserHasRoleParams(userID, roleID))
		require.NoError(t, err)
		assert.False(t, has, "a current UserRoleRevoked (seq 100 >= grant version 100) must delete the grant")
	})
}

// TestUserRoleDelete_HasProjectionVersionGuard is a self-discovering guard: it
// reads the DeleteUserRoleProjection query source and fails if the stale-replay
// predicate is ever dropped (e.g. by a regen or edit). Guards against matching
// zero query blocks.
func TestUserRoleDelete_HasProjectionVersionGuard(t *testing.T) {
	src, err := os.ReadFile("../store/queries/roles.sql")
	require.NoError(t, err)

	const marker = "-- name: DeleteUserRoleProjection "
	idx := strings.Index(string(src), marker)
	require.NotEqual(t, -1, idx, "DeleteUserRoleProjection query not found — self-discovering guard matched zero")

	// The query body runs from the marker to the next named query block.
	rest := string(src)[idx+len(marker):]
	if next := strings.Index(rest, "\n-- name:"); next != -1 {
		rest = rest[:next]
	}
	assert.Contains(t, rest, "projection_version",
		"DeleteUserRoleProjection must carry a projection_version stale-replay guard (WS16 #7)")
}
