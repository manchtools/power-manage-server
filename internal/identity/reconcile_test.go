package identity_test

// The boot-time role reconciler is a background writer, so it lives
// under the same audit contract as an RPC. It is exercised here rather
// than in its own package because proving it needs a real database:
// the point of the reconciler is what the system roles look like
// afterwards.

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
)

func TestReconcileSystemRoles_RefreshesTheSeededRolesFromTheRegistry(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Simulate a deployment whose seeded permission arrays predate a
	// permission added in code.
	_, err := f.raw.Exec(f.ctx(),
		`UPDATE roles SET permissions = '{ListUsers}' WHERE id = ANY($1)`,
		[]string{auth.AdminRoleID, auth.UserRoleID})
	require.NoError(t, err)

	require.NoError(t, auth.ReconcileSystemRoles(f.ctx(), f.store, *f.clock, logger))

	admin, err := f.store.GetRole(f.ctx(), auth.AdminRoleID)
	require.NoError(t, err)
	assert.ElementsMatch(t, auth.AdminPermissions(), admin.Permissions,
		"the admin role is the whole registry after a boot")

	user, err := f.store.GetRole(f.ctx(), auth.UserRoleID)
	require.NoError(t, err)
	assert.ElementsMatch(t, auth.DefaultUserPermissions(), user.Permissions)

	op := f.onlyOperationFor("auth.ReconcileSystemRoles")
	assert.Equal(t, "BACKGROUND_WRITER", op.Class,
		"a non-RPC writer records under its own class, not as a request")
	assert.Equal(t, "system", op.ActorType)
	assert.Empty(t, op.ActorID, "nobody asked for this; it is the process starting")
	assert.Equal(t, "NOT_APPLICABLE", op.AuthorizationOutcome)

	effects := f.effectsOf(op.OperationID)
	require.Len(t, effects, 2, "one effect per system role, both in the one transaction")
	for _, e := range effects {
		assert.Equal(t, "role", e.ResourceType)
		assert.Equal(t, "RECONCILE_PERMISSIONS", e.Action)
		require.NotNil(t, e.BeforeCount)
		require.NotNil(t, e.AfterCount)
		assert.Equal(t, int64(1), *e.BeforeCount, "the deployment held the stale single-permission array")
		assert.Greater(t, *e.AfterCount, *e.BeforeCount)
	}
}

// A role edited through the RPC surface is NOT a system role and the
// reconciler leaves it alone.
func TestReconcileSystemRoles_LeavesOrdinaryRolesAlone(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ordinary := f.insertRole([]string{"ListUsers"})
	require.NoError(t, auth.ReconcileSystemRoles(f.ctx(), f.store, *f.clock, logger))

	role, err := f.store.GetRole(f.ctx(), ordinary)
	require.NoError(t, err)
	assert.Equal(t, []string{"ListUsers"}, role.Permissions)
}
