package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

const (
	limitedLevel = pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED
	fullLevel    = pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL
)

// grantScopedTerminalAdmin grants `perm` to userID scoped to device
// group dgID (a device_group-scoped role grant). Returns the role id.
func grantScopedTerminalAdmin(t *testing.T, st *store.Store, actorID, userID, perm, dgID string) string {
	t.Helper()
	roleID := testutil.CreateTestRole(t, st, actorID, "scoped-"+perm+"-"+dgID, []string{perm})
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":" + dgID,
		EventType:  string(eventtypes.UserRoleAssigned),
		Data: map[string]any{
			"user_id": userID, "role_id": roleID,
			"scope_kind": "device_group", "scope_id": dgID,
		},
		ActorType: "user", ActorID: actorID,
	}))
	return roleID
}

func revokeScopedRole(t *testing.T, st *store.Store, actorID, userID, roleID, dgID string) {
	t.Helper()
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":" + dgID,
		EventType:  string(eventtypes.UserRoleRevoked),
		Data: map[string]any{
			"user_id": userID, "role_id": roleID,
			"scope_kind": "device_group", "scope_id": dgID,
		},
		ActorType: "user", ActorID: actorID,
	}))
}

func TestReconcileScoped_MaterializesPerScopeCohort(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantScopedTerminalAdmin(t, st, actorID, userID, "TerminalAdminFull", "dg-X")

	require.NoError(t, m.ReconcileScopedTerminalAdminActions(context.Background()))

	scoped := loadAdminPolicy(t, st, scopedTerminalAdminActionName(fullLevel, "dg-X"))
	assert.Equal(t, []string{"pm-tty-alice"}, scoped.Users,
		"a TerminalAdminFull:scope=dg-X holder must be in the per-scope FULL action")
	assert.Equal(t, fullLevel, scoped.AccessLevel)

	// The global FULL action must NOT contain the scoped holder.
	require.NoError(t, m.ReconcileGlobalTerminalAdminActions(context.Background()))
	assert.Empty(t, loadAdminPolicy(t, st, globalTerminalAdminFullActionName).Users,
		"a scoped grant must not leak into the global cohort")
}

// GAP-A: revoking Limited:dgX must not affect Full:dgY.
func TestReconcileScoped_GAPA_RevokeLimitedKeepsFull(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	limitedRole := grantScopedTerminalAdmin(t, st, actorID, userID, "TerminalAdminLimited", "dg-X")
	grantScopedTerminalAdmin(t, st, actorID, userID, "TerminalAdminFull", "dg-Y")

	require.NoError(t, m.ReconcileScopedTerminalAdminActions(context.Background()))
	require.Equal(t, []string{"pm-tty-alice"}, loadAdminPolicy(t, st, scopedTerminalAdminActionName(limitedLevel, "dg-X")).Users)
	require.Equal(t, []string{"pm-tty-alice"}, loadAdminPolicy(t, st, scopedTerminalAdminActionName(fullLevel, "dg-Y")).Users)

	// Revoke ONLY the Limited:dg-X grant.
	revokeScopedRole(t, st, actorID, userID, limitedRole, "dg-X")
	require.NoError(t, m.ReconcileScopedTerminalAdminActions(context.Background()))

	assert.Empty(t, loadAdminPolicy(t, st, scopedTerminalAdminActionName(limitedLevel, "dg-X")).Users,
		"revoked Limited:dg-X cohort must be emptied")
	assert.Equal(t, []string{"pm-tty-alice"}, loadAdminPolicy(t, st, scopedTerminalAdminActionName(fullLevel, "dg-Y")).Users,
		"Full:dg-Y must be untouched by the Limited:dg-X revoke (GAP-A)")
}

// When a scope loses its last holder, the action row persists with an
// empty users[] (inert) rather than being deleted.
func TestReconcileScoped_EmptyScopeCleanup(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	roleID := grantScopedTerminalAdmin(t, st, actorID, userID, "TerminalAdminLimited", "dg-X")
	require.NoError(t, m.ReconcileScopedTerminalAdminActions(context.Background()))

	name := scopedTerminalAdminActionName(limitedLevel, "dg-X")
	require.NotEmpty(t, loadAdminPolicy(t, st, name).Users)

	revokeScopedRole(t, st, actorID, userID, roleID, "dg-X")
	require.NoError(t, m.ReconcileScopedTerminalAdminActions(context.Background()))

	// Row still exists (GetActionByName succeeds in loadAdminPolicy) with empty users.
	assert.Empty(t, loadAdminPolicy(t, st, name).Users,
		"emptied scope keeps the action row with no members")
}

// A user_group-scoped TerminalAdmin grant has no device meaning and must
// materialize no per-scope action.
func TestReconcileScoped_IgnoresUserGroupScope(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	roleID := testutil.CreateTestRole(t, st, actorID, "ug-scoped", []string{"TerminalAdminLimited"})
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":ug-1",
		EventType:  string(eventtypes.UserRoleAssigned),
		Data: map[string]any{
			"user_id": userID, "role_id": roleID,
			"scope_kind": "user_group", "scope_id": "ug-1",
		},
		ActorType: "user", ActorID: actorID,
	}))

	require.NoError(t, m.ReconcileScopedTerminalAdminActions(context.Background()))

	names, err := st.Queries().ListScopedTerminalAdminActionNames(context.Background())
	require.NoError(t, err)
	assert.Empty(t, names, "a user_group-scoped TerminalAdmin grant must create no per-scope action")
}

func TestReconcileScoped_Idempotent_NoReSign(t *testing.T) {
	m, st := newManagerForTest(t)
	require.NoError(t, m.BootstrapGlobalTerminalAdminActions(context.Background()))

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@t.com", "pass", "viewer")
	setLinuxUsername(t, st, userID, "alice")
	grantScopedTerminalAdmin(t, st, actorID, userID, "TerminalAdminLimited", "dg-X")
	require.NoError(t, m.ReconcileScopedTerminalAdminActions(context.Background()))

	name := scopedTerminalAdminActionName(limitedLevel, "dg-X")
	before, err := st.Queries().GetActionByName(context.Background(), name)
	require.NoError(t, err)

	require.NoError(t, m.ReconcileScopedTerminalAdminActions(context.Background()))
	after, err := st.Queries().GetActionByName(context.Background(), name)
	require.NoError(t, err)

	assert.Equal(t, before.Signature, after.Signature,
		"a steady scoped cohort must not re-sign on a no-op reconcile tick")
}
