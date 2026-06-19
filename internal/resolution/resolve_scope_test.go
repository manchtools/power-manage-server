package resolution_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/resolution"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func containsAction(actions []db.ListResolvedActionsForDeviceRow, id string) bool {
	for _, a := range actions {
		if a.ID == id {
			return true
		}
	}
	return false
}

// assignScopedStartTerminal grants a StartTerminal role to userID scoped
// to device group dgID (a device_group-scoped grant).
func assignScopedStartTerminal(t *testing.T, st *store.Store, adminID, userID, dgID string) {
	t.Helper()
	roleID := testutil.CreateTestRole(t, st, adminID, "tty-scoped-"+dgID, []string{"StartTerminal"})
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "user_role",
		StreamID:   userID + ":" + roleID + ":" + dgID,
		EventType:  "UserRoleAssigned",
		Data: map[string]any{
			"user_id": userID, "role_id": roleID,
			"scope_kind": "device_group", "scope_id": dgID,
		},
		ActorType: "user", ActorID: adminID,
	}))
}

// A StartTerminal:scope=dgX holder's pm-tty account is delivered ONLY to
// devices in dgX; a device outside the scope does not receive it.
func TestResolveActions_TTYScopeAware(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	operatorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	dgX := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant X")
	assignScopedStartTerminal(t, st, adminID, operatorID, dgX)

	ttyActionID := testutil.CreateTestAction(t, st, adminID, "system:tty-user:"+operatorID, int(pm.ActionType_ACTION_TYPE_USER))
	linkSystemTtyAction(t, st, operatorID, ttyActionID)

	devIn := testutil.CreateTestDevice(t, st, "in-scope")
	devOut := testutil.CreateTestDevice(t, st, "out-scope")
	testutil.AddDeviceToTestGroup(t, st, adminID, dgX, devIn)

	inActions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), devIn)
	require.NoError(t, err)
	assert.True(t, containsAction(inActions, ttyActionID), "in-scope device must receive the pm-tty account")

	outActions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), devOut)
	require.NoError(t, err)
	assert.False(t, containsAction(outActions, ttyActionID), "out-of-scope device must NOT receive the pm-tty account")
}

// A global StartTerminal holder's account still reaches every device.
func TestResolveActions_TTYGlobalUnaffected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	operatorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	roleID := testutil.CreateTestRole(t, st, adminID, "tty-global", []string{"StartTerminal"})
	testutil.AssignRoleToTestUser(t, st, adminID, operatorID, roleID)

	ttyActionID := testutil.CreateTestAction(t, st, adminID, "system:tty-user:"+operatorID, int(pm.ActionType_ACTION_TYPE_USER))
	linkSystemTtyAction(t, st, operatorID, ttyActionID)

	devAnywhere := testutil.CreateTestDevice(t, st, "anywhere")
	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), devAnywhere)
	require.NoError(t, err)
	assert.True(t, containsAction(actions, ttyActionID), "a global StartTerminal holder's account reaches any device")
}

// A per-scope TerminalAdmin sudo action is delivered ONLY to devices in
// its scope group; the global ones reach every device.
func TestResolveActions_TerminalAdminScopeAware(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	dgX := testutil.CreateTestDeviceGroup(t, st, adminID, "Plant X")
	scopedActionID := testutil.CreateTestAction(t, st, adminID, "system:terminal-admin-limited:"+dgX, int(pm.ActionType_ACTION_TYPE_ADMIN_POLICY))
	globalActionID := testutil.CreateTestAction(t, st, adminID, "system:terminal-admin-limited:global", int(pm.ActionType_ACTION_TYPE_ADMIN_POLICY))

	devIn := testutil.CreateTestDevice(t, st, "in-scope")
	devOut := testutil.CreateTestDevice(t, st, "out-scope")
	testutil.AddDeviceToTestGroup(t, st, adminID, dgX, devIn)

	inActions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), devIn)
	require.NoError(t, err)
	assert.True(t, containsAction(inActions, scopedActionID), "in-scope device gets the per-scope sudo action")
	assert.True(t, containsAction(inActions, globalActionID), "global sudo action reaches every device")

	outActions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), devOut)
	require.NoError(t, err)
	assert.False(t, containsAction(outActions, scopedActionID), "out-of-scope device must NOT get the per-scope sudo action")
	assert.True(t, containsAction(outActions, globalActionID), "global sudo action still reaches the out-of-scope device")
}
