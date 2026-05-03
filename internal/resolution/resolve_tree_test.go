package resolution_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/resolution"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Helper: round-trip-friendly seed schedule. Stored as JSONB on the
// projection row when the projector inserts; we don't depend on the
// shape here beyond it being non-empty.
const treeTestScheduleJSON = `{"interval_hours": 2}`

// Verifies the new tree resolver classifies a directly-assigned action
// as standalone, with action-layer mode applied.
func TestResolveDeviceTree_StandaloneAction(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Solo Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "tree-solo")

	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, 0)

	tree, err := resolution.ResolveDeviceTree(context.Background(), st.Queries(), deviceID)
	require.NoError(t, err)

	assert.Empty(t, tree.Groups, "no container reaches device, no groups expected")
	require.Len(t, tree.StandaloneActions, 1)
	assert.Equal(t, actionID, tree.StandaloneActions[0].ActionID)
	assert.EqualValues(t, resolution.ModeRequired, tree.StandaloneActions[0].Mode)
}

// Set assignments at the device layer become a single ActionGroup, with
// the set's schedule and member actions in declared sort_order. The
// directly-assigned action that's also a member of the set is absorbed
// by the set and disappears from the standalone layer.
func TestResolveDeviceTree_AbsorbedByActionSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "tree-set")

	a1 := testutil.CreateTestAction(t, st, adminID, "A1", int(pm.ActionType_ACTION_TYPE_SHELL))
	a2 := testutil.CreateTestAction(t, st, adminID, "A2", int(pm.ActionType_ACTION_TYPE_SHELL))
	setID := testutil.CreateTestActionSet(t, st, adminID, "Web Stack")

	testutil.AddActionToTestSet(t, st, adminID, setID, a1, 0)
	testutil.AddActionToTestSet(t, st, adminID, setID, a2, 1)

	// Direct assignment of a1 is shadowed by the set assignment.
	testutil.CreateTestAssignment(t, st, adminID, "action", a1, "device", deviceID, 0)
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device", deviceID, 0)

	tree, err := resolution.ResolveDeviceTree(context.Background(), st.Queries(), deviceID)
	require.NoError(t, err)

	assert.Empty(t, tree.StandaloneActions, "a1's direct assignment is absorbed by the set")
	require.Len(t, tree.Groups, 1)
	g := tree.Groups[0]
	assert.Equal(t, "action_set:"+setID, g.SourceLabel)
	assert.EqualValues(t, resolution.ModeRequired, g.Mode)
	assert.Equal(t, []string{a1, a2}, g.ActionIDs, "members emitted in sort_order")
	assert.NotEmpty(t, g.Schedule, "set schedule must be populated from default column value")
}

// A definition reaching the device absorbs both its member set and the
// direct assignment of an action that's a member of that set. The group
// label points at the definition.
func TestResolveDeviceTree_AbsorbedByDefinition(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "tree-def")

	a1 := testutil.CreateTestAction(t, st, adminID, "A1", int(pm.ActionType_ACTION_TYPE_SHELL))
	setID := testutil.CreateTestActionSet(t, st, adminID, "Inner Set")
	defID := testutil.CreateTestDefinition(t, st, adminID, "Outer Definition")

	testutil.AddActionToTestSet(t, st, adminID, setID, a1, 0)
	testutil.AddActionSetToTestDefinition(t, st, adminID, defID, setID, 0)

	testutil.CreateTestAssignment(t, st, adminID, "action", a1, "device", deviceID, 0)
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device", deviceID, 0)
	testutil.CreateTestAssignment(t, st, adminID, "definition", defID, "device", deviceID, 0)

	tree, err := resolution.ResolveDeviceTree(context.Background(), st.Queries(), deviceID)
	require.NoError(t, err)

	assert.Empty(t, tree.StandaloneActions, "a1 absorbed by definition")
	require.Len(t, tree.Groups, 1, "set and definition collapse to a single group at the def layer")
	g := tree.Groups[0]
	assert.Equal(t, "definition:"+defID, g.SourceLabel)
	assert.Equal(t, []string{a1}, g.ActionIDs)
}

// UNINSTALL at the container layer surfaces as group Mode = ModeUninstall;
// the wrapping handler is responsible for forcing desired_state to ABSENT.
// EXCLUDED at the container layer drops the group (and its actions) entirely.
func TestResolveDeviceTree_ContainerModeOverride(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "tree-mode")

	uninstallAction := testutil.CreateTestAction(t, st, adminID, "Uninstall", int(pm.ActionType_ACTION_TYPE_SHELL))
	excludedAction := testutil.CreateTestAction(t, st, adminID, "Excluded", int(pm.ActionType_ACTION_TYPE_SHELL))

	uninstallSet := testutil.CreateTestActionSet(t, st, adminID, "Uninstall Set")
	excludedSet := testutil.CreateTestActionSet(t, st, adminID, "Excluded Set")

	testutil.AddActionToTestSet(t, st, adminID, uninstallSet, uninstallAction, 0)
	testutil.AddActionToTestSet(t, st, adminID, excludedSet, excludedAction, 0)

	// ASSIGNMENT_MODE_UNINSTALL = 3, ASSIGNMENT_MODE_EXCLUDED = 2.
	testutil.CreateTestAssignment(t, st, adminID, "action_set", uninstallSet, "device", deviceID, 3)
	testutil.CreateTestAssignment(t, st, adminID, "action_set", excludedSet, "device", deviceID, 2)

	tree, err := resolution.ResolveDeviceTree(context.Background(), st.Queries(), deviceID)
	require.NoError(t, err)

	require.Len(t, tree.Groups, 1, "excluded set is dropped, uninstall set survives")
	g := tree.Groups[0]
	assert.Equal(t, "action_set:"+uninstallSet, g.SourceLabel)
	assert.EqualValues(t, resolution.ModeUninstall, g.Mode)
	assert.Equal(t, []string{uninstallAction}, g.ActionIDs)
}
