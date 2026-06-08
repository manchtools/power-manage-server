package resolution_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/resolution"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

const uninstallAssignmentMode = int(pm.AssignmentMode_ASSIGNMENT_MODE_UNINSTALL)

func TestResolveActions_DeviceLayerOnly(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Dev Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-dev")

	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, 0)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Len(t, actions, 1)
	assert.Equal(t, actionID, actions[0].ID)
}

func TestResolveActions_UserLayerOnly(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ownerID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	actionID := testutil.CreateTestAction(t, st, adminID, "User Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-user")

	// Assign device to user
	testutil.AssignDeviceToUser(t, st, adminID, deviceID, ownerID)

	// Assign action to user
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "user", ownerID, 0)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Len(t, actions, 1)
	assert.Equal(t, actionID, actions[0].ID)
}

func TestResolveActions_UserGroupLayer(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ownerID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	actionID := testutil.CreateTestAction(t, st, adminID, "UG Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-ug")
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Resolve UG")

	// Assign device to user, add user to group
	testutil.AssignDeviceToUser(t, st, adminID, deviceID, ownerID)
	testutil.AddUserToTestGroup(t, st, adminID, groupID, ownerID)

	// Assign action to user group
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "user_group", groupID, 0)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Len(t, actions, 1)
	assert.Equal(t, actionID, actions[0].ID)
}

func TestResolveActions_DeviceExcludedBlocksUserRequired(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ownerID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	actionID := testutil.CreateTestAction(t, st, adminID, "Excluded Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-excl")

	testutil.AssignDeviceToUser(t, st, adminID, deviceID, ownerID)

	// EXCLUDED at device layer (mode=2)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, 2)
	// REQUIRED at user layer (mode=0)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "user", ownerID, 0)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Len(t, actions, 0, "device EXCLUDED should block user REQUIRED")
}

func TestResolveActions_UserExcludedDoesNotBlockDeviceRequired(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ownerID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	actionID := testutil.CreateTestAction(t, st, adminID, "UserExcl Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-uexcl")

	testutil.AssignDeviceToUser(t, st, adminID, deviceID, ownerID)

	// REQUIRED at device layer (mode=0)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, 0)
	// EXCLUDED at user layer (mode=2)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "user", ownerID, 2)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Len(t, actions, 1, "user EXCLUDED should NOT block device REQUIRED")
	assert.Equal(t, actionID, actions[0].ID)
}

func TestResolveActions_BothLayersSameAction_NoDuplicate(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ownerID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	actionID := testutil.CreateTestAction(t, st, adminID, "Both Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-both")

	testutil.AssignDeviceToUser(t, st, adminID, deviceID, ownerID)

	// REQUIRED at both layers
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, 0)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "user", ownerID, 0)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Len(t, actions, 1, "same action in both layers should not duplicate")
	assert.Equal(t, actionID, actions[0].ID)
}

func TestResolveActions_NoOwner_UserLayerEmpty(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "NoOwner Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-noown")

	// Only device-layer assignment, no owner assigned
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, 0)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Len(t, actions, 1)
}

func TestResolveActions_MergeDeviceAndUserActions(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ownerID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	deviceID := testutil.CreateTestDevice(t, st, "resolve-merge")

	testutil.AssignDeviceToUser(t, st, adminID, deviceID, ownerID)

	// Device-layer action
	actionDev := testutil.CreateTestAction(t, st, adminID, "Dev Merge", int(pm.ActionType_ACTION_TYPE_SHELL))
	testutil.CreateTestAssignment(t, st, adminID, "action", actionDev, "device", deviceID, 0)

	// User-layer action (different action)
	actionUser := testutil.CreateTestAction(t, st, adminID, "User Merge", int(pm.ActionType_ACTION_TYPE_SHELL))
	testutil.CreateTestAssignment(t, st, adminID, "action", actionUser, "user", ownerID, 0)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Len(t, actions, 2, "should merge device and user layer actions")

	ids := make(map[string]bool)
	for _, a := range actions {
		ids[a.ID] = true
	}
	assert.True(t, ids[actionDev])
	assert.True(t, ids[actionUser])
}

func TestResolveActions_DeviceUninstallForcesAbsent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Uninstall Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-uninstall")

	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, uninstallAssignmentMode)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, actionID, actions[0].ID)
	assert.Equal(t, int32(pm.DesiredState_DESIRED_STATE_ABSENT), actions[0].DesiredState)
}

func TestResolveActions_UserUninstallForcesAbsent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ownerID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	actionID := testutil.CreateTestAction(t, st, adminID, "User Uninstall Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-user-uninstall")

	testutil.AssignDeviceToUser(t, st, adminID, deviceID, ownerID)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "user", ownerID, uninstallAssignmentMode)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, actionID, actions[0].ID)
	assert.Equal(t, int32(pm.DesiredState_DESIRED_STATE_ABSENT), actions[0].DesiredState)
}

func TestResolveActions_ActionSetUninstallForcesAllMembersAbsent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "resolve-set-uninstall")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Uninstall Set")
	presentActionID := testutil.CreateTestActionWithDesiredState(t, st, adminID, "Present Member", int(pm.ActionType_ACTION_TYPE_SHELL), int(pm.DesiredState_DESIRED_STATE_PRESENT))
	absentActionID := testutil.CreateTestActionWithDesiredState(t, st, adminID, "Absent Member", int(pm.ActionType_ACTION_TYPE_SHELL), int(pm.DesiredState_DESIRED_STATE_ABSENT))

	testutil.AddActionToTestSet(t, st, adminID, setID, presentActionID, 0)
	testutil.AddActionToTestSet(t, st, adminID, setID, absentActionID, 1)
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device", deviceID, uninstallAssignmentMode)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 2)
	for _, action := range actions {
		assert.Equal(t, int32(pm.DesiredState_DESIRED_STATE_ABSENT), action.DesiredState)
	}
}

func TestResolveActions_DefinitionUninstallForcesAllMembersAbsent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "resolve-definition-uninstall")
	definitionID := testutil.CreateTestDefinition(t, st, adminID, "Uninstall Definition")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Definition Set")
	presentActionID := testutil.CreateTestActionWithDesiredState(t, st, adminID, "Definition Present Member", int(pm.ActionType_ACTION_TYPE_SHELL), int(pm.DesiredState_DESIRED_STATE_PRESENT))
	absentActionID := testutil.CreateTestActionWithDesiredState(t, st, adminID, "Definition Absent Member", int(pm.ActionType_ACTION_TYPE_SHELL), int(pm.DesiredState_DESIRED_STATE_ABSENT))

	testutil.AddActionToTestSet(t, st, adminID, setID, presentActionID, 0)
	testutil.AddActionToTestSet(t, st, adminID, setID, absentActionID, 1)
	testutil.AddActionSetToTestDefinition(t, st, adminID, definitionID, setID, 0)
	testutil.CreateTestAssignment(t, st, adminID, "definition", definitionID, "device", deviceID, uninstallAssignmentMode)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 2)
	for _, action := range actions {
		assert.Equal(t, int32(pm.DesiredState_DESIRED_STATE_ABSENT), action.DesiredState)
	}
}

func TestResolveActions_ExcludedBeatsUninstallAtSamePriority(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Excluded Beats Uninstall", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-excluded-beats-uninstall")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Uninstall Conflict Group")
	testutil.AddDeviceToTestGroup(t, st, adminID, groupID, deviceID)

	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, uninstallAssignmentMode)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device_group", groupID, int(pm.AssignmentMode_ASSIGNMENT_MODE_EXCLUDED))

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Len(t, actions, 0)
}

func TestResolveActions_UninstallBeatsRequiredAtSamePriority(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Uninstall Beats Required", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-uninstall-beats-required")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Required Conflict Group")
	testutil.AddDeviceToTestGroup(t, st, adminID, groupID, deviceID)

	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device_group", groupID, uninstallAssignmentMode)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, int32(pm.DesiredState_DESIRED_STATE_ABSENT), actions[0].DesiredState)
}

func TestResolveActions_HigherPriorityRequiredBeatsLowerPriorityUninstall(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestActionWithDesiredState(t, st, adminID, "Priority Winner", int(pm.ActionType_ACTION_TYPE_SHELL), int(pm.DesiredState_DESIRED_STATE_PRESENT))
	deviceID := testutil.CreateTestDevice(t, st, "resolve-priority-wins")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Lower Priority Set")
	definitionID := testutil.CreateTestDefinition(t, st, adminID, "Lower Priority Definition")

	testutil.AddActionToTestSet(t, st, adminID, setID, actionID, 0)
	testutil.AddActionSetToTestDefinition(t, st, adminID, definitionID, setID, 0)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, int(pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED))
	testutil.CreateTestAssignment(t, st, adminID, "definition", definitionID, "device", deviceID, uninstallAssignmentMode)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, actionID, actions[0].ID)
	assert.Equal(t, int32(pm.DesiredState_DESIRED_STATE_PRESENT), actions[0].DesiredState)
}

// Test that user assignment works via the handler (CreateAssignment + GetUserAssignments)
func TestCreateAssignment_UserTargetViaHandler(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, slog.Default(), nil)
	h := api.NewAssignmentHandler(st, slog.Default(), actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	actionID := testutil.CreateTestAction(t, st, adminID, "Handler Test", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateAssignment(ctx, connect.NewRequest(&pm.CreateAssignmentRequest{
		SourceType: pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId:   actionID,
		TargetType: pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER,
		TargetId:   userID,
		Mode:       pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED,
	}))
	require.NoError(t, err)

	resp, err := h.GetUserAssignments(ctx, connect.NewRequest(&pm.GetUserAssignmentsRequest{
		UserId: userID,
	}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Assignments, 1)
	assert.Equal(t, pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER, resp.Msg.Assignments[0].TargetType)
}

// linkSystemTtyAction stamps users_projection.system_tty_action_id by
// emitting the projector-recognised UserSystemActionLinked event. The
// resolver's permission-derived TTY query joins on this column.
//
// Mirrors production actor identity (ActorType "system", ActorID
// "system") used by SystemActionManager.linkSystemAction so the tests
// exercise the same audit/projection code path that ships.
func linkSystemTtyAction(t *testing.T, st *store.Store, userID, actionID string) {
	t.Helper()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserSystemActionLinked",
		Data: map[string]any{
			"field":     "system_tty_action_id",
			"action_id": actionID,
		},
		ActorType: "system",
		ActorID:   "system",
	})
	if err != nil {
		t.Fatalf("link tty action: %v", err)
	}
}

// TestResolveActions_TTYPermissionSource is the rc13 contract:
// when a user holds StartTerminal (directly or via group) and has
// system_tty_action_id linked, the resolver returns that TTY action
// for any device — including a freshly enrolled, unassigned device.
// Pre-fix this hung off ordinary user assignment, so bulk-enrolled
// devices never received the pm-tty-<username> account.
func TestResolveActions_TTYPermissionSource_DirectRole(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	// Operator user with StartTerminal via a directly-granted role.
	operatorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	roleID := testutil.CreateTestRole(t, st, adminID, "tty-operator", []string{"StartTerminal"})
	testutil.AssignRoleToTestUser(t, st, adminID, operatorID, roleID)

	// Operator's TTY action; no assignment to anything.
	ttyActionID := testutil.CreateTestAction(t, st, adminID, "system:tty-user:"+operatorID, int(pm.ActionType_ACTION_TYPE_USER))
	linkSystemTtyAction(t, st, operatorID, ttyActionID)

	// Brand-new, totally unassigned device — the bulk-enrollment shape.
	deviceID := testutil.CreateTestDevice(t, st, "bulk-enrolled")

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 1, "TTY action must reach unassigned devices for permission holders")
	assert.Equal(t, ttyActionID, actions[0].ID)
}

func TestResolveActions_TTYPermissionSource_ViaUserGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	operatorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	// Permission flows: user → group → role → permission.
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "tty-team")
	roleID := testutil.CreateTestRole(t, st, adminID, "tty-via-group", []string{"StartTerminal"})
	testutil.AddUserToTestGroup(t, st, adminID, groupID, operatorID)
	testutil.AssignRoleToTestGroup(t, st, adminID, groupID, roleID)

	ttyActionID := testutil.CreateTestAction(t, st, adminID, "system:tty-user:"+operatorID, int(pm.ActionType_ACTION_TYPE_USER))
	linkSystemTtyAction(t, st, operatorID, ttyActionID)

	deviceID := testutil.CreateTestDevice(t, st, "bulk-enrolled-2")

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, ttyActionID, actions[0].ID)
}

// Linked-but-unprivileged users must NOT have their TTY action shipped
// to devices — the system-action linkage alone is not authority. This
// is the cleanup-safety property that the user-deletion path relies on:
// revoking StartTerminal must drop the TTY account from the device's
// resolved action set on the next sync.
func TestResolveActions_TTYPermissionSource_NoPermissionExcluded(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	noPermID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	ttyActionID := testutil.CreateTestAction(t, st, adminID, "system:tty-user:"+noPermID, int(pm.ActionType_ACTION_TYPE_USER))
	linkSystemTtyAction(t, st, noPermID, ttyActionID)

	deviceID := testutil.CreateTestDevice(t, st, "no-perm-device")

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	assert.Empty(t, actions, "user without StartTerminal must not have TTY action shipped")
}

// TestResolveActions_TTYPermissionSource_BypassesDeviceExcluded locks
// in the rc13 contract: the permission-derived TTY layer is exempt
// from device-layer EXCLUDED. An operator who attaches an EXCLUDED
// assignment for a TTY action to a device must NOT be able to lock
// terminal access out — terminal access is the system's escape
// hatch, and cleanup of TTY accounts is driven by the user-deletion
// path, never by an operator's per-device exclusion. The contrast
// with TestResolveActions_DeviceExcludedBlocksUserRequired (which
// honors EXCLUDED for assignment-derived rows) is the point of this
// test: same exclusion event, different outcome by layer.
func TestResolveActions_TTYPermissionSource_BypassesDeviceExcluded(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	operatorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	roleID := testutil.CreateTestRole(t, st, adminID, "tty-bypass", []string{"StartTerminal"})
	testutil.AssignRoleToTestUser(t, st, adminID, operatorID, roleID)

	ttyActionID := testutil.CreateTestAction(t, st, adminID, "system:tty-user:"+operatorID, int(pm.ActionType_ACTION_TYPE_USER))
	linkSystemTtyAction(t, st, operatorID, ttyActionID)

	deviceID := testutil.CreateTestDevice(t, st, "exclusion-attempt-host")

	// Operator-style attempt to lock the TTY action out via a
	// device-layer EXCLUDED assignment (mode=2). The permission-
	// derived layer must ignore it.
	testutil.CreateTestAssignment(t, st, adminID, "action", ttyActionID, "device", deviceID, 2)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 1, "device-layer EXCLUDED must NOT block permission-derived TTY actions")
	assert.Equal(t, ttyActionID, actions[0].ID)
}

// A user with StartTerminal granted twice — direct role plus the same
// permission inherited via a group — must produce exactly one TTY
// action row in the resolved set.
//
// What this test actually exercises: the JOIN keys on
// users_projection.system_tty_action_id, and each user has at most
// one such ID, so the SQL never produces duplicate candidate rows
// for one user regardless of how many permission paths grant the
// permission (the role check is an EXISTS filter, not a row
// multiplier). The user-visible "one row per action" property is
// therefore upheld by the SQL shape on its own; the resolver's
// deviceActionSet dedupe and the SQL's DISTINCT ON (a.id) are both
// defensive belt-and-braces against future query/schema changes
// that could expose row multiplication, and this test guards the
// observable end-state rather than the exact mechanism that
// guarantees it.
func TestResolveActions_TTYPermissionSource_DedupesOverlappingRoleGrants(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	operatorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")

	// Direct role grant
	directRoleID := testutil.CreateTestRole(t, st, adminID, "tty-direct", []string{"StartTerminal"})
	testutil.AssignRoleToTestUser(t, st, adminID, operatorID, directRoleID)

	// Plus the same permission via a group role
	groupID := testutil.CreateTestUserGroup(t, st, adminID, "tty-dedupe-team")
	groupRoleID := testutil.CreateTestRole(t, st, adminID, "tty-via-group", []string{"StartTerminal"})
	testutil.AddUserToTestGroup(t, st, adminID, groupID, operatorID)
	testutil.AssignRoleToTestGroup(t, st, adminID, groupID, groupRoleID)

	ttyActionID := testutil.CreateTestAction(t, st, adminID, "system:tty-user:"+operatorID, int(pm.ActionType_ACTION_TYPE_USER))
	linkSystemTtyAction(t, st, operatorID, ttyActionID)

	deviceID := testutil.CreateTestDevice(t, st, "dedupe-host")

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)
	require.Len(t, actions, 1, "duplicate permission grants must collapse to one TTY action")
	assert.Equal(t, ttyActionID, actions[0].ID)
}

// ttyFailingQuerier wraps a real Querier and forces the TTY query to
// fail, leaving every other call delegated. Used to verify the
// fail-fast contract: a TTY query error must propagate up, NOT
// degrade to an empty slice. The agent's SyncActions treats the
// server's action list as authoritative and reverts USER actions
// that disappear from a successful sync response — so silently
// dropping the TTY rows would tear down every pm-tty-<username>
// account across the fleet on the next sync.
type ttyFailingQuerier struct {
	resolution.Querier
	err error
}

func (q ttyFailingQuerier) ListSystemTtyActionsForPermissionHolders(ctx context.Context) ([]db.ListSystemTtyActionsForPermissionHoldersRow, error) {
	return nil, q.err
}

// TestResolveActions_TTYPermissionSource_FailsFastOnTtyError locks in
// the rc13 safety contract: when ListSystemTtyActionsForPermissionHolders
// fails, ResolveActionsForDevice MUST surface the error rather than
// quietly continuing without TTY rows. ProxySyncActions then fails
// the sync, the agent retries on its interval, and nothing on disk
// changes in the meantime. The previous "graceful degradation" path
// was actively destructive — see the failure-mode note in resolve.go.
func TestResolveActions_TTYPermissionSource_FailsFastOnTtyError(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	actionID := testutil.CreateTestAction(t, st, adminID, "Survives TTY Failure", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "tty-failure-host")
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, 0)

	sentinel := errors.New("simulated DB hiccup")
	q := ttyFailingQuerier{
		Querier: st.Queries(),
		err:     sentinel,
	}
	_, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), q, deviceID)
	require.ErrorIs(t, err, sentinel, "TTY layer failure must propagate up, not degrade silently")
}

// =============================================================================
// Global TerminalAdmin layer (#70).
//
// Two rows in actions_projection — system:terminal-admin-limited:global
// and system:terminal-admin-full:global — are merged into every device's
// resolved action list, exclusion-exempt and deduped against the
// device/user layers, mirroring the TTY layer's shape.
// =============================================================================

// noOpSigner mirrors the api package's test-only NoOpSigner — a
// deterministic dummy signer so the resolution-layer tests can stand
// up a SystemActionManager without the real CA. api.NoOpSigner lives
// in a _test.go file in the api package and isn't visible across
// package boundaries, so we re-declare the minimal stub here.
type noOpSigner struct{}

func (noOpSigner) Sign(actionID string, actionType int32, paramsJSON []byte) ([]byte, error) {
	_ = actionID
	_ = actionType
	_ = paramsJSON
	return []byte("noop-test-signature"), nil
}

// bootstrapAndReconcileTerminalAdmin runs the manager's bootstrap +
// reconcile against the test store so the two global actions exist
// before the resolution-layer assertions run.
func bootstrapAndReconcileTerminalAdmin(t *testing.T, st *store.Store) {
	t.Helper()
	mgr := api.NewSystemActionManager(st, noOpSigner{}, slog.Default())
	require.NoError(t, mgr.BootstrapGlobalTerminalAdminActions(context.Background()))
	require.NoError(t, mgr.ReconcileGlobalTerminalAdminActions(context.Background()))
}

func TestResolveActions_GlobalTerminalAdmin_IncludedForFreshDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	bootstrapAndReconcileTerminalAdmin(t, st)
	deviceID := testutil.CreateTestDevice(t, st, "fresh-host-with-admin")

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, a := range actions {
		names[a.Name] = true
	}
	assert.True(t, names["system:terminal-admin-limited:global"],
		"Limited global must reach a brand-new device without any assignment")
	assert.True(t, names["system:terminal-admin-full:global"],
		"Full global must reach a brand-new device without any assignment")
}

// Operator EXCLUDED on a global TerminalAdmin action must NOT lock
// out the sudoers fragment — same property as the TTY layer. Terminal
// admin policy is the system's escape hatch; revocation goes through
// the role/permission system, not through per-device EXCLUDED.
func TestResolveActions_GlobalTerminalAdmin_BypassesDeviceExcluded(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	bootstrapAndReconcileTerminalAdmin(t, st)
	deviceID := testutil.CreateTestDevice(t, st, "excl-attempt-host")

	limited, err := st.Queries().GetActionByName(context.Background(), "system:terminal-admin-limited:global")
	require.NoError(t, err)

	// Operator attempt: EXCLUDED assignment on the Limited global.
	// The permission-derived layer must ignore it.
	testutil.CreateTestAssignment(t, st, adminID, "action", limited.ID, "device", deviceID, 2)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)

	found := false
	for _, a := range actions {
		if a.ID == limited.ID {
			found = true
		}
	}
	assert.True(t, found,
		"device-layer EXCLUDED must NOT remove the global Limited TerminalAdmin action — escape-hatch property mirrors TTY layer")
}

// Dedupe: if some operator authored a REQUIRED assignment for one of
// the globals (already-present-via-permission-layer), the action must
// appear exactly once in the resolved list.
func TestResolveActions_GlobalTerminalAdmin_DedupedAgainstDeviceLayer(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	bootstrapAndReconcileTerminalAdmin(t, st)
	deviceID := testutil.CreateTestDevice(t, st, "dedup-attempt-host")

	limited, err := st.Queries().GetActionByName(context.Background(), "system:terminal-admin-limited:global")
	require.NoError(t, err)

	testutil.CreateTestAssignment(t, st, adminID, "action", limited.ID, "device", deviceID, 0)

	actions, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), st.Queries(), deviceID)
	require.NoError(t, err)

	hits := 0
	for _, a := range actions {
		if a.ID == limited.ID {
			hits++
		}
	}
	assert.Equal(t, 1, hits, "Limited global must appear exactly once even when also assigned directly to the device")
}

// Fail-fast: the global TerminalAdmin query must propagate errors up,
// not degrade to an empty slice. The agent treats the server's action
// list as authoritative — silent drop would tear down every device's
// pm-sudo-* group on the next sync.
type globalTerminalAdminFailingQuerier struct {
	resolution.Querier
	err error
}

func (q globalTerminalAdminFailingQuerier) ListGlobalTerminalAdminActions(ctx context.Context) ([]db.ListGlobalTerminalAdminActionsRow, error) {
	return nil, q.err
}

func TestResolveActions_GlobalTerminalAdmin_FailsFastOnQueryError(t *testing.T) {
	st := testutil.SetupPostgres(t)
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	bootstrapAndReconcileTerminalAdmin(t, st)
	deviceID := testutil.CreateTestDevice(t, st, "global-failure-host")

	sentinel := errors.New("simulated DB hiccup on terminal-admin lookup")
	q := globalTerminalAdminFailingQuerier{
		Querier: st.Queries(),
		err:     sentinel,
	}
	_, err := resolution.ResolveActionsForDevice(testutil.AdminContext(adminID), q, deviceID)
	require.ErrorIs(t, err, sentinel,
		"global TerminalAdmin query failure must propagate, not degrade silently — agents revert membership on missing rows")
}
