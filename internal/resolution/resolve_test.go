package resolution_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/resolution"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

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

// Test that user assignment works via the handler (CreateAssignment + GetUserAssignments)
func TestCreateAssignment_UserTargetViaHandler(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, nil)
	h := api.NewAssignmentHandler(st, actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	actionID := testutil.CreateTestAction(t, st, adminID, "Handler Test", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateAssignment(ctx, connect.NewRequest(&pm.CreateAssignmentRequest{
		SourceType: "action",
		SourceId:   actionID,
		TargetType: "user",
		TargetId:   userID,
		Mode:       pm.AssignmentMode_ASSIGNMENT_MODE_REQUIRED,
	}))
	require.NoError(t, err)

	resp, err := h.GetUserAssignments(ctx, connect.NewRequest(&pm.GetUserAssignmentsRequest{
		UserId: userID,
	}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Assignments, 1)
	assert.Equal(t, "user", resp.Msg.Assignments[0].TargetType)
}
