package api_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestCreateAssignment_ActionToDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, nil)
	h := api.NewAssignmentHandler(st, actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Assign Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "assign-host")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateAssignment(ctx, connect.NewRequest(&pm.CreateAssignmentRequest{
		SourceType: "action",
		SourceId:   actionID,
		TargetType: "device",
		TargetId:   deviceID,
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Assignment.Id)
	assert.Equal(t, "action", resp.Msg.Assignment.SourceType)
	assert.Equal(t, actionID, resp.Msg.Assignment.SourceId)
	assert.Equal(t, "device", resp.Msg.Assignment.TargetType)
	assert.Equal(t, deviceID, resp.Msg.Assignment.TargetId)
}

func TestCreateAssignment_SetToGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, nil)
	h := api.NewAssignmentHandler(st, actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Assign Set")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Assign Group")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateAssignment(ctx, connect.NewRequest(&pm.CreateAssignmentRequest{
		SourceType: "action_set",
		SourceId:   setID,
		TargetType: "device_group",
		TargetId:   groupID,
	}))
	require.NoError(t, err)
	assert.Equal(t, "action_set", resp.Msg.Assignment.SourceType)
	assert.Equal(t, "device_group", resp.Msg.Assignment.TargetType)
}

func TestCreateAssignment_Idempotent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, nil)
	h := api.NewAssignmentHandler(st, actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Idem Action", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "idem-host")
	ctx := testutil.AdminContext(adminID)

	req := &pm.CreateAssignmentRequest{
		SourceType: "action",
		SourceId:   actionID,
		TargetType: "device",
		TargetId:   deviceID,
	}

	resp1, err := h.CreateAssignment(ctx, connect.NewRequest(req))
	require.NoError(t, err)

	resp2, err := h.CreateAssignment(ctx, connect.NewRequest(req))
	require.NoError(t, err)

	// Same assignment returned
	assert.Equal(t, resp1.Msg.Assignment.Id, resp2.Msg.Assignment.Id)
}

func TestDeleteAssignment(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, nil)
	h := api.NewAssignmentHandler(st, actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Del Assign", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "del-host")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateAssignment(ctx, connect.NewRequest(&pm.CreateAssignmentRequest{
		SourceType: "action",
		SourceId:   actionID,
		TargetType: "device",
		TargetId:   deviceID,
	}))
	require.NoError(t, err)

	_, err = h.DeleteAssignment(ctx, connect.NewRequest(&pm.DeleteAssignmentRequest{
		Id: createResp.Msg.Assignment.Id,
	}))
	require.NoError(t, err)
}

func TestListAssignments(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, nil)
	h := api.NewAssignmentHandler(st, actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "list-host")
	ctx := testutil.AdminContext(adminID)

	for i := 0; i < 3; i++ {
		actionID := testutil.CreateTestAction(t, st, adminID, testutil.NewID(), int(pm.ActionType_ACTION_TYPE_SHELL))
		_, err := h.CreateAssignment(ctx, connect.NewRequest(&pm.CreateAssignmentRequest{
			SourceType: "action",
			SourceId:   actionID,
			TargetType: "device",
			TargetId:   deviceID,
		}))
		require.NoError(t, err)
	}

	resp, err := h.ListAssignments(ctx, connect.NewRequest(&pm.ListAssignmentsRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Assignments), 3)
}

func TestGetDeviceAssignments(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, nil)
	h := api.NewAssignmentHandler(st, actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Device Assign", int(pm.ActionType_ACTION_TYPE_SHELL))
	deviceID := testutil.CreateTestDevice(t, st, "device-assign-host")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateAssignment(ctx, connect.NewRequest(&pm.CreateAssignmentRequest{
		SourceType: "action",
		SourceId:   actionID,
		TargetType: "device",
		TargetId:   deviceID,
	}))
	require.NoError(t, err)

	resp, err := h.GetDeviceAssignments(ctx, connect.NewRequest(&pm.GetDeviceAssignmentsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Actions), 1)
}
