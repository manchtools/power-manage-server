package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestSetUserSelection_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserSelectionHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-device")
	actionID := testutil.CreateTestAction(t, st, adminID, "Test Action", 1)

	// Create an available-mode assignment (mode 1 = ASSIGNMENT_MODE_AVAILABLE)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, int(pm.AssignmentMode_ASSIGNMENT_MODE_AVAILABLE))

	resp, err := h.SetUserSelection(ctx, connect.NewRequest(&pm.SetUserSelectionRequest{
		DeviceId:   deviceID,
		SourceType: "action",
		SourceId:   actionID,
		Selected:   true,
	}))
	require.NoError(t, err)
	assert.NotNil(t, resp.Msg.Selection)
	assert.Equal(t, deviceID, resp.Msg.Selection.DeviceId)
	assert.Equal(t, "action", resp.Msg.Selection.SourceType)
	assert.Equal(t, actionID, resp.Msg.Selection.SourceId)
	assert.True(t, resp.Msg.Selection.Selected)
}

func TestSetUserSelection_NoAssignment(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserSelectionHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-device")
	actionID := testutil.CreateTestAction(t, st, adminID, "Unassigned Action", 1)

	// No assignment created — selecting should fail
	_, err := h.SetUserSelection(ctx, connect.NewRequest(&pm.SetUserSelectionRequest{
		DeviceId:   deviceID,
		SourceType: "action",
		SourceId:   actionID,
		Selected:   true,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListAvailableActions_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserSelectionHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-device")
	actionID := testutil.CreateTestAction(t, st, adminID, "Available Action", 1)

	// Create an available-mode assignment (mode 1 = ASSIGNMENT_MODE_AVAILABLE)
	testutil.CreateTestAssignment(t, st, adminID, "action", actionID, "device", deviceID, int(pm.AssignmentMode_ASSIGNMENT_MODE_AVAILABLE))

	resp, err := h.ListAvailableActions(ctx, connect.NewRequest(&pm.ListAvailableActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Items, 1)
	assert.Equal(t, "action", resp.Msg.Items[0].SourceType)
	assert.Equal(t, actionID, resp.Msg.Items[0].SourceId)
	assert.Equal(t, "Available Action", resp.Msg.Items[0].SourceName)
	assert.False(t, resp.Msg.Items[0].Selected) // no selection yet
}

func TestListAvailableActions_EmptyForDeviceWithNoAssignments(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserSelectionHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-device")

	resp, err := h.ListAvailableActions(ctx, connect.NewRequest(&pm.ListAvailableActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Items)
}
