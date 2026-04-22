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

func TestQueryDeviceLogs_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewLogsHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.QueryDeviceLogs(ctx, connect.NewRequest(&pm.QueryDeviceLogsRequest{
		DeviceId: "nonexistent-device",
		Lines:    100,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

// TestQueryDeviceLogs_NoTaskQueue_RefusesWithPrecondition pins the
// fail-closed contract introduced when we tightened the dispatch
// paths against silent no-ops. Previously a handler with no aqClient
// would still create a pending query row and return 200 OK — the
// caller saw a queryID to poll that the agent would never receive.
// Now the handler refuses the RPC with FailedPrecondition so the
// operator knows the deployment is misconfigured.
func TestQueryDeviceLogs_NoTaskQueue_RefusesWithPrecondition(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewLogsHandler(st, slog.Default())
	// Intentionally do NOT call h.SetTaskQueueClient.

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-device")

	_, err := h.QueryDeviceLogs(ctx, connect.NewRequest(&pm.QueryDeviceLogsRequest{
		DeviceId: deviceID,
		Lines:    50,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestGetDeviceLogResult_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewLogsHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetDeviceLogResult(ctx, connect.NewRequest(&pm.GetDeviceLogResultRequest{
		QueryId: "nonexistent-query-id",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestGetDeviceLogResult_PendingResult(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewLogsHandler(st, slog.Default())
	// Wire a no-op enqueuer so QueryDeviceLogs actually dispatches
	// and creates the pending row this test reads back. Without it
	// the new FailedPrecondition gate rejects the dispatch.
	h.SetTaskQueueClient(&api.NoOpEnqueuer{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-device")

	// Create a log query to get a valid query ID
	queryResp, err := h.QueryDeviceLogs(ctx, connect.NewRequest(&pm.QueryDeviceLogsRequest{
		DeviceId: deviceID,
		Lines:    50,
	}))
	require.NoError(t, err)

	// Retrieve the pending result
	resultResp, err := h.GetDeviceLogResult(ctx, connect.NewRequest(&pm.GetDeviceLogResultRequest{
		QueryId: queryResp.Msg.QueryId,
	}))
	require.NoError(t, err)
	assert.Equal(t, queryResp.Msg.QueryId, resultResp.Msg.QueryId)
	assert.False(t, resultResp.Msg.Completed)
	assert.False(t, resultResp.Msg.Success)
}
