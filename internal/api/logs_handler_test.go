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

func TestQueryDeviceLogs_ValidDevice_NoTaskQueue(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewLogsHandler(st, slog.Default())
	// No task queue client set — tests that it still creates the query result row

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	deviceID := testutil.CreateTestDevice(t, st, "test-device")

	resp, err := h.QueryDeviceLogs(ctx, connect.NewRequest(&pm.QueryDeviceLogsRequest{
		DeviceId: deviceID,
		Lines:    50,
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.QueryId)
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
