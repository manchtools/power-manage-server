package api_test

import (
	"encoding/json"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestDispatchOSQuery(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID,
		Table:    "processes",
		Limit:    100,
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.QueryId)

	// Verify the pending result was created
	result, err := st.Queries().GetOSQueryResult(ctx, resp.Msg.QueryId)
	require.NoError(t, err)
	assert.Equal(t, deviceID, result.DeviceID)
	assert.Equal(t, "processes", result.TableName)
	assert.False(t, result.Completed)
}

func TestDispatchOSQuery_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: "nonexistent",
		Table:    "processes",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestGetOSQueryResult_Pending(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	// Dispatch a query first
	dispatchResp, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID,
		Table:    "processes",
	}))
	require.NoError(t, err)

	// Poll — should be pending
	resp, err := h.GetOSQueryResult(ctx, connect.NewRequest(&pm.GetOSQueryResultRequest{
		QueryId: dispatchResp.Msg.QueryId,
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Completed)
	assert.Empty(t, resp.Msg.Rows)
}

func TestGetOSQueryResult_Completed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	// Dispatch
	dispatchResp, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID,
		Table:    "processes",
	}))
	require.NoError(t, err)
	queryID := dispatchResp.Msg.QueryId

	// Simulate agent completing the query
	rows := []map[string]string{
		{"pid": "1", "name": "systemd"},
		{"pid": "42", "name": "sshd"},
	}
	rowsJSON, err := json.Marshal(rows)
	require.NoError(t, err)

	err = st.Queries().CompleteOSQueryResult(ctx, generated.CompleteOSQueryResultParams{
		QueryID: queryID,
		Success: true,
		Error:   "",
		Rows:    rowsJSON,
	})
	require.NoError(t, err)

	// Poll — should be completed with rows
	resp, err := h.GetOSQueryResult(ctx, connect.NewRequest(&pm.GetOSQueryResultRequest{
		QueryId: queryID,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Completed)
	assert.True(t, resp.Msg.Success)
	assert.Len(t, resp.Msg.Rows, 2)
	assert.Equal(t, "1", resp.Msg.Rows[0].Data["pid"])
	assert.Equal(t, "systemd", resp.Msg.Rows[0].Data["name"])
}

func TestGetOSQueryResult_CompletedWithError(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	// Dispatch
	dispatchResp, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID,
		Table:    "nonexistent_table",
	}))
	require.NoError(t, err)

	// Simulate agent error
	err = st.Queries().CompleteOSQueryResult(ctx, generated.CompleteOSQueryResultParams{
		QueryID: dispatchResp.Msg.QueryId,
		Success: false,
		Error:   "table not found: nonexistent_table",
		Rows:    []byte("[]"),
	})
	require.NoError(t, err)

	// Poll — should be completed with error
	resp, err := h.GetOSQueryResult(ctx, connect.NewRequest(&pm.GetOSQueryResultRequest{
		QueryId: dispatchResp.Msg.QueryId,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Completed)
	assert.False(t, resp.Msg.Success)
	assert.Equal(t, "table not found: nonexistent_table", resp.Msg.Error)
	assert.Empty(t, resp.Msg.Rows)
}

func TestGetOSQueryResult_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetOSQueryResult(ctx, connect.NewRequest(&pm.GetOSQueryResultRequest{
		QueryId: "nonexistent",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestGetDeviceInventory(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	// Insert inventory data
	sysInfoRows, _ := json.Marshal([]map[string]string{
		{"hostname": "test-host", "cpu_brand": "Intel i7", "physical_memory": "17179869184"},
	})
	blockRows, _ := json.Marshal([]map[string]string{
		{"name": "sda", "size": "500107862016"},
		{"name": "sdb", "size": "1000204886016"},
	})

	err := st.Queries().UpsertDeviceInventory(ctx, generated.UpsertDeviceInventoryParams{
		DeviceID:  deviceID,
		TableName: "system_info",
		Rows:      sysInfoRows,
	})
	require.NoError(t, err)

	err = st.Queries().UpsertDeviceInventory(ctx, generated.UpsertDeviceInventoryParams{
		DeviceID:  deviceID,
		TableName: "block_devices",
		Rows:      blockRows,
	})
	require.NoError(t, err)

	// Get all inventory
	resp, err := h.GetDeviceInventory(ctx, connect.NewRequest(&pm.GetDeviceInventoryRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Tables, 2)

	// Verify tables contain expected data
	tableMap := make(map[string]*pm.InventoryTableResult)
	for _, table := range resp.Msg.Tables {
		tableMap[table.TableName] = table
	}

	sysInfo := tableMap["system_info"]
	require.NotNil(t, sysInfo)
	assert.Len(t, sysInfo.Rows, 1)
	assert.Equal(t, "test-host", sysInfo.Rows[0].Data["hostname"])

	blocks := tableMap["block_devices"]
	require.NotNil(t, blocks)
	assert.Len(t, blocks.Rows, 2)
}

func TestGetDeviceInventory_FilterByTables(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	// Insert multiple tables
	for _, table := range []string{"system_info", "block_devices", "interface_details"} {
		rows, _ := json.Marshal([]map[string]string{{"key": "value"}})
		err := st.Queries().UpsertDeviceInventory(ctx, generated.UpsertDeviceInventoryParams{
			DeviceID:  deviceID,
			TableName: table,
			Rows:      rows,
		})
		require.NoError(t, err)
	}

	// Filter to just system_info
	resp, err := h.GetDeviceInventory(ctx, connect.NewRequest(&pm.GetDeviceInventoryRequest{
		DeviceId:   deviceID,
		TableNames: []string{"system_info"},
	}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Tables, 1)
	assert.Equal(t, "system_info", resp.Msg.Tables[0].TableName)
}

func TestGetDeviceInventory_Empty(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.GetDeviceInventory(ctx, connect.NewRequest(&pm.GetDeviceInventoryRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Tables)
}

func TestRefreshDeviceInventory(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "test-host")

	resp, err := h.RefreshDeviceInventory(ctx, connect.NewRequest(&pm.RefreshDeviceInventoryRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.NotNil(t, resp.Msg)
}

func TestRefreshDeviceInventory_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewOSQueryHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.RefreshDeviceInventory(ctx, connect.NewRequest(&pm.RefreshDeviceInventoryRequest{
		DeviceId: "nonexistent",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}
