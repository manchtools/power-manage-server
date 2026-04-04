package gateway

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// TestParseActionParams_Package tests package parameter parsing.
func TestParseActionParams_Package(t *testing.T) {
	action := &pm.Action{}
	params := `{"name":"vim"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_PACKAGE), []byte(params))

	require.NotNil(t, action.GetPackage())
	assert.Equal(t, "vim", action.GetPackage().Name)
}

func TestParseActionParams_Shell(t *testing.T) {
	action := &pm.Action{}
	params := `{"script":"echo hello","runAsRoot":true}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_SHELL), []byte(params))

	require.NotNil(t, action.GetShell())
	assert.Equal(t, "echo hello", action.GetShell().Script)
	assert.True(t, action.GetShell().RunAsRoot)
}

func TestParseActionParams_ScriptRun(t *testing.T) {
	action := &pm.Action{}
	params := `{"script":"#!/bin/bash\nexit 0"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_SCRIPT_RUN), []byte(params))

	require.NotNil(t, action.GetShell())
	assert.Contains(t, action.GetShell().Script, "exit 0")
}

func TestParseActionParams_Systemd(t *testing.T) {
	action := &pm.Action{}
	params := `{"unitName":"nginx.service","enable":true}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_SYSTEMD), []byte(params))

	require.NotNil(t, action.GetSystemd())
	assert.Equal(t, "nginx.service", action.GetSystemd().UnitName)
	assert.True(t, action.GetSystemd().Enable)
}

func TestParseActionParams_File(t *testing.T) {
	action := &pm.Action{}
	params := `{"path":"/etc/test.conf","content":"key=value"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_FILE), []byte(params))

	require.NotNil(t, action.GetFile())
	assert.Equal(t, "/etc/test.conf", action.GetFile().Path)
}

func TestParseActionParams_Directory(t *testing.T) {
	action := &pm.Action{}
	params := `{"path":"/opt/myapp"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_DIRECTORY), []byte(params))

	require.NotNil(t, action.GetDirectory())
	assert.Equal(t, "/opt/myapp", action.GetDirectory().Path)
}

func TestParseActionParams_Update(t *testing.T) {
	action := &pm.Action{}
	params := `{}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_UPDATE), []byte(params))

	require.NotNil(t, action.GetUpdate())
}

func TestParseActionParams_Repository(t *testing.T) {
	action := &pm.Action{}
	params := `{"name":"myrepo"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_REPOSITORY), []byte(params))

	require.NotNil(t, action.GetRepository())
	assert.Equal(t, "myrepo", action.GetRepository().Name)
}

func TestParseActionParams_Flatpak(t *testing.T) {
	action := &pm.Action{}
	params := `{"appId":"org.gnome.Calculator"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_FLATPAK), []byte(params))

	require.NotNil(t, action.GetFlatpak())
	assert.Equal(t, "org.gnome.Calculator", action.GetFlatpak().AppId)
}

func TestParseActionParams_User(t *testing.T) {
	action := &pm.Action{}
	params := `{"username":"testuser"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_USER), []byte(params))

	require.NotNil(t, action.GetUser())
	assert.Equal(t, "testuser", action.GetUser().Username)
}

func TestParseActionParams_Group(t *testing.T) {
	action := &pm.Action{}
	params := `{"name":"developers"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_GROUP), []byte(params))

	require.NotNil(t, action.GetGroup())
	assert.Equal(t, "developers", action.GetGroup().Name)
}

func TestParseActionParams_InvalidJSON(t *testing.T) {
	action := &pm.Action{}
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_PACKAGE), []byte("not json"))

	// Should not panic and params should remain nil
	assert.Nil(t, action.Params)
}

func TestParseActionParams_EmptyParams(t *testing.T) {
	action := &pm.Action{}
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_SHELL), []byte("{}"))

	// Should parse without error, Shell should be set (with empty fields)
	require.NotNil(t, action.GetShell())
}

func TestParseActionParams_AppImage(t *testing.T) {
	action := &pm.Action{}
	params := `{"url":"https://example.com/app.AppImage"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_APP_IMAGE), []byte(params))

	require.NotNil(t, action.GetApp())
}

func TestParseActionParams_Deb(t *testing.T) {
	action := &pm.Action{}
	params := `{"url":"https://example.com/app.deb"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_DEB), []byte(params))

	require.NotNil(t, action.GetApp())
}

func TestParseActionParams_Rpm(t *testing.T) {
	action := &pm.Action{}
	params := `{"url":"https://example.com/app.rpm"}`
	parseActionParams(action, int32(pm.ActionType_ACTION_TYPE_RPM), []byte(params))

	require.NotNil(t, action.GetApp())
}

// TestActionDispatchPayloadRoundtrip verifies that the payload JSON
// correctly round-trips through marshal/unmarshal.
func TestActionDispatchPayloadRoundtrip(t *testing.T) {
	original := taskqueue.ActionDispatchPayload{
		ExecutionID:    "exec-123",
		ActionType:     int32(pm.ActionType_ACTION_TYPE_SHELL),
		DesiredState:   int32(pm.DesiredState_DESIRED_STATE_PRESENT),
		Params:         json.RawMessage(`{"script":"echo hi"}`),
		TimeoutSeconds: 300,
		Signature:      []byte("sig"),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded taskqueue.ActionDispatchPayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ExecutionID, decoded.ExecutionID)
	assert.Equal(t, original.ActionType, decoded.ActionType)
	assert.Equal(t, original.TimeoutSeconds, decoded.TimeoutSeconds)
	assert.JSONEq(t, `{"script":"echo hi"}`, string(decoded.Params))
}

// TestOSQueryDispatchPayloadRoundtrip verifies osquery payload round-trips.
func TestOSQueryDispatchPayloadRoundtrip(t *testing.T) {
	original := taskqueue.OSQueryDispatchPayload{
		QueryID: "q-123",
		Table:   "processes",
		Columns: []string{"pid", "name"},
		Limit:   100,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded taskqueue.OSQueryDispatchPayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.QueryID, decoded.QueryID)
	assert.Equal(t, original.Table, decoded.Table)
	assert.Equal(t, original.Columns, decoded.Columns)
	assert.Equal(t, original.Limit, decoded.Limit)
}

// TestLogQueryDispatchPayloadRoundtrip verifies log query payload round-trips.
func TestLogQueryDispatchPayloadRoundtrip(t *testing.T) {
	original := taskqueue.LogQueryDispatchPayload{
		QueryID:  "lq-456",
		Lines:    100,
		Unit:     "nginx.service",
		Since:    "2026-01-01",
		Priority: "err",
		Grep:     "error",
		Kernel:   true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded taskqueue.LogQueryDispatchPayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.QueryID, decoded.QueryID)
	assert.Equal(t, original.Lines, decoded.Lines)
	assert.Equal(t, original.Unit, decoded.Unit)
	assert.Equal(t, original.Kernel, decoded.Kernel)
}

func TestDeviceTaskHandler_BuildsActionMessage(t *testing.T) {
	// Directly test the action building logic by constructing the Action
	// exactly as handleActionDispatch does (minus the Send call).
	payload := taskqueue.ActionDispatchPayload{
		ExecutionID:    "exec-001",
		ActionType:     int32(pm.ActionType_ACTION_TYPE_PACKAGE),
		DesiredState:   int32(pm.DesiredState_DESIRED_STATE_PRESENT),
		Params:         json.RawMessage(`{"name":"htop"}`),
		TimeoutSeconds: 600,
	}

	action := &pm.Action{
		Id:             &pm.ActionId{Value: payload.ExecutionID},
		Type:           pm.ActionType(payload.ActionType),
		DesiredState:   pm.DesiredState(payload.DesiredState),
		TimeoutSeconds: payload.TimeoutSeconds,
	}
	parseActionParams(action, payload.ActionType, payload.Params)

	assert.Equal(t, "exec-001", action.Id.Value)
	assert.Equal(t, pm.ActionType_ACTION_TYPE_PACKAGE, action.Type)
	assert.Equal(t, pm.DesiredState_DESIRED_STATE_PRESENT, action.DesiredState)
	assert.Equal(t, int32(600), action.TimeoutSeconds)
	require.NotNil(t, action.GetPackage())
	assert.Equal(t, "htop", action.GetPackage().Name)
}

