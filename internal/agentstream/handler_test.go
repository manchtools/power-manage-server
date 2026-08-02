package agentstream

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/delivery"
)

func TestFrameBudgetsArePerDeviceAndClass(t *testing.T) {
	heartbeats := auth.NewRateLimiter(2, time.Minute)
	alerts := auth.NewRateLimiter(1, time.Minute)
	hellos := auth.NewRateLimiter(1, time.Minute)
	defer heartbeats.Stop()
	defer alerts.Stop()
	defer hellos.Stop()
	h := &Handler{frameLimiters: map[frameClass]*auth.RateLimiter{
		frameTelemetry: heartbeats,
		frameAudit:     alerts,
		frameHello:     hellos,
	}}
	heartbeat := &pmv1.AgentMessage{Payload: &pmv1.AgentMessage_Heartbeat{Heartbeat: &pmv1.Heartbeat{}}}
	alert := &pmv1.AgentMessage{Payload: &pmv1.AgentMessage_SecurityAlert{SecurityAlert: &pmv1.SecurityAlert{
		Type: pmv1.SecurityAlertType_SECURITY_ALERT_TYPE_CREDENTIAL_TAMPERING,
	}}}
	hello := &pmv1.AgentMessage{Payload: &pmv1.AgentMessage_Hello{Hello: &pmv1.Hello{}}}

	assert.True(t, h.allowFrame("device-1", heartbeat))
	assert.True(t, h.allowFrame("device-1", heartbeat))
	assert.False(t, h.allowFrame("device-1", heartbeat))
	assert.True(t, h.allowFrame("device-2", heartbeat), "devices must not share a budget")
	assert.True(t, h.allowFrame("device-1", alert), "frame classes must not share a budget")
	assert.False(t, h.allowFrame("device-1", alert))
	assert.True(t, h.allowFrame("device-1", hello))
	assert.False(t, h.allowFrame("device-1", hello))
}

type fakeDeliveryState struct {
	receiptDelivery, receiptDevice                      string
	resultDelivery, resultDevice, manifest, state, code string
}

func (f *fakeDeliveryState) AcknowledgeReceipt(_ context.Context, deliveryID, deviceID string) (bool, error) {
	f.receiptDelivery, f.receiptDevice = deliveryID, deviceID
	return true, nil
}

func (f *fakeDeliveryState) Complete(_ context.Context, deliveryID, deviceID, manifestID, state, code string) (bool, error) {
	f.resultDelivery, f.resultDevice, f.manifest, f.state, f.code = deliveryID, deviceID, manifestID, state, code
	return true, nil
}

type fakeExecutionResults struct {
	resultDevice, outputDevice string
	result                     *pmv1.ActionResult
	output                     *pmv1.OutputChunk
}

func (f *fakeExecutionResults) ApplyActionResult(_ context.Context, deviceID string, result *pmv1.ActionResult) error {
	f.resultDevice, f.result = deviceID, result
	return nil
}

func (f *fakeExecutionResults) AppendOutputChunk(_ context.Context, deviceID string, output *pmv1.OutputChunk) error {
	f.outputDevice, f.output = deviceID, output
	return nil
}

type fakeDeviceResults struct {
	queryDevice, logDevice, inventoryDevice, revocationDevice string
}

func (f *fakeDeviceResults) CompleteOSQueryResult(_ context.Context, deviceID string, _ *pmv1.OSQueryResult) error {
	f.queryDevice = deviceID
	return nil
}

func (f *fakeDeviceResults) CompleteLogQueryResult(_ context.Context, deviceID string, _ *pmv1.LogQueryResult) error {
	f.logDevice = deviceID
	return nil
}

func (f *fakeDeviceResults) StoreDeviceInventory(_ context.Context, deviceID string, _ *pmv1.DeviceInventory) error {
	f.inventoryDevice = deviceID
	return nil
}

func (f *fakeDeviceResults) CompleteLuksKeyRevocation(_ context.Context, deviceID string, _ *pmv1.RevokeLuksDeviceKeyResult) error {
	f.revocationDevice = deviceID
	return nil
}

func TestHandleAgentMessageRoutesDirectDurableFrames(t *testing.T) {
	deviceID, deliveryID, manifestID := "device", "delivery", "manifest"
	deliveryState := &fakeDeliveryState{}
	executionResults := &fakeExecutionResults{}
	deviceResults := &fakeDeviceResults{}
	handler := &Handler{
		deliveries: deliveryState, executions: executionResults, deviceResults: deviceResults,
		terminalSessions: connection.NewTerminalSessionRegistry(),
	}
	agent := &connection.Agent{DeviceID: deviceID}

	frames := []*pmv1.AgentMessage{
		{Payload: &pmv1.AgentMessage_Heartbeat{Heartbeat: &pmv1.Heartbeat{}}},
		{Payload: &pmv1.AgentMessage_DeliveryReceipt{DeliveryReceipt: &pmv1.DeliveryReceipt{DeliveryId: deliveryID}}},
		{Payload: &pmv1.AgentMessage_ManifestResult{ManifestResult: &pmv1.ManifestResult{
			DeliveryId: deliveryID, ManifestId: manifestID,
			Status: pmv1.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE,
		}}},
		{Payload: &pmv1.AgentMessage_ActionResult{ActionResult: &pmv1.ActionResult{OccurrenceId: "occurrence"}}},
		{Payload: &pmv1.AgentMessage_OutputChunk{OutputChunk: &pmv1.OutputChunk{ExecutionId: "occurrence"}}},
		{Payload: &pmv1.AgentMessage_QueryResult{QueryResult: &pmv1.OSQueryResult{QueryId: "query"}}},
		{Payload: &pmv1.AgentMessage_LogQueryResult{LogQueryResult: &pmv1.LogQueryResult{QueryId: "log"}}},
		{Payload: &pmv1.AgentMessage_Inventory{Inventory: &pmv1.DeviceInventory{}}},
		{Payload: &pmv1.AgentMessage_RevokeLuksDeviceKeyResult{RevokeLuksDeviceKeyResult: &pmv1.RevokeLuksDeviceKeyResult{ActionId: "action"}}},
	}
	for _, frame := range frames {
		require.NoError(t, handler.handleAgentMessage(context.Background(), agent, frame))
	}

	assert.Equal(t, deliveryID, deliveryState.receiptDelivery)
	assert.Equal(t, deviceID, deliveryState.receiptDevice)
	assert.Equal(t, deliveryID, deliveryState.resultDelivery)
	assert.Equal(t, manifestID, deliveryState.manifest)
	assert.Equal(t, delivery.StatePartial, deliveryState.state)
	assert.Equal(t, "INDETERMINATE", deliveryState.code)
	assert.Equal(t, deviceID, executionResults.resultDevice)
	assert.Equal(t, deviceID, executionResults.outputDevice)
	assert.Equal(t, deviceID, deviceResults.queryDevice)
	assert.Equal(t, deviceID, deviceResults.logDevice)
	assert.Equal(t, deviceID, deviceResults.inventoryDevice)
	assert.Equal(t, deviceID, deviceResults.revocationDevice)
}

func TestHandleAgentMessageEnforcesTerminalDeviceBinding(t *testing.T) {
	registry := connection.NewTerminalSessionRegistry()
	registry.Register(connection.NewTerminalSession("session", "right-device", "user", "root", 80, 24))
	handler := &Handler{terminalSessions: registry}
	message := &pmv1.AgentMessage{Payload: &pmv1.AgentMessage_TerminalOutput{
		TerminalOutput: &pmv1.TerminalOutput{SessionId: "session", Data: []byte("output")},
	}}

	err := handler.handleAgentMessage(context.Background(), &connection.Agent{DeviceID: "wrong-device"}, message)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "another device")

	require.NoError(t, handler.handleAgentMessage(context.Background(), &connection.Agent{DeviceID: "right-device"}, message))
	select {
	case routed := <-registry.Get("session").OutputCh:
		assert.Same(t, message, routed)
	default:
		t.Fatal("terminal frame was not routed")
	}
}

func TestManifestResultStateAcceptsOnlyAggregateOutcomes(t *testing.T) {
	tests := []struct {
		status pmv1.ExecutionStatus
		state  string
		code   string
	}{
		{pmv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS, delivery.StateSucceeded, "SUCCESS"},
		{pmv1.ExecutionStatus_EXECUTION_STATUS_FAILED, delivery.StateFailed, "FAILED"},
		{pmv1.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE, delivery.StatePartial, "INDETERMINATE"},
	}
	for _, test := range tests {
		state, code, err := manifestResultState(&pmv1.ManifestResult{Status: test.status})
		require.NoError(t, err)
		assert.Equal(t, test.state, state)
		assert.Equal(t, test.code, code)
	}
	_, _, err := manifestResultState(&pmv1.ManifestResult{Status: pmv1.ExecutionStatus_EXECUTION_STATUS_RUNNING})
	require.Error(t, err)
}
