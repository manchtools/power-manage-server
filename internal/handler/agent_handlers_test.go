package handler

// Per-message handler coverage for AgentHandler
// (manchtools/power-manage-server#150 / audit F014). The existing
// agent_test.go covers only the input-validation surface of the
// public RPCs (SyncActions, ValidateLuksToken). This file exercises
// the per-message dispatcher's leaf handlers — the ones that take
// a decoded payload, do their per-type bookkeeping (logging, JSON
// marshal, payload assembly), and enqueue a control-bound Asynq
// task.
//
// Approach: a recording fake of taskqueue.Enqueuer captures each
// EnqueueToControl call. Tests assert task type + payload shape
// match the contract the inbox worker reads on the control side.
// No Valkey, no real Asynq.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// recordedEnqueue captures one EnqueueToControl / EnqueueToDevice /
// EnqueueToSearch call so tests can assert it was made with the
// right shape.
type recordedEnqueue struct {
	queue    string // "control" / "device:<id>" / "search"
	taskType string
	payload  any
}

// fakeEnqueuer records every enqueue call. err overrides the return
// to exercise failure-path branches.
type fakeEnqueuer struct {
	mu       sync.Mutex
	recorded []recordedEnqueue
	err      error
}

func (f *fakeEnqueuer) EnqueueToDevice(deviceID, taskType string, payload any, _ ...asynq.Option) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, recordedEnqueue{queue: "device:" + deviceID, taskType: taskType, payload: payload})
	return f.err
}

func (f *fakeEnqueuer) EnqueueToControl(taskType string, payload any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, recordedEnqueue{queue: "control", taskType: taskType, payload: payload})
	return f.err
}

func (f *fakeEnqueuer) EnqueueToSearch(taskType string, payload any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, recordedEnqueue{queue: "search", taskType: taskType, payload: payload})
	return f.err
}

func (f *fakeEnqueuer) DeleteScheduledDeviceTask(deviceID, taskID string) error { return nil }

func (f *fakeEnqueuer) lastCall(t *testing.T) recordedEnqueue {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.recorded, "expected at least one enqueue call")
	return f.recorded[len(f.recorded)-1]
}

// newAgentHandlerForTest wires a minimal AgentHandler with the
// recording fake. The other dependencies are nil because the
// handlers under test never reach for them on the success path.
func newAgentHandlerForTest(t *testing.T) (*AgentHandler, *fakeEnqueuer) {
	t.Helper()
	fake := &fakeEnqueuer{}
	h := &AgentHandler{
		aqClient: fake,
		logger:   slog.Default(),
	}
	return h, fake
}

// =============================================================================
// handleHeartbeat
// =============================================================================

func TestHandleHeartbeat_EnqueuesDeviceHeartbeat(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleHeartbeat(context.Background(), "dev-1", &pm.Heartbeat{}))

	last := fake.lastCall(t)
	assert.Equal(t, "control", last.queue)
	assert.Equal(t, taskqueue.TypeDeviceHeartbeat, last.taskType)
	payload, ok := last.payload.(taskqueue.DeviceHeartbeatPayload)
	require.True(t, ok, "payload type should be DeviceHeartbeatPayload, got %T", last.payload)
	assert.Equal(t, "dev-1", payload.DeviceID)
}

func TestHandleHeartbeat_PropagatesEnqueueError(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)
	fake.err = errors.New("valkey unavailable")

	err := h.handleHeartbeat(context.Background(), "dev-1", &pm.Heartbeat{})
	require.Error(t, err, "transport-level enqueue failure must propagate; the bidi stream loop relies on this to fail-close")
}

// =============================================================================
// handleActionResult — input validation (missing/empty action ID)
// =============================================================================

func TestHandleActionResult_NilActionID_RejectsBeforeEnqueue(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	err := h.handleActionResult(context.Background(), "dev-1", &pm.ActionResult{ActionId: nil})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing action ID")
	assert.Empty(t, fake.recorded, "validation failure must NOT enqueue — would persist a half-typed event")
}

func TestHandleActionResult_EmptyActionID_RejectsBeforeEnqueue(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	err := h.handleActionResult(context.Background(), "dev-1", &pm.ActionResult{ActionId: &pm.ActionId{Value: ""}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty action ID")
	assert.Empty(t, fake.recorded)
}

// =============================================================================
// handleOutputChunk
// =============================================================================

func TestHandleOutputChunk_EmptyExecutionID_Rejected(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	err := h.handleOutputChunk(context.Background(), "dev-1", &pm.OutputChunk{ExecutionId: ""})
	require.Error(t, err)
	assert.Empty(t, fake.recorded)
}

func TestHandleOutputChunk_StdoutHappyPath(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleOutputChunk(context.Background(), "dev-1", &pm.OutputChunk{
		ExecutionId: "exec-1",
		Stream:      pm.OutputStreamType_OUTPUT_STREAM_TYPE_STDOUT,
		Data:        []byte("hello"),
		Sequence:    7,
	}))

	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeExecutionOutputChunk, last.taskType)
	payload, ok := last.payload.(taskqueue.ExecutionOutputChunkPayload)
	require.True(t, ok)
	assert.Equal(t, "dev-1", payload.DeviceID)
	assert.Equal(t, "exec-1", payload.ExecutionID)
	assert.Equal(t, "stdout", payload.Stream)
	assert.Equal(t, "hello", payload.Data)
	assert.Equal(t, int64(7), payload.Sequence)
}

func TestHandleOutputChunk_StderrStreamMapped(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleOutputChunk(context.Background(), "dev-1", &pm.OutputChunk{
		ExecutionId: "exec-1",
		Stream:      pm.OutputStreamType_OUTPUT_STREAM_TYPE_STDERR,
		Data:        []byte("oops"),
	}))

	payload := fake.lastCall(t).payload.(taskqueue.ExecutionOutputChunkPayload)
	assert.Equal(t, "stderr", payload.Stream,
		"OUTPUT_STREAM_TYPE_STDERR enum must map to the stored 'stderr' string the projector keys on")
}

// =============================================================================
// handleQueryResult
// =============================================================================

func TestHandleQueryResult_EnqueuesWithMarshalledRows(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleQueryResult("dev-1", &pm.OSQueryResult{
		QueryId: "q-1",
		Success: true,
		Rows: []*pm.OSQueryRow{
			{Data: map[string]string{"name": "alice", "uid": "1000"}},
			{Data: map[string]string{"name": "bob", "uid": "1001"}},
		},
	}))

	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeOSQueryResult, last.taskType)
	payload := last.payload.(taskqueue.OSQueryResultPayload)
	assert.Equal(t, "dev-1", payload.DeviceID)
	assert.Equal(t, "q-1", payload.QueryID)
	assert.True(t, payload.Success)

	var rows []map[string]string
	require.NoError(t, json.Unmarshal(payload.RowsJSON, &rows))
	require.Len(t, rows, 2)
	assert.Equal(t, "alice", rows[0]["name"])
	assert.Equal(t, "bob", rows[1]["name"])
}

func TestHandleQueryResult_EmptyRows_DecodesToEmptySlice(t *testing.T) {
	// Pin the behaviour for empty Rows: the handler currently emits
	// JSON `null` (because `json.Marshal` of a nil slice is `null`),
	// which the control inbox decodes back to a nil slice. Either
	// `null` or `[]` is acceptable as long as the round-trip yields
	// an empty slice; the test asserts the round-trip not the wire
	// shape so a future "always-emit-[]" tightening doesn't break.
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleQueryResult("dev-1", &pm.OSQueryResult{
		QueryId: "q-1",
		Success: true,
		Rows:    nil,
	}))

	payload := fake.lastCall(t).payload.(taskqueue.OSQueryResultPayload)
	var rows []map[string]string
	require.NoError(t, json.Unmarshal(payload.RowsJSON, &rows))
	assert.Empty(t, rows, "empty Rows must round-trip through valid JSON to an empty slice on the inbox side")
}

// =============================================================================
// handleInventory
// =============================================================================

func TestHandleInventory_EnqueuesEachTable(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleInventory("dev-1", &pm.DeviceInventory{
		Tables: []*pm.InventoryTable{
			{
				TableName: "os_version",
				Rows: []*pm.OSQueryRow{
					{Data: map[string]string{"name": "Fedora", "version": "44"}},
				},
			},
			{
				TableName: "kernel_info",
				Rows: []*pm.OSQueryRow{
					{Data: map[string]string{"version": "7.0.4"}},
				},
			},
		},
	}))

	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeInventoryUpdate, last.taskType)
	payload := last.payload.(taskqueue.InventoryUpdatePayload)
	assert.Equal(t, "dev-1", payload.DeviceID)
	require.Len(t, payload.Tables, 2)
	assert.Equal(t, "os_version", payload.Tables[0].TableName)
	assert.Equal(t, "kernel_info", payload.Tables[1].TableName)
}

// =============================================================================
// handleSecurityAlert
// =============================================================================

func TestHandleSecurityAlert_EnqueuesAlert(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleSecurityAlert(context.Background(), "dev-1", &pm.SecurityAlert{
		Type:    pm.SecurityAlertType_SECURITY_ALERT_TYPE_INVALID_CERTIFICATE,
		Message: "header signature mismatch",
		Details: map[string]string{"slot": "1"},
	}))

	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeSecurityAlert, last.taskType)
	payload := last.payload.(taskqueue.SecurityAlertPayload)
	assert.Equal(t, "dev-1", payload.DeviceID)
	assert.Equal(t, "header signature mismatch", payload.Message)
	assert.Equal(t, "1", payload.Details["slot"])
	assert.NotEmpty(t, payload.AlertType, "alert type must be stringified, not int")
}

// =============================================================================
// handleRevokeLuksResult
// =============================================================================

func TestHandleRevokeLuksResult_EnqueuesResult(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleRevokeLuksResult("dev-1", &pm.RevokeLuksDeviceKeyResult{
		ActionId: "act-1",
		Success:  false,
		Error:    "slot in use",
	}))

	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeRevokeLuksDeviceKeyResult, last.taskType)
	payload := last.payload.(taskqueue.RevokeLuksDeviceKeyResultPayload)
	assert.Equal(t, "dev-1", payload.DeviceID)
	assert.Equal(t, "act-1", payload.ActionID)
	assert.False(t, payload.Success)
	assert.Equal(t, "slot in use", payload.Error)
}

// =============================================================================
// handleLogQueryResult
// =============================================================================

func TestHandleLogQueryResult_EnqueuesLogs(t *testing.T) {
	h, fake := newAgentHandlerForTest(t)

	require.NoError(t, h.handleLogQueryResult("dev-1", &pm.LogQueryResult{
		QueryId: "q-1",
		Success: true,
		Logs:    "line one\nline two",
	}))

	last := fake.lastCall(t)
	assert.Equal(t, taskqueue.TypeLogQueryResult, last.taskType)
	payload := last.payload.(taskqueue.LogQueryResultPayload)
	assert.Equal(t, "dev-1", payload.DeviceID)
	assert.Equal(t, "q-1", payload.QueryID)
	assert.True(t, payload.Success)
	assert.Equal(t, "line one\nline two", payload.Logs)
}

// =============================================================================
// Compile-time guard: fakeEnqueuer must satisfy taskqueue.Enqueuer
// =============================================================================

var _ taskqueue.Enqueuer = (*fakeEnqueuer)(nil)

// Belt-and-suspenders: prevent connect import elimination if the
// test surface evolves to drop the only direct connect reference.
var _ = connect.CodeOf
