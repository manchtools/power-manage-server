package control_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/control"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// fakeSigner records Sign calls so tests can verify the signer
// was invoked with the correct arguments (execution ID, not action ID).
type fakeSigner struct {
	mu    sync.Mutex
	calls []fakeSignCall
}

type fakeSignCall struct {
	ActionID   string
	ActionType int32
	ParamsJSON []byte
}

func (s *fakeSigner) Sign(actionID string, actionType int32, paramsJSON []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, fakeSignCall{
		ActionID:   actionID,
		ActionType: actionType,
		ParamsJSON: append([]byte(nil), paramsJSON...),
	})
	return []byte("fake-sig-for-" + actionID), nil
}

func (s *fakeSigner) getCalls() []fakeSignCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]fakeSignCall(nil), s.calls...)
}

func newTask(t *testing.T, typeName string, payload any) *asynq.Task {
	t.Helper()
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	return asynq.NewTask(typeName, data)
}

func TestHandleDeviceHeartbeat(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "heartbeat-host")

	task := newTask(t, taskqueue.TypeDeviceHeartbeat, taskqueue.DeviceHeartbeatPayload{
		DeviceID:      deviceID,
		AgentVersion:  "2.0.0",
		UptimeSeconds: 3600,
		CpuPercent:    25.5,
		MemoryPercent: 50.0,
		DiskPercent:   70.0,
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	// Verify the device's last_seen was updated via the projection
	device, err := st.Queries().GetDeviceByID(context.Background(), db.GetDeviceByIDParams{ID: deviceID})
	require.NoError(t, err)
	assert.NotNil(t, device.LastSeenAt)
}

func TestHandleDeviceHeartbeat_DeletedDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "deleted-heartbeat-host")

	// Delete the device
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceDeleted",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeDeviceHeartbeat, taskqueue.DeviceHeartbeatPayload{
		DeviceID:     deviceID,
		AgentVersion: "2.0.0",
	})

	// Should succeed silently (skip deleted device)
	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleSecurityAlert(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "alert-host")

	task := newTask(t, taskqueue.TypeSecurityAlert, taskqueue.SecurityAlertPayload{
		DeviceID:  deviceID,
		AlertType: "tamper_detected",
		Message:   "Agent binary modified",
		Details:   map[string]string{"path": "/usr/bin/pm-agent"},
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	// Verify the event was stored by checking the events table
	events, err := st.Queries().LoadStream(context.Background(), db.LoadStreamParams{
		StreamType: "device",
		StreamID:   deviceID,
	})
	require.NoError(t, err)

	found := false
	for _, e := range events {
		if e.EventType == "SecurityAlert" {
			found = true
			break
		}
	}
	assert.True(t, found, "SecurityAlert event should be stored")
}

func TestHandleExecutionResult_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "exec-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Test Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Create an execution via DispatchAction event
	executionID := testutil.NewID()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
			"executed_at":     time.Now().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	// Build action result with protojson
	result := &pm.ActionResult{
		ActionId:    &pm.ActionId{Value: executionID},
		Status:      pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		DurationMs:  1500,
		CompletedAt: timestamppb.Now(),
		Changed:     true,
		Compliant:   true,
		Output: &pm.CommandOutput{
			Stdout:   "hello world",
			ExitCode: 0,
		},
	}
	resultJSON, err := protojson.Marshal(result)
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:         deviceID,
		ActionResultJSON: resultJSON,
	})

	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	// Verify execution status was updated
	exec, err := st.Queries().GetExecutionByID(context.Background(), executionID)
	require.NoError(t, err)
	assert.Equal(t, "success", exec.Status)
}

func TestHandleExecutionResult_Failed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "exec-fail-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Fail Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	executionID := testutil.NewID()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
			"executed_at":     time.Now().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	result := &pm.ActionResult{
		ActionId:    &pm.ActionId{Value: executionID},
		Status:      pm.ExecutionStatus_EXECUTION_STATUS_FAILED,
		Error:       "command exited with code 1",
		DurationMs:  500,
		CompletedAt: timestamppb.Now(),
		Output: &pm.CommandOutput{
			Stderr:   "error: not found",
			ExitCode: 1,
		},
	}
	resultJSON, err := protojson.Marshal(result)
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:         deviceID,
		ActionResultJSON: resultJSON,
	})

	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	exec, err := st.Queries().GetExecutionByID(context.Background(), executionID)
	require.NoError(t, err)
	assert.Equal(t, "failed", exec.Status)
}

func TestHandleExecutionResult_CreatesExecutionIfNotExists(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "offline-exec-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Offline Action", int(pm.ActionType_ACTION_TYPE_SHELL))

	// Use the actionID as the result ID (not an existing execution ID).
	// The handler should create a new execution.
	result := &pm.ActionResult{
		ActionId:    &pm.ActionId{Value: actionID},
		Status:      pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		DurationMs:  200,
		CompletedAt: timestamppb.Now(),
	}
	resultJSON, err := protojson.Marshal(result)
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:         deviceID,
		ActionResultJSON: resultJSON,
	})

	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleExecutionOutputChunk(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "chunk-host")
	executionID := testutil.NewID()

	// Create the execution first
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       testutil.CreateTestAction(t, st, adminID, "Chunk Test", int(pm.ActionType_ACTION_TYPE_SHELL)),
			"action_type":     int(pm.ActionType_ACTION_TYPE_SHELL),
			"desired_state":   0,
			"params":          map[string]any{},
			"timeout_seconds": 300,
			"executed_at":     time.Now().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeExecutionOutputChunk, taskqueue.ExecutionOutputChunkPayload{
		DeviceID:    deviceID,
		ExecutionID: executionID,
		Stream:      "stdout",
		Data:        "line 1 of output\n",
		Sequence:    1,
	})

	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleRevokeLuksDeviceKeyResult_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "luks-host")
	actionID := testutil.NewID()

	task := newTask(t, taskqueue.TypeRevokeLuksDeviceKeyResult, taskqueue.RevokeLuksDeviceKeyResultPayload{
		DeviceID: deviceID,
		ActionID: actionID,
		Success:  true,
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleRevokeLuksDeviceKeyResult_Failure(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "luks-fail-host")
	actionID := testutil.NewID()

	task := newTask(t, taskqueue.TypeRevokeLuksDeviceKeyResult, taskqueue.RevokeLuksDeviceKeyResultPayload{
		DeviceID: deviceID,
		ActionID: actionID,
		Success:  false,
		Error:    "device busy",
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

func TestHandleDeviceHello(t *testing.T) {
	st := testutil.SetupPostgres(t)
	// handleDeviceHello calls dispatchPendingActions which needs aqClient.
	// Passing nil is safe here because there are no pending executions to dispatch.
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "hello-host")

	task := newTask(t, taskqueue.TypeDeviceHello, taskqueue.DeviceHelloPayload{
		DeviceID:     deviceID,
		Hostname:     "hello-host-updated",
		AgentVersion: "3.0.0",
	})

	err := mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)

	// Verify the heartbeat event was recorded (updates last_seen)
	device, err := st.Queries().GetDeviceByID(context.Background(), db.GetDeviceByIDParams{ID: deviceID})
	require.NoError(t, err)
	assert.NotNil(t, device.LastSeenAt)
}

func TestHandleDeviceHello_DeletedDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	worker := control.NewInboxWorker(st, nil, nil, slog.Default())
	mux := worker.NewMux()

	deviceID := testutil.CreateTestDevice(t, st, "hello-deleted-host")

	// Delete the device
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceDeleted",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	task := newTask(t, taskqueue.TypeDeviceHello, taskqueue.DeviceHelloPayload{
		DeviceID:     deviceID,
		Hostname:     "hello-deleted-host",
		AgentVersion: "1.0.0",
	})

	// Should succeed silently (skip deleted device)
	err = mux.ProcessTask(context.Background(), task)
	require.NoError(t, err)
}

// TestDispatchPendingActions_ReSignsWithExecutionID verifies that when
// dispatchPendingActions dispatches a pending execution, it re-signs
// the action payload with the execution ID (not the original action ID).
// This is critical because the gateway sets Action.Id = executionID,
// so the agent verifies the signature against the execution ID.
func TestDispatchPendingActions_ReSignsWithExecutionID(t *testing.T) {
	st := testutil.SetupPostgres(t)
	mr := miniredis.RunT(t)
	aqClient := taskqueue.NewClient(mr.Addr(), "", 0)
	defer aqClient.Close()

	signer := &fakeSigner{}
	worker := control.NewInboxWorker(st, aqClient, signer, slog.Default())
	mux := worker.NewMux()

	ctx := context.Background()

	// Setup: create user, device, action, and a pending execution
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "resign-host")
	actionID := testutil.CreateTestAction(t, st, adminID, "Resign Test", int(pm.ActionType_ACTION_TYPE_USER))

	// Sign the action with the action ID (as the real system does)
	err := st.Queries().UpdateActionSignature(ctx, db.UpdateActionSignatureParams{
		ID:              actionID,
		Signature:       []byte("original-sig-for-action"),
		ParamsCanonical: []byte(`{"username":"test"}`),
	})
	require.NoError(t, err)

	// Create a pending execution for this device+action
	executionID := testutil.NewID()
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  "ExecutionCreated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     int(pm.ActionType_ACTION_TYPE_USER),
			"desired_state":   0,
			"params":          map[string]any{"username": "test"},
			"timeout_seconds": 300,
			"executed_at":     time.Now().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	// Verify execution is pending
	exec, err := st.Queries().GetExecutionByID(ctx, executionID)
	require.NoError(t, err)
	assert.Equal(t, "pending", exec.Status)

	// Trigger device hello — this calls dispatchPendingActions internally
	task := newTask(t, taskqueue.TypeDeviceHello, taskqueue.DeviceHelloPayload{
		DeviceID:     deviceID,
		Hostname:     "resign-host",
		AgentVersion: "1.0.0",
	})
	err = mux.ProcessTask(ctx, task)
	require.NoError(t, err)

	// Verify the signer was called with the EXECUTION ID, not the action ID,
	// and with the correct canonical params and action type.
	calls := signer.getCalls()
	require.Len(t, calls, 1, "signer should be called exactly once for the pending execution")
	assert.Equal(t, executionID, calls[0].ActionID,
		"signer must be called with the execution ID (not action ID %s)", actionID)
	assert.Equal(t, int32(pm.ActionType_ACTION_TYPE_USER), calls[0].ActionType)
	assert.JSONEq(t, `{"username":"test"}`, string(calls[0].ParamsJSON),
		"signer must receive the canonical params from the action")
}
