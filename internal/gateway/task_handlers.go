package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// TaskHandlerFactory creates per-device Asynq ServeMux instances.
//
// taskSigner is the HMAC signer that verifies the Asynq envelope on
// every dequeue (audit F-02). It must match the key configured on
// control so the wrapper produced by Client.EnqueueToDevice
// round-trips cleanly. A nil signer disables verification — tests
// only; production wiring in cmd/gateway/main.go refuses an empty
// PM_TASK_SIGNING_KEY.
type messageSender interface {
	Send(deviceID string, msg *pm.ServerMessage) error
}

type TaskHandlerFactory struct {
	manager    messageSender
	taskSigner *taskqueue.Signer
	logger     *slog.Logger
}

// NewTaskHandlerFactory creates a new factory.
func NewTaskHandlerFactory(manager *connection.Manager, taskSigner *taskqueue.Signer, logger *slog.Logger) *TaskHandlerFactory {
	return &TaskHandlerFactory{
		manager:    manager,
		taskSigner: taskSigner,
		logger:     logger,
	}
}

// NewMux returns a handler factory function for DeviceWorkerManager.
func (f *TaskHandlerFactory) NewMux(deviceID string) *asynq.ServeMux {
	h := &deviceTaskHandler{
		deviceID: deviceID,
		manager:  f.manager,
		logger:   f.logger.With("device_id", deviceID),
	}

	mux := asynq.NewServeMux()
	if f.taskSigner != nil {
		mux.Use(f.taskSigner.VerifyMiddleware())
	}
	mux.HandleFunc(taskqueue.TypeActionDispatch, h.handleActionDispatch)
	mux.HandleFunc(taskqueue.TypeOSQueryDispatch, h.handleOSQueryDispatch)
	mux.HandleFunc(taskqueue.TypeInventoryRequest, h.handleInventoryRequest)
	mux.HandleFunc(taskqueue.TypeRevokeLuksDeviceKey, h.handleRevokeLuksDeviceKey)
	mux.HandleFunc(taskqueue.TypeLogQueryDispatch, h.handleLogQueryDispatch)
	return mux
}

// deviceTaskHandler processes tasks from a specific device's queue.
type deviceTaskHandler struct {
	deviceID string
	manager  messageSender
	logger   *slog.Logger
}

func (h *deviceTaskHandler) handleActionDispatch(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.ActionDispatchPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal action dispatch: %w", err)
	}

	h.logger.Info("dispatching action to agent",
		"execution_id", payload.ExecutionID,
	)

	// Clean break (action-signing rewrite): the control server already
	// built and signed the full SignedActionEnvelope. The gateway no
	// longer reconstructs a typed Action or re-serialises params — that
	// re-marshal was the exact gap a compromised gateway could exploit to
	// rewrite the executed action under a still-valid signature. Forward
	// the signed bytes + signature verbatim; the agent verifies the
	// signature over THESE bytes and unmarshals THESE bytes to execute.
	//
	// Fail closed if the producer somehow enqueued an empty envelope or
	// signature (a wiring bug) rather than sending the agent a message it
	// would reject anyway.
	if len(payload.EnvelopeBytes) == 0 {
		return fmt.Errorf("action dispatch %s: empty envelope bytes", payload.ExecutionID)
	}
	if len(payload.Signature) == 0 {
		return fmt.Errorf("action dispatch %s: empty signature", payload.ExecutionID)
	}

	// Wrap in ServerMessage
	msg := &pm.ServerMessage{
		Id: ulid.Make().String(),
		Payload: &pm.ServerMessage_Action{
			Action: &pm.ActionDispatch{
				Envelope:  payload.EnvelopeBytes,
				Signature: payload.Signature,
			},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send action to agent: %w", err)
	}

	h.logger.Info("action dispatched successfully",
		"execution_id", payload.ExecutionID,
	)
	return nil
}

func (h *deviceTaskHandler) handleOSQueryDispatch(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.OSQueryDispatchPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal osquery dispatch: %w", err)
	}

	// Relay the control-signed message verbatim: build the wire OSQuery from
	// the shared ToProto (so its bytes match what the control server signed)
	// and attach the carried signature. The gateway NEVER originates a
	// signature — it only forwards (WS4).
	query := payload.ToProto()
	query.Signature = payload.Signature
	msg := &pm.ServerMessage{
		Id: ulid.Make().String(),
		Payload: &pm.ServerMessage_Query{
			Query: query,
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send osquery to agent: %w", err)
	}

	h.logger.Info("osquery dispatched", "query_id", payload.QueryID, "table", payload.Table)
	return nil
}

func (h *deviceTaskHandler) handleInventoryRequest(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.InventoryRequestPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal inventory request: %w", err)
	}

	// Relay the control-signed request verbatim (WS4): carry query_id +
	// signature onto the wire so the agent verifies before running osquery.
	req := payload.ToProto()
	req.Signature = payload.Signature
	msg := &pm.ServerMessage{
		Id: ulid.Make().String(),
		Payload: &pm.ServerMessage_RequestInventory{
			RequestInventory: req,
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send inventory request to agent: %w", err)
	}

	h.logger.Info("inventory request dispatched", "query_id", payload.QueryID)
	return nil
}

func (h *deviceTaskHandler) handleRevokeLuksDeviceKey(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.RevokeLuksDeviceKeyPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal revoke luks: %w", err)
	}

	// Relay the control-signed revocation verbatim (WS4): carry the signature
	// binding action_id onto the wire so the agent verifies before the wipe.
	revoke := payload.ToProto()
	revoke.Signature = payload.Signature
	msg := &pm.ServerMessage{
		Id: ulid.Make().String(),
		Payload: &pm.ServerMessage_RevokeLuksDeviceKey{
			RevokeLuksDeviceKey: revoke,
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send LUKS revocation to agent: %w", err)
	}

	h.logger.Info("LUKS device key revocation dispatched", "action_id", payload.ActionID)
	return nil
}

func (h *deviceTaskHandler) handleLogQueryDispatch(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.LogQueryDispatchPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal log query dispatch: %w", err)
	}

	// Relay the control-signed log query verbatim (WS4): build the wire
	// LogQuery from the shared ToProto (matching the signed bytes) and attach
	// the carried signature. Gateway never originates it.
	query := payload.ToProto()
	query.Signature = payload.Signature
	msg := &pm.ServerMessage{
		Id: ulid.Make().String(),
		Payload: &pm.ServerMessage_LogQuery{
			LogQuery: query,
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send log query to agent: %w", err)
	}

	h.logger.Info("log query dispatched", "query_id", payload.QueryID, "unit", payload.Unit)
	return nil
}
