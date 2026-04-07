package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// TaskHandlerFactory creates per-device Asynq ServeMux instances.
type TaskHandlerFactory struct {
	manager *connection.Manager
	logger  *slog.Logger
}

// NewTaskHandlerFactory creates a new factory.
func NewTaskHandlerFactory(manager *connection.Manager, logger *slog.Logger) *TaskHandlerFactory {
	return &TaskHandlerFactory{
		manager: manager,
		logger:  logger,
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
	manager  *connection.Manager
	logger   *slog.Logger
}

func (h *deviceTaskHandler) handleActionDispatch(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.ActionDispatchPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal action dispatch: %w", err)
	}

	h.logger.Info("dispatching action to agent",
		"execution_id", payload.ExecutionID,
		"action_type", payload.ActionType,
	)

	// Build Action message
	action := &pm.Action{
		Id:              &pm.ActionId{Value: payload.ExecutionID},
		Type:            pm.ActionType(payload.ActionType),
		DesiredState:    pm.DesiredState(payload.DesiredState),
		TimeoutSeconds:  payload.TimeoutSeconds,
		Signature:       payload.Signature,
		ParamsCanonical: payload.ParamsCanonical,
	}

	// Parse params
	if len(payload.Params) > 0 && string(payload.Params) != "null" && string(payload.Params) != "{}" {
		actionparams.PopulateAction(action, payload.ActionType, payload.Params)
	}

	// Wrap in ServerMessage
	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_Action{
			Action: &pm.ActionDispatch{
				Action: action,
			},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send action to agent: %w", err)
	}

	h.logger.Info("action dispatched successfully",
		"execution_id", payload.ExecutionID,
		"action_type", pm.ActionType(payload.ActionType).String(),
	)
	return nil
}

func (h *deviceTaskHandler) handleOSQueryDispatch(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.OSQueryDispatchPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal osquery dispatch: %w", err)
	}

	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_Query{
			Query: &pm.OSQuery{
				QueryId: payload.QueryID,
				Table:   payload.Table,
				Columns: payload.Columns,
				Limit:   payload.Limit,
				RawSql:  payload.RawSQL,
			},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send osquery to agent: %w", err)
	}

	h.logger.Info("osquery dispatched", "query_id", payload.QueryID, "table", payload.Table)
	return nil
}

func (h *deviceTaskHandler) handleInventoryRequest(_ context.Context, _ *asynq.Task) error {
	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_RequestInventory{
			RequestInventory: &pm.RequestInventory{},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send inventory request to agent: %w", err)
	}

	h.logger.Info("inventory request dispatched")
	return nil
}

func (h *deviceTaskHandler) handleRevokeLuksDeviceKey(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.RevokeLuksDeviceKeyPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal revoke luks: %w", err)
	}

	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_RevokeLuksDeviceKey{
			RevokeLuksDeviceKey: &pm.RevokeLuksDeviceKey{
				ActionId: payload.ActionID,
			},
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

	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_LogQuery{
			LogQuery: &pm.LogQuery{
				QueryId:  payload.QueryID,
				Lines:    payload.Lines,
				Unit:     payload.Unit,
				Since:    payload.Since,
				Until:    payload.Until,
				Priority: payload.Priority,
				Grep:     payload.Grep,
				Kernel:   payload.Kernel,
			},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send log query to agent: %w", err)
	}

	h.logger.Info("log query dispatched", "query_id", payload.QueryID, "unit", payload.Unit)
	return nil
}

