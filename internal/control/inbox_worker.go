package control

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// InboxWorker processes tasks from the control:inbox queue.
// It replaces the PostgreSQL LISTEN-based Handler for gateway → control messages.
type InboxWorker struct {
	store    *store.Store
	aqClient *taskqueue.Client
	logger   *slog.Logger
}

// NewInboxWorker creates a new inbox worker.
func NewInboxWorker(st *store.Store, aqClient *taskqueue.Client, logger *slog.Logger) *InboxWorker {
	return &InboxWorker{
		store:    st,
		aqClient: aqClient,
		logger:   logger,
	}
}

// NewMux returns an Asynq ServeMux with handlers for all control inbox task types.
func (w *InboxWorker) NewMux() *asynq.ServeMux {
	mux := asynq.NewServeMux()
	mux.HandleFunc(taskqueue.TypeDeviceHello, w.handleDeviceHello)
	mux.HandleFunc(taskqueue.TypeDeviceHeartbeat, w.handleDeviceHeartbeat)
	mux.HandleFunc(taskqueue.TypeExecutionResult, w.handleExecutionResult)
	mux.HandleFunc(taskqueue.TypeExecutionOutputChunk, w.handleExecutionOutputChunk)
	mux.HandleFunc(taskqueue.TypeOSQueryResult, w.handleOSQueryResult)
	mux.HandleFunc(taskqueue.TypeInventoryUpdate, w.handleInventoryUpdate)
	mux.HandleFunc(taskqueue.TypeSecurityAlert, w.handleSecurityAlert)
	mux.HandleFunc(taskqueue.TypeRevokeLuksDeviceKeyResult, w.handleRevokeLuksDeviceKeyResult)
	return mux
}

func (w *InboxWorker) handleDeviceHello(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.DeviceHelloPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal device hello: %w", err)
	}

	logger := w.logger.With("device_id", payload.DeviceID, "hostname", payload.Hostname)
	logger.Info("agent connected", "agent_version", payload.AgentVersion)

	// Emit DeviceHeartbeat event
	if err := w.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   payload.DeviceID,
		EventType:  "DeviceHeartbeat",
		Data: map[string]any{
			"agent_version": payload.AgentVersion,
			"hostname":      payload.Hostname,
		},
		ActorType: "device",
		ActorID:   payload.DeviceID,
	}); err != nil {
		logger.Error("failed to append heartbeat event", "error", err)
		return err
	}

	// Dispatch pending actions to the device via Asynq
	w.dispatchPendingActions(ctx, payload.DeviceID, logger)
	return nil
}

func (w *InboxWorker) handleDeviceHeartbeat(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.DeviceHeartbeatPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal device heartbeat: %w", err)
	}

	data := map[string]any{}
	if payload.AgentVersion != "" {
		data["agent_version"] = payload.AgentVersion
	}
	if payload.UptimeSeconds > 0 {
		data["uptime_seconds"] = payload.UptimeSeconds
	}
	if payload.CpuPercent > 0 {
		data["cpu_percent"] = payload.CpuPercent
	}
	if payload.MemoryPercent > 0 {
		data["memory_percent"] = payload.MemoryPercent
	}
	if payload.DiskPercent > 0 {
		data["disk_percent"] = payload.DiskPercent
	}

	return w.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   payload.DeviceID,
		EventType:  "DeviceHeartbeat",
		Data:       data,
		ActorType:  "device",
		ActorID:    payload.DeviceID,
	})
}

func (w *InboxWorker) handleExecutionResult(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.ExecutionResultPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal execution result: %w", err)
	}

	// The ActionResultJSON is a protojson-encoded pm.ActionResult.
	// We deserialize it to extract the fields and reconstruct the events,
	// mirroring the logic from handler/agent.go handleAgentMessage ActionResult case.
	var resultData struct {
		ActionId        struct{ Value string } `json:"actionId"`
		Status          string                 `json:"status"`
		DurationMs      int64                  `json:"durationMs"`
		Error           string                 `json:"error"`
		Changed         bool                   `json:"changed"`
		Compliant       bool                   `json:"compliant"`
		CompletedAt     string                 `json:"completedAt"`
		Output          *struct {
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
			ExitCode int32  `json:"exitCode"`
		} `json:"output"`
		DetectionOutput *struct {
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
			ExitCode int32  `json:"exitCode"`
		} `json:"detectionOutput"`
	}
	if err := json.Unmarshal(payload.ActionResultJSON, &resultData); err != nil {
		return fmt.Errorf("unmarshal action result json: %w", err)
	}

	deviceID := payload.DeviceID
	resultID := resultData.ActionId.Value
	if resultID == "" {
		return fmt.Errorf("action result missing action ID")
	}

	logger := w.logger.With("device_id", deviceID, "result_id", resultID)

	// Determine execution ID and action ID
	var executionID, actionID string
	var needsCreate bool

	existingExec, err := w.store.Queries().GetExecutionByID(ctx, resultID)
	if err == nil {
		executionID = existingExec.ID
		if existingExec.ActionID != nil {
			actionID = *existingExec.ActionID
		}
		needsCreate = false
	} else {
		actionID = resultID
		executionID = ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
		needsCreate = true
	}

	// Calculate timestamps
	var executedAt, completedAt time.Time
	if resultData.CompletedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, resultData.CompletedAt); err == nil {
			completedAt = t
			executedAt = completedAt.Add(-time.Duration(resultData.DurationMs) * time.Millisecond)
		}
	}
	if completedAt.IsZero() {
		completedAt = time.Now()
		executedAt = completedAt.Add(-time.Duration(resultData.DurationMs) * time.Millisecond)
	}

	if needsCreate {
		action, err := w.store.Queries().GetActionByID(ctx, actionID)
		if err != nil {
			logger.Warn("could not look up action", "error", err)
			action.ActionType = 0
			action.Params = nil
			action.TimeoutSeconds = 300
		}

		createdData := map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"action_type":     action.ActionType,
			"desired_state":   0,
			"params":          json.RawMessage(action.Params),
			"timeout_seconds": action.TimeoutSeconds,
			"executed_at":     executedAt.Format(time.RFC3339Nano),
		}
		if err := w.store.AppendEvent(ctx, store.Event{
			StreamType: "execution",
			StreamID:   executionID,
			EventType:  "ExecutionCreated",
			Data:       createdData,
			ActorType:  "device",
			ActorID:    deviceID,
		}); err != nil {
			return fmt.Errorf("create execution event: %w", err)
		}
	}

	// Map status string to event type
	var eventType string
	var data map[string]any

	switch resultData.Status {
	case "EXECUTION_STATUS_SUCCESS":
		eventType = "ExecutionCompleted"
		data = map[string]any{
			"duration_ms":  resultData.DurationMs,
			"completed_at": completedAt.Format(time.RFC3339Nano),
			"changed":      resultData.Changed,
			"compliant":    resultData.Compliant,
		}
		if resultData.Output != nil {
			data["output"] = map[string]any{
				"stdout":    resultData.Output.Stdout,
				"stderr":    resultData.Output.Stderr,
				"exit_code": resultData.Output.ExitCode,
			}
		}
		if resultData.DetectionOutput != nil {
			data["detection_output"] = map[string]any{
				"stdout":    resultData.DetectionOutput.Stdout,
				"stderr":    resultData.DetectionOutput.Stderr,
				"exit_code": resultData.DetectionOutput.ExitCode,
			}
		}

	case "EXECUTION_STATUS_FAILED":
		eventType = "ExecutionFailed"
		data = map[string]any{
			"error":        resultData.Error,
			"duration_ms":  resultData.DurationMs,
			"completed_at": completedAt.Format(time.RFC3339Nano),
			"changed":      resultData.Changed,
			"compliant":    resultData.Compliant,
		}
		if resultData.Output != nil {
			data["output"] = map[string]any{
				"stdout":    resultData.Output.Stdout,
				"stderr":    resultData.Output.Stderr,
				"exit_code": resultData.Output.ExitCode,
			}
		}
		if resultData.DetectionOutput != nil {
			data["detection_output"] = map[string]any{
				"stdout":    resultData.DetectionOutput.Stdout,
				"stderr":    resultData.DetectionOutput.Stderr,
				"exit_code": resultData.DetectionOutput.ExitCode,
			}
		}

	case "EXECUTION_STATUS_RUNNING":
		eventType = "ExecutionStarted"
		data = map[string]any{}

	case "EXECUTION_STATUS_TIMEOUT":
		eventType = "ExecutionTimedOut"
		data = map[string]any{
			"error":        resultData.Error,
			"duration_ms":  resultData.DurationMs,
			"completed_at": completedAt.Format(time.RFC3339Nano),
		}
		if resultData.Output != nil {
			data["output"] = map[string]any{
				"stdout":    resultData.Output.Stdout,
				"stderr":    resultData.Output.Stderr,
				"exit_code": resultData.Output.ExitCode,
			}
		}

	case "EXECUTION_STATUS_SKIPPED":
		eventType = "ExecutionSkipped"
		data = map[string]any{}
		if resultData.Error != "" {
			data["reason"] = resultData.Error
		}

	default:
		return fmt.Errorf("unknown execution status: %s", resultData.Status)
	}

	if err := w.store.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   executionID,
		EventType:  eventType,
		Data:       data,
		ActorType:  "device",
		ActorID:    deviceID,
	}); err != nil {
		return fmt.Errorf("append execution event: %w", err)
	}

	// Emit compliance event for actions with is_compliance=true
	if resultData.DetectionOutput != nil && actionID != "" {
		actionName := ""
		isCompliance := false
		if action, err := w.store.Queries().GetActionByID(ctx, actionID); err == nil {
			actionName = action.Name
			var params map[string]any
			if json.Unmarshal(action.Params, &params) == nil {
				isCompliance, _ = params["isCompliance"].(bool)
			}
		}
		if isCompliance {
			complianceData := map[string]any{
				"device_id":   deviceID,
				"action_id":   actionID,
				"action_name": actionName,
				"compliant":   resultData.Compliant,
				"detection_output": map[string]any{
					"stdout":    resultData.DetectionOutput.Stdout,
					"stderr":    resultData.DetectionOutput.Stderr,
					"exit_code": resultData.DetectionOutput.ExitCode,
				},
			}
			if err := w.store.AppendEvent(ctx, store.Event{
				StreamType: "compliance",
				StreamID:   deviceID + "_" + actionID,
				EventType:  "ComplianceResultUpdated",
				Data:       complianceData,
				ActorType:  "device",
				ActorID:    deviceID,
			}); err != nil {
				logger.Error("failed to append compliance event", "error", err)
			}
		}
	}

	logger.Info("execution result recorded", "event_type", eventType)
	return nil
}

func (w *InboxWorker) handleExecutionOutputChunk(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.ExecutionOutputChunkPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal output chunk: %w", err)
	}

	return w.store.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   payload.ExecutionID,
		EventType:  "OutputChunk",
		Data: map[string]any{
			"stream":   payload.Stream,
			"data":     payload.Data,
			"sequence": payload.Sequence,
		},
		ActorType: "device",
		ActorID:   payload.DeviceID,
	})
}

func (w *InboxWorker) handleOSQueryResult(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.OSQueryResultPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal osquery result: %w", err)
	}

	w.logger.Info("received query result",
		"device_id", payload.DeviceID,
		"query_id", payload.QueryID,
		"success", payload.Success,
	)

	return w.store.Queries().CompleteOSQueryResult(ctx, db.CompleteOSQueryResultParams{
		QueryID: payload.QueryID,
		Success: payload.Success,
		Error:   payload.Error,
		Rows:    payload.RowsJSON,
	})
}

func (w *InboxWorker) handleInventoryUpdate(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.InventoryUpdatePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal inventory update: %w", err)
	}

	w.logger.Info("received device inventory",
		"device_id", payload.DeviceID,
		"tables", len(payload.Tables),
	)

	for _, table := range payload.Tables {
		if err := w.store.Queries().UpsertDeviceInventory(ctx, db.UpsertDeviceInventoryParams{
			DeviceID:  payload.DeviceID,
			TableName: table.TableName,
			Rows:      table.RowsJSON,
		}); err != nil {
			w.logger.Warn("failed to upsert inventory table",
				"device_id", payload.DeviceID,
				"table", table.TableName,
				"error", err,
			)
		}
	}

	return nil
}

func (w *InboxWorker) handleSecurityAlert(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.SecurityAlertPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal security alert: %w", err)
	}

	w.logger.Warn("received security alert from device",
		"device_id", payload.DeviceID,
		"alert_type", payload.AlertType,
		"message", payload.Message,
	)

	return w.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   payload.DeviceID,
		EventType:  "SecurityAlert",
		Data: map[string]any{
			"alert_type": payload.AlertType,
			"message":    payload.Message,
			"details":    payload.Details,
		},
		ActorType: "device",
		ActorID:   payload.DeviceID,
	})
}

func (w *InboxWorker) handleRevokeLuksDeviceKeyResult(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.RevokeLuksDeviceKeyResultPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal revoke luks result: %w", err)
	}

	w.logger.Info("received LUKS device key revocation result",
		"device_id", payload.DeviceID,
		"action_id", payload.ActionID,
		"success", payload.Success,
	)

	luksStreamID := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
	if payload.Success {
		return w.store.AppendEvent(ctx, store.Event{
			StreamType: "luks_key",
			StreamID:   luksStreamID,
			EventType:  "LuksDeviceKeyRevoked",
			Data: map[string]any{
				"device_id":  payload.DeviceID,
				"action_id":  payload.ActionID,
				"revoked_at": time.Now().Format(time.RFC3339),
			},
			ActorType: "device",
			ActorID:   payload.DeviceID,
		})
	}

	return w.store.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   luksStreamID,
		EventType:  "LuksDeviceKeyRevocationFailed",
		Data: map[string]any{
			"device_id": payload.DeviceID,
			"action_id": payload.ActionID,
			"error":     payload.Error,
			"failed_at": time.Now().Format(time.RFC3339),
		},
		ActorType: "device",
		ActorID:   payload.DeviceID,
	})
}

// dispatchPendingActions finds pending executions for a device and enqueues them
// to the device's Asynq queue. This mirrors the logic from Handler.dispatchPendingActions
// but uses Asynq instead of PostgreSQL NOTIFY.
func (w *InboxWorker) dispatchPendingActions(ctx context.Context, deviceID string, logger *slog.Logger) {
	logger.Debug("checking for pending executions")

	executions, err := w.store.Queries().ListPendingExecutionsForDevice(ctx, deviceID)
	if err != nil {
		logger.Error("failed to list pending executions", "error", err)
		return
	}

	logger.Debug("found pending executions", "count", len(executions))

	for _, exec := range executions {
		// Emit ExecutionDispatched event
		if err := w.store.AppendEvent(ctx, store.Event{
			StreamType: "execution",
			StreamID:   exec.ID,
			EventType:  "ExecutionDispatched",
			Data: map[string]any{
				"device_id": deviceID,
			},
			ActorType: "system",
			ActorID:   "dispatcher",
		}); err != nil {
			logger.Error("failed to append dispatch event", "error", err, "execution_id", exec.ID)
			continue
		}

		// Parse params from []byte to avoid base64 encoding
		var params json.RawMessage
		if len(exec.Params) > 0 {
			params = exec.Params
		}

		// Look up the action's signature if this execution references one
		var signature, paramsCanonical []byte
		if exec.ActionID != nil {
			if action, err := w.store.Queries().GetActionByID(ctx, *exec.ActionID); err == nil {
				signature = action.Signature
				paramsCanonical = action.ParamsCanonical
			}
		}

		// Enqueue action dispatch to device queue via Asynq
		if err := w.aqClient.EnqueueToDevice(deviceID, taskqueue.TypeActionDispatch, taskqueue.ActionDispatchPayload{
			ExecutionID:     exec.ID,
			ActionType:      exec.ActionType,
			DesiredState:    exec.DesiredState,
			Params:          params,
			TimeoutSeconds:  exec.TimeoutSeconds,
			Signature:       signature,
			ParamsCanonical: paramsCanonical,
		}); err != nil {
			logger.Error("failed to enqueue action dispatch", "error", err, "execution_id", exec.ID)
			continue
		}

		logger.Info("dispatched pending execution via Asynq",
			"execution_id", exec.ID,
			"action_type", exec.ActionType,
		)
	}
}
