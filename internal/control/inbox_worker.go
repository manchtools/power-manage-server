package control

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/dyngroupeval"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// InboxWorker processes tasks from the control:inbox queue.
// It replaces the PostgreSQL LISTEN-based Handler for gateway → control messages.
//
// signer follows the ca.ActionSigner contract: a nil signer disables
// signing (dev mode); dispatchPendingActions skips any execution
// referencing an action when signer is nil, since agents reject
// unsigned payloads.
//
// taskSigner is the HMAC signer for the Asynq envelope (audit F-02);
// NewMux wires it as a middleware so every handler sees an
// HMAC-verified payload before its JSON-unmarshal call. nil means
// "verification disabled" (tests only).
type InboxWorker struct {
	now        func() time.Time // clock seam; defaults to time.Now, overridden in tests
	store      *store.Store
	aqClient   *taskqueue.Client
	signer     ca.ActionSigner
	taskSigner *taskqueue.Signer
	logger     *slog.Logger
	// resolver looks up which gateway a device is currently live on, so
	// every device-origin handler can confine the task to that gateway
	// (registry.CheckDeviceGatewayBinding). nil = single-gateway / non-HA
	// deployment: the binding is documented-disabled there, exactly as on
	// the InternalService side (api/gateway_binding.go).
	resolver registry.DeviceGatewayLookup
}

// NewInboxWorker creates a new inbox worker. resolver is the
// device→gateway routing lookup used to bind device-origin tasks to the
// gateway the device is live on; pass nil in single-gateway deployments
// where the binding is not enforced.
func NewInboxWorker(st *store.Store, aqClient *taskqueue.Client, signer ca.ActionSigner, taskSigner *taskqueue.Signer, logger *slog.Logger, resolver registry.DeviceGatewayLookup) *InboxWorker {
	return &InboxWorker{
		now:        time.Now,
		store:      st,
		aqClient:   aqClient,
		signer:     signer,
		taskSigner: taskSigner,
		logger:     logger,
		resolver:   resolver,
	}
}

// verifyDeviceGatewayBinding maps the shared binding policy to an inbox drop:
// a forged/mismatched binding is NOT retryable, so wrap with asynq.SkipRetry
// and append NO event. Returns nil when the binding is OK (or no resolver).
func (w *InboxWorker) verifyDeviceGatewayBinding(ctx context.Context, deviceID, gatewayID string) error {
	if err := registry.CheckDeviceGatewayBinding(ctx, w.resolver, deviceID, gatewayID); err != nil {
		w.logger.Warn("inbox: rejecting device-origin task: gateway binding", "device_id", deviceID, "claimed_gateway_id", gatewayID, "error", err)
		return fmt.Errorf("%w: device→gateway binding: %v", asynq.SkipRetry, err)
	}
	return nil
}

// NewMux returns an Asynq ServeMux with handlers for the main
// control inbox queue. The terminal audit chunk handler is split
// out onto its own mux (NewTerminalAuditMux) so a dedicated Asynq
// server can process it with Concurrency=1 — see the documentation
// on taskqueue.ControlTerminalAuditQueue.
func (w *InboxWorker) NewMux() *asynq.ServeMux {
	mux := asynq.NewServeMux()
	if w.taskSigner != nil {
		mux.Use(w.taskSigner.VerifyMiddleware())
	}
	mux.HandleFunc(taskqueue.TypeDeviceHello, w.handleDeviceHello)
	mux.HandleFunc(taskqueue.TypeDeviceHeartbeat, w.handleDeviceHeartbeat)
	mux.HandleFunc(taskqueue.TypeExecutionResult, w.handleExecutionResult)
	mux.HandleFunc(taskqueue.TypeExecutionOutputChunk, w.handleExecutionOutputChunk)
	mux.HandleFunc(taskqueue.TypeOSQueryResult, w.handleOSQueryResult)
	mux.HandleFunc(taskqueue.TypeInventoryUpdate, w.handleInventoryUpdate)
	mux.HandleFunc(taskqueue.TypeSecurityAlert, w.handleSecurityAlert)
	mux.HandleFunc(taskqueue.TypeRevokeLuksDeviceKeyResult, w.handleRevokeLuksDeviceKeyResult)
	mux.HandleFunc(taskqueue.TypeLogQueryResult, w.handleLogQueryResult)
	return mux
}

// NewTerminalAuditMux returns an Asynq ServeMux with ONLY the
// terminal-audit-chunk handler. Mounted on a second Asynq server
// with Concurrency=1 so per-session chunks are applied strictly in
// sequence order. If we served this on the main inbox server's
// 10-worker pool, two workers could race on the last_sequence
// guard and the loser's bytes would be silently dropped.
func (w *InboxWorker) NewTerminalAuditMux() *asynq.ServeMux {
	mux := asynq.NewServeMux()
	if w.taskSigner != nil {
		mux.Use(w.taskSigner.VerifyMiddleware())
	}
	mux.HandleFunc(taskqueue.TypeTerminalAuditChunk, w.handleTerminalAuditChunk)
	return mux
}

func (w *InboxWorker) handleDeviceHello(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.DeviceHelloPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal device hello: %w", err)
	}

	if err := w.verifyDeviceGatewayBinding(ctx, payload.DeviceID, payload.GatewayID); err != nil {
		return err
	}

	logger := w.logger.With("device_id", payload.DeviceID, "hostname", payload.Hostname)

	// Skip processing for deleted or unknown devices.
	deleted, err := w.store.Repos().Device.IsDeleted(ctx, payload.DeviceID)
	if err != nil {
		if store.IsNotFound(err) {
			logger.Debug("ignoring hello from unknown device")
			return nil
		}
		logger.Error("failed to check device deletion status", "error", err)
		return err
	}
	if deleted {
		logger.Debug("ignoring hello from deleted device")
		return nil
	}

	logger.Info("agent connected", "agent_version", payload.AgentVersion)

	// Emit DeviceHeartbeat event
	if err := w.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   payload.DeviceID,
		EventType:  string(eventtypes.DeviceHeartbeat),
		Data: payloads.DeviceHeartbeat{
			AgentVersion: optStrEmpty(payload.AgentVersion),
			Hostname:     optStrEmpty(payload.Hostname),
		},
		ActorType: "device",
		ActorID:   payload.DeviceID,
	}); err != nil {
		logger.Error("failed to append heartbeat event", "error", err)
		return err
	}

	// Dispatch pending actions to the device via Asynq
	if err := w.dispatchPendingActions(ctx, payload.DeviceID, logger); err != nil {
		logger.Error("failed to dispatch pending actions", "error", err)
		return err
	}
	return nil
}

func (w *InboxWorker) handleDeviceHeartbeat(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.DeviceHeartbeatPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal device heartbeat: %w", err)
	}

	if err := w.verifyDeviceGatewayBinding(ctx, payload.DeviceID, payload.GatewayID); err != nil {
		return err
	}

	// Skip processing for deleted or unknown devices.
	deleted, err := w.store.Repos().Device.IsDeleted(ctx, payload.DeviceID)
	if err != nil {
		if store.IsNotFound(err) {
			w.logger.Debug("ignoring heartbeat from unknown device", "device_id", payload.DeviceID)
			return nil
		}
		w.logger.Error("failed to check device deletion status", "device_id", payload.DeviceID, "error", err)
		return err
	}
	if deleted {
		w.logger.Debug("ignoring heartbeat from deleted device", "device_id", payload.DeviceID)
		return nil
	}

	// Audit N008: only the AgentVersion field is projected today;
	// uptime / cpu / memory / disk percentages from the taskqueue
	// payload are dropped here because no projector consumes them.
	// Re-enable once a device_metrics_projection is added.
	return w.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   payload.DeviceID,
		EventType:  string(eventtypes.DeviceHeartbeat),
		Data: payloads.DeviceHeartbeat{
			AgentVersion: optStrEmpty(payload.AgentVersion),
		},
		ActorType: "device",
		ActorID:   payload.DeviceID,
	})
}

func (w *InboxWorker) handleExecutionResult(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.ExecutionResultPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal execution result: %w", err)
	}

	// The ActionResultJSON is a protojson-encoded pm.ActionResult.
	// We must use protojson.Unmarshal (not json.Unmarshal) because protojson
	// encodes int64 fields as JSON strings per the protobuf spec, which
	// standard json.Unmarshal cannot decode into Go int64 fields.
	var result pm.ActionResult
	if err := protojson.Unmarshal(payload.ActionResultJSON, &result); err != nil {
		return fmt.Errorf("unmarshal action result: %w", err)
	}

	deviceID := payload.DeviceID
	resultID := result.GetActionId().GetValue()
	if resultID == "" {
		return fmt.Errorf("action result missing action ID")
	}

	if err := w.verifyDeviceGatewayBinding(ctx, deviceID, payload.GatewayID); err != nil {
		return err
	}

	logger := w.logger.With("device_id", deviceID, "result_id", resultID)

	// Determine execution ID and action ID.
	// resultID may be an execution ID (dispatched by API) or an action ID
	// (scheduled locally by the agent). We try execution first.
	var executionID, actionID string
	var needsCreate bool

	existingExec, err := w.store.Repos().Execution.Get(ctx, resultID)
	if err == nil {
		// The reporting device must OWN this execution. resultID (an execution
		// ID) is non-secret, so without this a compromised agent could write
		// forged results onto another device's execution by supplying its ID
		// (cross-device result spoofing). The agent-scheduled path below is
		// already device-safe — its execution ID is derived from deviceID.
		if existingExec.DeviceID != deviceID {
			logger.Warn("rejecting execution result: execution belongs to a different device",
				"execution_device_id", existingExec.DeviceID)
			return fmt.Errorf("execution %s does not belong to reporting device %s", resultID, deviceID)
		}
		executionID = existingExec.ID
		if existingExec.ActionID != nil {
			actionID = *existingExec.ActionID
		}
		needsCreate = false
	} else if store.IsNotFound(err) {
		// Not an execution ID — treat as action ID (agent-scheduled action).
		// Derive a stable execution ID from device+action+completedAt so
		// retries of the same result don't create duplicates, but separate
		// scheduled runs of the same action get unique IDs.
		actionID = resultID
		// Use CompletedAt (seconds+nanos) for per-run uniqueness; fall back to
		// DurationMs+Status — stable across retries of the same result — when
		// CompletedAt is absent. stableExecutionID frames + domain-separates the
		// two variants internally.
		executionID = stableExecutionID(deviceID, actionID, result.CompletedAt, result.DurationMs, result.Status)

		// Check if this derived execution already exists (retry of a previously processed result)
		_, checkErr := w.store.Repos().Execution.Get(ctx, executionID)
		if checkErr == nil {
			needsCreate = false
		} else if store.IsNotFound(checkErr) {
			needsCreate = true
		} else {
			return fmt.Errorf("check derived execution %s: %w", executionID, checkErr)
		}
	} else {
		// Transient DB error — let Asynq retry
		return fmt.Errorf("lookup execution %s: %w", resultID, err)
	}

	// Calculate timestamps
	var executedAt, completedAt time.Time
	if result.CompletedAt != nil && result.CompletedAt.IsValid() {
		completedAt = result.CompletedAt.AsTime()
		executedAt = completedAt.Add(-time.Duration(result.DurationMs) * time.Millisecond)
	}
	if completedAt.IsZero() {
		completedAt = w.now()
		executedAt = completedAt.Add(-time.Duration(result.DurationMs) * time.Millisecond)
	}

	// Cache the action lookup — reused for both execution creation and compliance check.
	var cachedAction *store.Action

	if needsCreate {
		action, err := w.store.Repos().Action.Get(ctx, actionID)
		if err != nil {
			if store.IsNotFound(err) {
				// Action was deleted while agent was offline — skip, don't retry.
				logger.Warn("action not found, skipping execution creation", "action_id", actionID)
				return nil
			}
			return fmt.Errorf("lookup action %s: %w", actionID, err)
		}
		cachedAction = &action

		actionIDCopy := actionID
		actionType := action.ActionType
		desiredState := int32(0)
		timeoutSeconds := action.TimeoutSeconds
		executedAtStr := executedAt.Format(time.RFC3339Nano)
		createdData := payloads.ExecutionCreated{
			DeviceID:       deviceID,
			ActionID:       &actionIDCopy,
			ActionType:     &actionType,
			DesiredState:   &desiredState,
			Params:         json.RawMessage(action.Params),
			TimeoutSeconds: &timeoutSeconds,
			ExecutedAt:     &executedAtStr,
		}
		if err := w.store.AppendEvent(ctx, store.Event{
			StreamType: "execution",
			StreamID:   executionID,
			EventType:  string(eventtypes.ExecutionCreated),
			Data:       createdData,
			ActorType:  "device",
			ActorID:    deviceID,
		}); err != nil {
			return fmt.Errorf("create execution event: %w", err)
		}
	}

	// Map proto status to event type. data holds whichever payloads.*
	// struct matches — store.Event.Data accepts any JSON-marshalable
	// value, so each branch picks the typed wire shape rather than
	// dropping back to map[string]any.
	var eventType string
	var data any
	completedAtStr := completedAt.Format(time.RFC3339Nano)

	switch result.Status {
	case pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS:
		eventType = "ExecutionCompleted"
		durationMs := result.DurationMs
		changed := result.Changed
		compliant := result.Compliant
		data = payloads.ExecutionTerminal{
			CompletedAt:     &completedAtStr,
			DurationMs:      &durationMs,
			Changed:         &changed,
			Compliant:       &compliant,
			Output:          payloads.RawCommandOutput(commandOutputPayload(result.Output)),
			DetectionOutput: payloads.RawCommandOutput(commandOutputPayload(result.DetectionOutput)),
		}

	case pm.ExecutionStatus_EXECUTION_STATUS_FAILED:
		eventType = "ExecutionFailed"
		errStr := result.Error
		durationMs := result.DurationMs
		changed := result.Changed
		compliant := result.Compliant
		data = payloads.ExecutionTerminal{
			Error:           &errStr,
			CompletedAt:     &completedAtStr,
			DurationMs:      &durationMs,
			Changed:         &changed,
			Compliant:       &compliant,
			Output:          payloads.RawCommandOutput(commandOutputPayload(result.Output)),
			DetectionOutput: payloads.RawCommandOutput(commandOutputPayload(result.DetectionOutput)),
		}

	case pm.ExecutionStatus_EXECUTION_STATUS_RUNNING:
		eventType = "ExecutionStarted"
		data = map[string]any{}

	case pm.ExecutionStatus_EXECUTION_STATUS_TIMEOUT:
		eventType = "ExecutionTimedOut"
		errStr := result.Error
		durationMs := result.DurationMs
		data = payloads.ExecutionTimedOut{
			Error:       &errStr,
			CompletedAt: &completedAtStr,
			DurationMs:  &durationMs,
			Output:      payloads.RawCommandOutput(commandOutputPayload(result.Output)),
		}

	case pm.ExecutionStatus_EXECUTION_STATUS_SKIPPED:
		eventType = "ExecutionSkipped"
		if result.Error != "" {
			reason := result.Error
			data = payloads.ExecutionReason{Reason: &reason}
		} else {
			data = payloads.ExecutionReason{}
		}

	default:
		return fmt.Errorf("unknown execution status: %s", result.Status.String())
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
	if result.DetectionOutput != nil && actionID != "" {
		// Reuse cached action if available, otherwise fetch
		if cachedAction == nil {
			if a, err := w.store.Repos().Action.Get(ctx, actionID); err != nil {
				logger.Warn("failed to look up action for compliance check", "action_id", actionID, "error", err)
			} else {
				cachedAction = &a
			}
		}
		if cachedAction != nil {
			isCompliance := false
			var params map[string]any
			if err := json.Unmarshal(cachedAction.Params, &params); err == nil {
				isCompliance, _ = params["isCompliance"].(bool)
			}
			if isCompliance {
				complianceData := map[string]any{
					"device_id":        deviceID,
					"action_id":        actionID,
					"action_name":      cachedAction.Name,
					"compliant":        result.Compliant,
					"detection_output": commandOutputToMap(result.DetectionOutput),
				}
				if err := w.store.AppendEvent(ctx, store.Event{
					StreamType: "compliance",
					StreamID:   deviceID + "_" + actionID,
					EventType:  string(eventtypes.ComplianceResultUpdated),
					Data:       complianceData,
					ActorType:  "device",
					ActorID:    deviceID,
				}); err != nil {
					logger.Error("failed to append compliance event", "error", err)
				}
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

	if err := w.verifyDeviceGatewayBinding(ctx, payload.DeviceID, payload.GatewayID); err != nil {
		return err
	}

	// Second-line size guard (audit F-33). The gateway already caps
	// at 64 KiB on the agent-facing side (handler/agent.go,
	// maxOutputChunkBytes), but the inbox worker is also a trust
	// boundary — a future gateway compromise or a buggy intermediate
	// could otherwise enqueue an oversized chunk into Valkey. We
	// drop oversized chunks here rather than truncate, matching the
	// gateway's drop-with-WARN policy, so a fuzz-fed flood doesn't
	// silently corrupt the visible output stream.
	const maxOutputChunkInboxBytes = 64 * 1024
	if len(payload.Data) > maxOutputChunkInboxBytes {
		w.logger.Warn("inbox: output chunk exceeds size cap; dropping",
			"device_id", payload.DeviceID,
			"execution_id", payload.ExecutionID,
			"stream", payload.Stream,
			"sequence", payload.Sequence,
			"size", len(payload.Data),
			"limit", maxOutputChunkInboxBytes,
		)
		return nil
	}

	// Cross-device ownership guard (mirrors the handleExecutionResult
	// check). The execution ID is non-secret, so without this a
	// compromised agent could splice forged output onto ANOTHER device's
	// execution stream by supplying its ID. The reporting device must own
	// the execution. When the execution is not found we keep the prior
	// behaviour (append anyway) — chunks can legitimately race ahead of
	// the ExecutionCreated projection, and there is no owner to spoof yet.
	if exec, err := w.store.Repos().Execution.Get(ctx, payload.ExecutionID); err == nil {
		if exec.DeviceID != payload.DeviceID {
			w.logger.Warn("dropping output chunk: execution belongs to a different device",
				"execution_id", payload.ExecutionID,
				"reporting_device_id", payload.DeviceID,
				"execution_device_id", exec.DeviceID)
			return nil
		}
	} else if !store.IsNotFound(err) {
		// Transient DB / context error — let Asynq retry rather than
		// drop or blindly append.
		return fmt.Errorf("look up execution %s for output chunk: %w", payload.ExecutionID, err)
	}

	return w.store.AppendEvent(ctx, store.Event{
		StreamType: "execution",
		StreamID:   payload.ExecutionID,
		EventType:  string(eventtypes.OutputChunk),
		Data: payloads.OutputChunk{
			Stream:   payload.Stream,
			Data:     payload.Data,
			Sequence: payload.Sequence,
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

	if err := w.verifyDeviceGatewayBinding(ctx, payload.DeviceID, payload.GatewayID); err != nil {
		return err
	}

	w.logger.Info("received query result",
		"device_id", payload.DeviceID,
		"query_id", payload.QueryID,
		"success", payload.Success,
	)

	n, err := w.store.Queries().CompleteOSQueryResult(ctx, db.CompleteOSQueryResultParams{
		QueryID:  payload.QueryID,
		Success:  payload.Success,
		Error:    payload.Error,
		Rows:     payload.RowsJSON,
		DeviceID: payload.DeviceID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		// No matching pending query for THIS device — either an unknown/expired
		// query, or a result reported for a query owned by a different device
		// (cross-device spoofing). Drop it; a retry won't change the match.
		w.logger.Warn("dropping osquery result: no matching pending query for this device",
			"query_id", payload.QueryID, "device_id", payload.DeviceID)
	}
	return nil
}

func (w *InboxWorker) handleLogQueryResult(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.LogQueryResultPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal log query result: %w", err)
	}

	if err := w.verifyDeviceGatewayBinding(ctx, payload.DeviceID, payload.GatewayID); err != nil {
		return err
	}

	w.logger.Info("received log query result",
		"device_id", payload.DeviceID,
		"query_id", payload.QueryID,
		"success", payload.Success,
	)

	n, err := w.store.Queries().CompleteLogQueryResult(ctx, db.CompleteLogQueryResultParams{
		QueryID:  payload.QueryID,
		Success:  payload.Success,
		Error:    payload.Error,
		Logs:     payload.Logs,
		DeviceID: payload.DeviceID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		w.logger.Warn("dropping log query result: no matching pending query for this device",
			"query_id", payload.QueryID, "device_id", payload.DeviceID)
	}
	return nil
}

func (w *InboxWorker) handleInventoryUpdate(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.InventoryUpdatePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal inventory update: %w", err)
	}

	if err := w.verifyDeviceGatewayBinding(ctx, payload.DeviceID, payload.GatewayID); err != nil {
		return err
	}

	w.logger.Info("received device inventory",
		"device_id", payload.DeviceID,
		"tables", len(payload.Tables),
	)

	for _, table := range payload.Tables {
		if err := w.store.Repos().Inventory.Upsert(ctx, store.UpsertInventoryTable{
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

	// Enqueue dynamic device groups for re-evaluation. Wave F
	// replacement for the PL/pgSQL device_inventory_changed trigger:
	// since the trigger is gone, the inbox worker enqueues explicitly
	// after the inventory upsert chain completes.
	if err := w.store.Queries().EnqueueAllDynamicDeviceGroups(ctx, "device_"+payload.DeviceID+"_changed"); err != nil {
		w.logger.Warn("failed to enqueue dynamic device groups after inventory update",
			"device_id", payload.DeviceID,
			"error", err,
		)
	}

	// Immediately evaluate dynamic groups queued by the inventory update above.
	// Without this, groups are only evaluated on the periodic ticker (default 1h).
	// Single-batch invocation here — the caller doesn't drain to
	// completion the way cmd/control does. The `more` flag is
	// ignored on this path because the periodic worker (or a
	// subsequent inbox event) will pick up any leftover.
	if r, err := dyngroupeval.New(w.store, w.logger).DrainDeviceGroupQueue(ctx); err != nil {
		w.logger.Warn("failed to evaluate dynamic groups after inventory update",
			"device_id", payload.DeviceID,
			"error", err,
		)
	} else if r.Count > 0 {
		w.logger.Info("evaluated dynamic groups after inventory update",
			"device_id", payload.DeviceID,
			"count", r.Count,
		)
	}

	return nil
}

func (w *InboxWorker) handleSecurityAlert(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.SecurityAlertPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal security alert: %w", err)
	}

	if err := w.verifyDeviceGatewayBinding(ctx, payload.DeviceID, payload.GatewayID); err != nil {
		return err
	}

	w.logger.Warn("received security alert from device",
		"device_id", payload.DeviceID,
		"alert_type", payload.AlertType,
		"message", payload.Message,
	)

	return w.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   payload.DeviceID,
		EventType:  string(eventtypes.SecurityAlert),
		Data: payloads.SecurityAlert{
			AlertType: payload.AlertType,
			Message:   payload.Message,
			Details:   payload.Details,
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

	if err := w.verifyDeviceGatewayBinding(ctx, payload.DeviceID, payload.GatewayID); err != nil {
		return err
	}

	w.logger.Info("received LUKS device key revocation result",
		"device_id", payload.DeviceID,
		"action_id", payload.ActionID,
		"success", payload.Success,
	)

	// Look up the stream ID minted at request time so the Revoked /
	// Failed event lands on the SAME stream as the Requested /
	// Dispatched phases. Earlier versions generated a fresh ULID
	// here, which split every revocation across two streams and
	// broke the projection's three-phase stitch — fixed in rc10.
	//
	// Correctness assumption: at most one outstanding revocation
	// per (device, action) at a time. Enforced at the API layer:
	// RevokeLuksDeviceKey checks the projection for an already-
	// dispatched-and-unterminal request before accepting a new
	// one, so duplicates via concurrent operator clicks are
	// rejected upstream. If that invariant ever regresses, the
	// ORDER BY sequence_num DESC + LIMIT 1 here will pick the
	// LATEST matching request — which is the expected "the
	// operator re-requested and here's the result" semantic.
	// Older abandoned streams would then lack a terminal event;
	// not a correctness issue for the projection (it keys by
	// stream_id), but worth flagging for the audit export.
	//
	// If the lookup finds no matching Requested/Dispatched stream, the
	// result is dropped (see the IsNotFound branch). Earlier versions
	// minted a FRESH ulid here and appended anyway — but the (device,
	// action) pair is attacker-supplied, so a compromised gateway could
	// fabricate an orphan luks_key stream out of thin air (audit:
	// no genuine operator request ever existed). We only ever land the
	// terminal event on a stream a real RevokeLuksDeviceKey request
	// minted.
	luksStreamID, err := w.store.Repos().Luks.GetRevocationStreamID(ctx, store.LuksRevocationStreamKey{
		DeviceID: payload.DeviceID,
		ActionID: payload.ActionID,
	})
	switch {
	case err == nil:
		// Happy path — stream ID recovered.
	case store.IsNotFound(err):
		// No outstanding revocation request for this (device, action).
		// Either the result is stale/duplicate, or it was forged by a
		// compromised gateway for a request that was never made. Drop
		// it rather than fabricate an orphan stream from attacker input.
		w.logger.Warn("dropping LUKS revocation result: no matching outstanding revocation request",
			"device_id", payload.DeviceID,
			"action_id", payload.ActionID,
		)
		return nil
	default:
		// Transient DB / context error. Return so Asynq retries;
		// previously we masked these as "not found" and forked
		// the stream, which would compound audit fragmentation
		// under DB flakes.
		return fmt.Errorf("look up LUKS revocation stream ID for device %s action %s: %w", payload.DeviceID, payload.ActionID, err)
	}

	if payload.Success {
		return w.store.AppendEvent(ctx, store.Event{
			StreamType: "luks_key",
			StreamID:   luksStreamID,
			EventType:  string(eventtypes.LuksDeviceKeyRevoked),
			Data: payloads.LuksDeviceKeyRevoked{
				DeviceID:  payload.DeviceID,
				ActionID:  payload.ActionID,
				RevokedAt: w.now().UTC().Format(time.RFC3339Nano),
			},
			ActorType: "device",
			ActorID:   payload.DeviceID,
		})
	}

	return w.store.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   luksStreamID,
		EventType:  string(eventtypes.LuksDeviceKeyRevocationFailed),
		Data: payloads.LuksDeviceKeyRevocationFailed{
			DeviceID: payload.DeviceID,
			ActionID: payload.ActionID,
			Error:    payload.Error,
			FailedAt: w.now().UTC().Format(time.RFC3339Nano),
		},
		ActorType: "device",
		ActorID:   payload.DeviceID,
	})
}

// dispatchPendingActions finds pending executions for a device and enqueues them
// to the device's Asynq queue. This mirrors the logic from Handler.dispatchPendingActions
// but uses Asynq instead of PostgreSQL NOTIFY.
func (w *InboxWorker) dispatchPendingActions(ctx context.Context, deviceID string, logger *slog.Logger) error {
	logger.Debug("checking for pending executions")

	executions, err := w.store.Repos().Execution.ListPendingForDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("list pending executions: %w", err)
	}

	logger.Debug("found pending executions", "count", len(executions))

	var enqueueErrs []error
	for _, exec := range executions {
		// Every dispatch — whether it references a stored action or is an
		// inline/compliance execution with no action row — now ships a
		// fully signed SignedActionEnvelope. The gateway forwards those
		// bytes verbatim and the agent verifies+executes them, so an empty
		// envelope/signature is never acceptable. A nil signer is therefore
		// fatal to dispatch regardless of ActionID.
		if w.signer == nil {
			logger.Error("cannot dispatch execution without signer",
				"execution_id", exec.ID)
			continue
		}

		// When the execution references a stored action, detect the
		// action-deleted-before-reconnect race and fail the orphan so it
		// leaves the pending state. The action row is NOT a params source
		// any more — the envelope params come from the execution's own
		// stored params (exec.Params), which are authoritative for THIS
		// execution. (Create-time no longer persists a dispatch-grade
		// signature/canonical blob; the dispatcher rebuilds the envelope
		// here.)
		if exec.ActionID != nil {
			if _, err := w.store.Repos().Action.Get(ctx, *exec.ActionID); err != nil {
				if store.IsNotFound(err) {
					// Action was deleted after the execution was created.
					// Mark the execution failed so it leaves the "pending"
					// state — otherwise every reconnect retries dispatch
					// and re-logs the same error forever.
					logger.Warn("action for pending execution no longer exists; failing execution",
						"execution_id", exec.ID, "action_id", *exec.ActionID)
					if appendErr := w.store.AppendEvent(ctx, store.Event{
						StreamType: "execution",
						StreamID:   exec.ID,
						EventType:  string(eventtypes.ExecutionFailed),
						Data: payloads.ExecutionFailedReason{
							Error:       "action was deleted before the device came online",
							DurationMs:  0,
							CompletedAt: w.now().UTC().Format(time.RFC3339Nano),
						},
						ActorType: "system",
						ActorID:   "dispatcher",
					}); appendErr != nil {
						logger.Error("failed to mark orphaned execution as failed",
							"execution_id", exec.ID, "error", appendErr)
					}
					continue
				}
				logger.Error("failed to look up action for dispatch, skipping",
					"execution_id", exec.ID, "action_id", *exec.ActionID, "error", err)
				continue
			}
		}

		// Build and sign the full envelope, binding it to the execution id
		// and target device. The gateway sets nothing — the agent verifies
		// the signature over these exact bytes and unmarshals them, so the
		// envelope's ActionId == execution id is the identity the agent
		// trusts. Reconnect re-dispatch signs the SAME executed semantics
		// (desired_state / timeout / params / device) the API originally
		// committed, so a compromised relay can't rewrite them.
		//
		// Reconnect re-dispatch carries no schedule (nil): a pending one-shot
		// dispatch is not an autonomous scheduled action.
		paramsJSON := exec.Params
		if len(paramsJSON) == 0 {
			paramsJSON = []byte("{}")
		}
		envelopeBytes, signature, err := actionparams.BuildAndSignEnvelope(
			w.signer,
			exec.ID,
			exec.ActionType,
			paramsJSON,
			exec.DesiredState,
			exec.TimeoutSeconds,
			nil, // reconnect re-dispatch is one-shot, no schedule
			deviceID,
		)
		if err != nil {
			logger.Error("failed to build/sign action envelope for dispatch, skipping",
				"execution_id", exec.ID, "error", err)
			continue
		}

		// Enqueue to device queue first — only record the event after the
		// task is durably queued so we never mark "dispatched" without delivery.
		// Use a stable TaskID so retries don't create duplicate tasks.
		if err := w.aqClient.EnqueueToDevice(deviceID, taskqueue.TypeActionDispatch, taskqueue.ActionDispatchPayload{
			ExecutionID:   exec.ID,
			EnvelopeBytes: envelopeBytes,
			Signature:     signature,
		}, asynq.MaxRetry(3), asynq.TaskID("dispatch:"+exec.ID)); err != nil {
			if errors.Is(err, asynq.ErrTaskIDConflict) {
				// Task already in queue — still need to record the dispatch event
				// so the execution isn't stuck in "pending" state.
				logger.Debug("action already enqueued", "execution_id", exec.ID)
			} else {
				logger.Error("failed to enqueue action dispatch", "error", err, "execution_id", exec.ID)
				enqueueErrs = append(enqueueErrs, err)
				continue
			}
		}

		// Record the dispatch event now that the task is in the queue.
		// Retry on transient failures — the task is already enqueued, so
		// failing to record the event could cause duplicate dispatch on reconnect.
		dispatchEvt := store.Event{
			StreamType: "execution",
			StreamID:   exec.ID,
			EventType:  string(eventtypes.ExecutionDispatched),
			Data: payloads.ExecutionDispatched{
				DeviceID: deviceID,
			},
			ActorType: "system",
			ActorID:   "dispatcher",
		}
		var appendErr error
		const maxAttempts = 3
		for attempt := 0; attempt < maxAttempts; attempt++ {
			if appendErr = w.store.AppendEvent(ctx, dispatchEvt); appendErr == nil {
				break
			}
			logger.Warn("failed to append dispatch event, retrying",
				"error", appendErr, "execution_id", exec.ID, "attempt", attempt+1)
			// Exponential backoff between attempts (100ms, 200ms). Skip
			// the wait on the final failure so callers see the error
			// immediately. Respect ctx cancellation.
			if attempt == maxAttempts-1 {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(100*(1<<attempt)) * time.Millisecond):
			}
		}
		if appendErr != nil {
			return fmt.Errorf("append dispatch event for %s after 3 attempts: %w", exec.ID, appendErr)
		}

		logger.Info("dispatched pending execution via Asynq",
			"execution_id", exec.ID,
			"action_type", exec.ActionType,
		)
	}
	if len(enqueueErrs) > 0 {
		return fmt.Errorf("%d dispatch(es) failed, first: %w", len(enqueueErrs), enqueueErrs[0])
	}
	return nil
}

// commandOutputToMap converts a CommandOutput proto to a map for event
// data. Returns nil if the output is nil. Used by emit sites that
// still construct payloads as map[string]any (the compliance event
// shape, for now).
func commandOutputToMap(o *pm.CommandOutput) map[string]any {
	if o == nil {
		return nil
	}
	return map[string]any{
		"stdout":    o.Stdout,
		"stderr":    o.Stderr,
		"exit_code": o.ExitCode,
	}
}

// maxCommandOutputBytes is the per-stream ceiling enforced on
// stdout / stderr before persistence (audit F-33). A compromised
// agent (or a buggy executor) could otherwise dump multi-MB results
// into the event store and the Valkey inbox queue, filling
// events.data and bloating the audit trail. 1 MiB is comfortably
// above any sane single-execution output — when a stream exceeds
// it, we keep the head (first MiB) and append a trailing marker so
// the UI shows what happened. The F-13 per-chunk cap (64 KiB) gates
// streaming output; F-33 gates the consolidated result payload that
// the agent emits on completion.
const maxCommandOutputBytes = 1024 * 1024

// truncateOutputStream caps an output stream at maxCommandOutputBytes
// and appends an explicit truncation marker so the UI / log readers
// can tell the difference between "agent emitted exactly N bytes" and
// "we dropped the tail." Returns the input unchanged when it fits.
func truncateOutputStream(s string) string {
	if len(s) <= maxCommandOutputBytes {
		return s
	}
	const marker = "\n... [truncated by control server — output exceeded 1 MiB]"
	return s[:maxCommandOutputBytes-len(marker)] + marker
}

// commandOutputPayload converts a CommandOutput proto into the typed
// payloads.CommandOutput used by the execution-event payload structs.
// Returns nil for nil input so payloads.RawCommandOutput drops the
// field via omitempty. Caps Stdout + Stderr per stream (audit F-33).
func commandOutputPayload(o *pm.CommandOutput) *payloads.CommandOutput {
	if o == nil {
		return nil
	}
	return &payloads.CommandOutput{
		Stdout:   truncateOutputStream(o.Stdout),
		Stderr:   truncateOutputStream(o.Stderr),
		ExitCode: o.ExitCode,
	}
}

// stableExecutionID derives a deterministic execution ID from device, action,
// and completed-at timestamp. Including completedAt ensures separate scheduled
// runs of the same action get unique IDs, while retries of the same result
// (same completedAt) produce the same ID for deduplication.
//
// Returns a valid ULID constructed from the first 16 bytes of a SHA-256 hash.
// The timestamp portion is not meaningful, but the result is deterministic and
// passes ULID validation everywhere IDs are checked.
// optStrEmpty returns nil for an empty string and a pointer to s
// otherwise. Used by emit sites that want JSON `omitempty` semantics
// on payload struct fields without sprinkling `if s != "" { ... }`
// guards into every callsite.
func optStrEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// stableExecutionIDDomain is the domain separator prefixed onto every
// derived-execution-id pre-image, so this hash space can never collide another
// SHA-256 use elsewhere in the system.
const stableExecutionIDDomain = "pm-derived-execution-id"

// stableExecutionID derives a deterministic execution id for an agent-scheduled
// action result, so retries of the SAME result dedup to one row while distinct
// runs stay unique. The pre-image is length-prefixed (each component framed by
// a big-endian uint32 length, mirroring the signing digest's sha256Tree) and
// domain-separated, which fixes two latent ambiguities of the old
// ':'-concatenated string:
//
//   - Field-boundary collision: ("a:b","c") and ("a","b:c") hashed identically
//     because ':' was both the delimiter AND a legal id character. Framing each
//     field by its length removes the ambiguity.
//   - Mixed pre-image domains: completion was a single formatted string that was
//     EITHER an RFC3339Nano timestamp OR a `dur:status` fallback, with nothing
//     marking which. Each variant now carries a distinct tag, and the timestamp
//     variant keys off the proto Timestamp's (seconds, nanos) rather than a
//     formatted string whose precision/format could drift.
func stableExecutionID(deviceID, actionID string, completedAt *timestamppb.Timestamp, durationMs int64, status pm.ExecutionStatus) string {
	h := sha256.New()
	writeFramed(h, []byte(stableExecutionIDDomain))
	writeFramed(h, []byte(deviceID))
	writeFramed(h, []byte(actionID))
	if completedAt != nil && completedAt.IsValid() {
		writeFramed(h, []byte("completed-at"))
		var buf [12]byte
		binary.BigEndian.PutUint64(buf[0:8], uint64(completedAt.GetSeconds()))
		binary.BigEndian.PutUint32(buf[8:12], uint32(completedAt.GetNanos()))
		writeFramed(h, buf[:])
	} else {
		writeFramed(h, []byte("duration-status"))
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(durationMs))
		writeFramed(h, buf[:])
		writeFramed(h, []byte(status.String()))
	}
	sum := h.Sum(nil)
	var id ulid.ULID
	copy(id[:], sum[:16])
	return id.String()
}

// writeFramed writes a length-prefixed component into the running hash:
// a big-endian uint32 of len(b) followed by b. Prefixing every field with its
// length makes the concatenation injective, so no field's bytes can shift
// across a boundary to alias a different field arrangement.
func writeFramed(h hash.Hash, b []byte) {
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(b)))
	h.Write(lp[:])
	h.Write(b)
}

// handleTerminalAuditChunk appends a stdin chunk to the owning
// session's row in terminal_sessions. The gateway tees batched
// stdin to this handler (see terminalAuditBatcher in the gateway's
// handler package); the batcher already coalesces keystrokes into
// ≤4 KiB chunks before dispatch, so the hot path here is a single
// indexed UPDATE per batch.
//
// rc7 rework note: prior versions emitted one TerminalInputChunk
// event per chunk onto the device's audit stream. That polluted
// the event log with one opaque base64 fragment per chunk and
// left no way to group them for replay. terminal_sessions now
// owns the stdin bytes; the lifecycle events
// (TerminalSessionStarted / Stopped / Terminated) stay on the
// audit stream as the user-visible audit markers.
//
// The sqlc query is UPDATE-only (keyed on session_id): an audit chunk
// can append stdin onto an EXISTING session but can never INSERT an
// owner-bearing row. Session bootstrap is the lifecycle
// TerminalSessionStarted handler's job (UpsertTerminalSessionStart). A
// chunk that outruns the Started event — or one a compromised gateway
// forges for an unknown / unowned session — is dropped here rather than
// allowed to mint a placeholder with attacker-chosen owners.
func (w *InboxWorker) handleTerminalAuditChunk(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.TerminalAuditChunkPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal terminal audit chunk: %w", err)
	}

	if payload.SessionID == "" || payload.DeviceID == "" || payload.UserID == "" {
		w.logger.Warn("dropping terminal audit chunk with missing fields",
			"session_id", payload.SessionID, "device_id", payload.DeviceID, "user_id", payload.UserID)
		return nil
	}

	if err := w.verifyDeviceGatewayBinding(ctx, payload.DeviceID, payload.GatewayID); err != nil {
		return err
	}

	// The session row is the authority on who owns the stdin stream.
	// The audit chunk is no longer allowed to CREATE a session (an
	// upsert keyed on payload DeviceID/UserID would let a compromised
	// gateway mint a placeholder row with attacker-chosen owners, then
	// have it back-filled — or simply pollute the audit trail). Require
	// the session to already exist (bootstrapped by the
	// TerminalSessionStarted lifecycle handler), and require the chunk's
	// claimed (device, user) to match the row's owners exactly. Append
	// using the owners DERIVED FROM THE ROW, never the payload.
	session, err := w.store.Queries().GetTerminalSession(ctx, payload.SessionID)
	if err != nil {
		if store.IsNotFound(err) {
			w.logger.Warn("dropping terminal audit chunk for unknown session: refusing to create a session from an audit chunk",
				"session_id", payload.SessionID, "device_id", payload.DeviceID, "user_id", payload.UserID)
			return nil
		}
		return fmt.Errorf("look up terminal session %s: %w", payload.SessionID, err)
	}
	if session.DeviceID != payload.DeviceID || session.UserID != payload.UserID {
		w.logger.Warn("dropping terminal audit chunk: device/user does not own the session",
			"session_id", payload.SessionID,
			"claimed_device_id", payload.DeviceID, "session_device_id", session.DeviceID,
			"claimed_user_id", payload.UserID, "session_user_id", session.UserID)
		return nil
	}

	return w.store.Queries().AppendTerminalSessionChunk(ctx, db.AppendTerminalSessionChunkParams{
		SessionID: payload.SessionID,
		Input:     payload.Data,
		// Sequence guards against duplicate / out-of-order retries
		// from Asynq. The gateway's audit batcher stamps each chunk
		// with a strictly-monotonic per-session counter; the query
		// only applies the append when the incoming sequence
		// strictly exceeds the stored last_sequence, so a
		// redelivered chunk is a no-op rather than a corrupting
		// double-append.
		Sequence: payload.Sequence,
	})
}
