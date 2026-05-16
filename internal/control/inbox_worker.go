package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/dyngroupeval"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
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
type InboxWorker struct {
	store    *store.Store
	aqClient *taskqueue.Client
	signer   ca.ActionSigner
	logger   *slog.Logger
}

// NewInboxWorker creates a new inbox worker.
func NewInboxWorker(st *store.Store, aqClient *taskqueue.Client, signer ca.ActionSigner, logger *slog.Logger) *InboxWorker {
	return &InboxWorker{
		store:    st,
		aqClient: aqClient,
		signer:   signer,
		logger:   logger,
	}
}

// NewMux returns an Asynq ServeMux with handlers for the main
// control inbox queue. The terminal audit chunk handler is split
// out onto its own mux (NewTerminalAuditMux) so a dedicated Asynq
// server can process it with Concurrency=1 — see the documentation
// on taskqueue.ControlTerminalAuditQueue.
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
	mux.HandleFunc(taskqueue.TypeTerminalAuditChunk, w.handleTerminalAuditChunk)
	return mux
}

func (w *InboxWorker) handleDeviceHello(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.DeviceHelloPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal device hello: %w", err)
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

	logger := w.logger.With("device_id", deviceID, "result_id", resultID)

	// Determine execution ID and action ID.
	// resultID may be an execution ID (dispatched by API) or an action ID
	// (scheduled locally by the agent). We try execution first.
	var executionID, actionID string
	var needsCreate bool

	existingExec, err := w.store.Repos().Execution.Get(ctx, resultID)
	if err == nil {
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
		// Use CompletedAt for per-run uniqueness. Fall back to DurationMs+Status
		// (stable across retries of the same result) when CompletedAt is absent.
		completedStr := fmt.Sprintf("%d:%s", result.DurationMs, result.Status.String())
		if result.CompletedAt != nil && result.CompletedAt.IsValid() {
			completedStr = result.CompletedAt.AsTime().Format(time.RFC3339Nano)
		}
		executionID = stableExecutionID(deviceID, actionID, completedStr)

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
		completedAt = time.Now()
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

func (w *InboxWorker) handleLogQueryResult(ctx context.Context, t *asynq.Task) error {
	var payload taskqueue.LogQueryResultPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal log query result: %w", err)
	}

	w.logger.Info("received log query result",
		"device_id", payload.DeviceID,
		"query_id", payload.QueryID,
		"success", payload.Success,
	)

	return w.store.Queries().CompleteLogQueryResult(ctx, db.CompleteLogQueryResultParams{
		QueryID: payload.QueryID,
		Success: payload.Success,
		Error:   payload.Error,
		Logs:    payload.Logs,
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
	// If the lookup fails (e.g. the Requested event never made it
	// to disk because the original API call crashed), fall back to
	// a fresh stream ID so we still record the Failed outcome
	// durably — an orphan Failed event is better than dropping the
	// agent-reported failure on the floor.
	luksStreamID, err := w.store.Repos().Luks.GetRevocationStreamID(ctx, store.LuksRevocationStreamKey{
		DeviceID: payload.DeviceID,
		ActionID: payload.ActionID,
	})
	switch {
	case err == nil:
		// Happy path — stream ID recovered.
	case store.IsNotFound(err):
		// Genuinely absent: the Requested event never landed
		// (original RPC crashed before append). Fall back to a
		// fresh ULID so we still record the terminal outcome —
		// an orphan Failed event is better than silently dropping
		// the agent-reported failure on the floor.
		w.logger.Warn("LUKS revocation stream ID not found — appending to a fresh stream; projection will show only the terminal event",
			"device_id", payload.DeviceID,
			"action_id", payload.ActionID,
		)
		luksStreamID = ulid.Make().String()
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
				RevokedAt: time.Now().UTC().Format(time.RFC3339Nano),
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
			FailedAt: time.Now().UTC().Format(time.RFC3339Nano),
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

	// Cache action lookups — multiple executions may reference the same
	// action (e.g., system actions assigned to many devices).
	actionCache := make(map[string][]byte) // actionID → paramsCanonical

	var enqueueErrs []error
	for _, exec := range executions {
		// Parse params from []byte to avoid base64 encoding
		var params json.RawMessage
		if len(exec.Params) > 0 {
			params = exec.Params
		}

		// Re-sign the action with the execution ID. The gateway sets
		// Action.Id = executionID, so the agent verifies the signature
		// against the execution ID — not the original action ID the
		// action was signed with. This mirrors the API dispatch handler.
		//
		// Signing failures are permanent (missing signer, deleted action,
		// broken key) — skip silently rather than returning an error that
		// would cause Asynq to retry the entire hello handler.
		var signature, paramsCanonical []byte
		if exec.ActionID != nil {
			if w.signer == nil {
				logger.Error("cannot dispatch execution without signer",
					"execution_id", exec.ID, "action_id", *exec.ActionID)
				continue
			}
			cached, ok := actionCache[*exec.ActionID]
			if !ok {
				action, err := w.store.Repos().Action.Get(ctx, *exec.ActionID)
				if err != nil {
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
								CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
							},
							ActorType: "system",
							ActorID:   "dispatcher",
						}); appendErr != nil {
							logger.Error("failed to mark orphaned execution as failed",
								"execution_id", exec.ID, "error", appendErr)
						}
						continue
					}
					logger.Error("failed to look up action for re-signing, skipping dispatch",
						"execution_id", exec.ID, "action_id", *exec.ActionID, "error", err)
					continue
				}
				cached = action.ParamsCanonical
				actionCache[*exec.ActionID] = cached
			}
			paramsCanonical = cached
			if paramsCanonical == nil {
				paramsCanonical = exec.Params
			}
			sig, err := w.signer.Sign(exec.ID, exec.ActionType, paramsCanonical)
			if err != nil {
				logger.Error("failed to re-sign action for dispatch, skipping",
					"execution_id", exec.ID, "action_id", *exec.ActionID, "error", err)
				continue
			}
			signature = sig
		}

		// Enqueue to device queue first — only record the event after the
		// task is durably queued so we never mark "dispatched" without delivery.
		// Use a stable TaskID so retries don't create duplicate tasks.
		if err := w.aqClient.EnqueueToDevice(deviceID, taskqueue.TypeActionDispatch, taskqueue.ActionDispatchPayload{
			ExecutionID:     exec.ID,
			ActionType:      exec.ActionType,
			DesiredState:    exec.DesiredState,
			Params:          params,
			TimeoutSeconds:  exec.TimeoutSeconds,
			Signature:       signature,
			ParamsCanonical: paramsCanonical,
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

// commandOutputPayload converts a CommandOutput proto into the typed
// payloads.CommandOutput used by the execution-event payload structs.
// Returns nil for nil input so payloads.RawCommandOutput drops the
// field via omitempty.
func commandOutputPayload(o *pm.CommandOutput) *payloads.CommandOutput {
	if o == nil {
		return nil
	}
	return &payloads.CommandOutput{
		Stdout:   o.Stdout,
		Stderr:   o.Stderr,
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

func stableExecutionID(deviceID, actionID, completedAt string) string {
	h := sha256.Sum256([]byte("exec:" + deviceID + ":" + actionID + ":" + completedAt))
	var id ulid.ULID
	copy(id[:], h[:16])
	return id.String()
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
// The sqlc query uses INSERT ... ON CONFLICT so a chunk arriving
// before the lifecycle Started event still creates a valid row;
// the Started handler's upsert then completes the metadata.
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

	return w.store.Queries().AppendTerminalSessionChunk(ctx, db.AppendTerminalSessionChunkParams{
		SessionID: payload.SessionID,
		DeviceID:  payload.DeviceID,
		UserID:    payload.UserID,
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
