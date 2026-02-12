// Package handler implements the Connect-RPC service handlers.
package handler

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// contextKey is a custom type for context keys.
type contextKey string

const (
	// DeviceIDContextKey is the context key for the device ID extracted from mTLS.
	DeviceIDContextKey contextKey = "device_id"
)

// AgentHandler implements the AgentService.
type AgentHandler struct {
	pmv1connect.UnimplementedAgentServiceHandler

	manager    *connection.Manager
	store      *store.Store
	logger     *slog.Logger
	requireTLS bool
}

// NewAgentHandler creates a new agent handler.
func NewAgentHandler(manager *connection.Manager, s *store.Store, logger *slog.Logger) *AgentHandler {
	return &AgentHandler{
		manager:    manager,
		store:      s,
		logger:     logger,
		requireTLS: false,
	}
}

// NewAgentHandlerWithTLS creates a new agent handler that requires mTLS.
func NewAgentHandlerWithTLS(manager *connection.Manager, s *store.Store, logger *slog.Logger) *AgentHandler {
	return &AgentHandler{
		manager:    manager,
		store:      s,
		logger:     logger,
		requireTLS: true,
	}
}

// MTLSMiddleware extracts the device ID from the client certificate and adds it to the context.
func MTLSMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip TLS check for health endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract device ID from client certificate
		deviceID, err := mtls.DeviceIDFromRequest(r)
		if err != nil {
			logger.Warn("mTLS authentication failed",
				"error", err,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}

		// Add device ID to context
		ctx := context.WithValue(r.Context(), DeviceIDContextKey, deviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DeviceIDFromContext extracts the device ID from the context.
func DeviceIDFromContext(ctx context.Context) (string, bool) {
	deviceID, ok := ctx.Value(DeviceIDContextKey).(string)
	return deviceID, ok
}

// Stream handles the bidirectional stream between agent and server.
// The stream is used for:
// - Receiving heartbeats and execution results from agents
// - Future one-off actions (like restart commands)
// Note: Regular action sync is handled via the SyncActions RPC, not via push.
func (h *AgentHandler) Stream(ctx context.Context, stream *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) (err error) {
	// Recover from panics to prevent server crashes
	defer func() {
		if r := recover(); r != nil {
			h.logger.Error("panic in stream handler", "panic", r)
			err = connect.NewError(connect.CodeInternal, fmt.Errorf("internal error: %v", r))
		}
	}()

	// Get device ID from mTLS context (if TLS is enabled)
	var certDeviceID string
	if h.requireTLS {
		var ok bool
		certDeviceID, ok = DeviceIDFromContext(ctx)
		if !ok {
			return connect.NewError(connect.CodeUnauthenticated, errors.New("mTLS authentication required"))
		}
	}

	// Wait for Hello message
	msg, err := stream.Receive()
	if err != nil {
		return fmt.Errorf("receive hello: %w", err)
	}

	hello := msg.GetHello()
	if hello == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first message must be Hello"))
	}

	deviceID := hello.DeviceId.GetValue()
	if deviceID == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("device ID required"))
	}

	// If mTLS is enabled, verify that the device ID in the Hello matches the certificate
	if h.requireTLS && certDeviceID != deviceID {
		h.logger.Warn("device ID mismatch",
			"cert_device_id", certDeviceID,
			"hello_device_id", deviceID,
		)
		return connect.NewError(connect.CodePermissionDenied, errors.New("device ID does not match certificate"))
	}

	h.logger.Info("agent connected",
		"device_id", deviceID,
		"hostname", hello.Hostname,
		"version", hello.AgentVersion,
		"mtls", h.requireTLS,
	)

	// Register the agent connection
	h.manager.Register(deviceID, hello.Hostname, hello.AgentVersion, stream)

	// Subscribe to agent-specific notification channel so dispatcher can forward actions
	agentChannel := fmt.Sprintf("agent_%s", deviceID)
	if err := h.store.ListenChannel(ctx, agentChannel); err != nil {
		h.logger.Warn("failed to subscribe to agent channel", "channel", agentChannel, "error", err)
	} else {
		h.logger.Debug("subscribed to agent channel", "channel", agentChannel)
	}

	defer func() {
		// Unsubscribe from agent channel
		if err := h.store.UnlistenChannel(context.Background(), agentChannel); err != nil {
			h.logger.Warn("failed to unsubscribe from agent channel", "channel", agentChannel, "error", err)
		}
		h.manager.Unregister(deviceID)
		h.logger.Info("agent disconnected", "device_id", deviceID)
	}()

	// Record heartbeat event for the hello
	if err := h.recordHeartbeat(ctx, deviceID, hello.AgentVersion); err != nil {
		h.logger.Warn("failed to record heartbeat", "error", err)
	}

	// Notify control server about agent connection so it can dispatch pending actions
	if err := h.notifyControlHello(ctx, deviceID, hello.Hostname, hello.AgentVersion); err != nil {
		h.logger.Warn("failed to notify control server", "error", err)
	}

	// Process incoming messages from agent
	for {
		msg, err := stream.Receive()
		if err != nil {
			return err
		}

		h.manager.UpdateLastSeen(deviceID)

		if err := h.handleAgentMessage(ctx, deviceID, msg); err != nil {
			h.logger.Warn("handle agent message",
				"device_id", deviceID,
				"error", err,
			)
		}
	}
}

// recordHeartbeat records a device heartbeat event.
func (h *AgentHandler) recordHeartbeat(ctx context.Context, deviceID, agentVersion string) error {
	return h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceHeartbeat",
		Data: map[string]any{
			"agent_version": agentVersion,
		},
		ActorType: "device",
		ActorID:   deviceID,
	})
}

// notifyControlHello notifies the control server that an agent has connected.
// This triggers the control server to dispatch any pending actions to the agent.
func (h *AgentHandler) notifyControlHello(ctx context.Context, deviceID, hostname, agentVersion string) error {
	msgID := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()

	payload, err := json.Marshal(map[string]string{
		"hostname":      hostname,
		"agent_version": agentVersion,
	})
	if err != nil {
		return fmt.Errorf("marshal hello payload: %w", err)
	}

	msg := map[string]any{
		"type":       "hello",
		"device_id":  deviceID,
		"message_id": msgID,
		"payload":    json.RawMessage(payload),
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal control message: %w", err)
	}

	return h.store.Notify(ctx, "control_inbox", string(msgBytes))
}

// handleAgentMessage processes messages from the agent and records events.
func (h *AgentHandler) handleAgentMessage(ctx context.Context, deviceID string, msg *pm.AgentMessage) error {
	switch p := msg.Payload.(type) {
	case *pm.AgentMessage_Heartbeat:
		// Record heartbeat event with metrics
		data := map[string]any{}
		if p.Heartbeat.Uptime != nil {
			data["uptime_seconds"] = p.Heartbeat.Uptime.Seconds
		}
		if p.Heartbeat.CpuPercent > 0 {
			data["cpu_percent"] = p.Heartbeat.CpuPercent
		}
		if p.Heartbeat.MemoryPercent > 0 {
			data["memory_percent"] = p.Heartbeat.MemoryPercent
		}
		if p.Heartbeat.DiskPercent > 0 {
			data["disk_percent"] = p.Heartbeat.DiskPercent
		}

		return h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   deviceID,
			EventType:  "DeviceHeartbeat",
			Data:       data,
			ActorType:  "device",
			ActorID:    deviceID,
		})

	case *pm.AgentMessage_ActionResult:
		// Record execution result event
		result := p.ActionResult
		if result.ActionId == nil {
			return fmt.Errorf("action result missing action ID")
		}
		resultID := result.ActionId.GetValue()
		if resultID == "" {
			return fmt.Errorf("action result has empty action ID")
		}

		// The resultID could be either:
		// 1. An execution ID (for dispatched actions from the server)
		// 2. An action ID (for agent-scheduled actions)
		//
		// Try to look up an existing execution first. If found, we update it.
		// If not found, we create a new execution record.
		var executionID string
		var actionID string
		var needsCreate bool

		existingExec, err := h.store.Queries().GetExecutionByID(ctx, resultID)
		if err == nil {
			// Found existing execution - this was a dispatched action
			executionID = existingExec.ID
			if existingExec.ActionID != nil {
				actionID = *existingExec.ActionID
			}
			needsCreate = false
			h.logger.Info("received result for dispatched action",
				"device_id", deviceID,
				"execution_id", executionID,
				"action_id", actionID,
				"status", result.Status.String(),
				"duration_ms", result.DurationMs,
			)
		} else {
			// No existing execution - this is an agent-scheduled action
			// resultID is the action ID, generate a new execution ID
			actionID = resultID
			executionID = ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
			needsCreate = true
			h.logger.Info("received result for agent-scheduled action",
				"device_id", deviceID,
				"action_id", actionID,
				"execution_id", executionID,
				"status", result.Status.String(),
				"duration_ms", result.DurationMs,
			)
		}

		// Calculate execution timestamps from agent data
		// executed_at = completed_at - duration_ms (when the action started on the agent)
		var executedAt, completedAt time.Time
		if result.CompletedAt != nil && result.CompletedAt.IsValid() {
			completedAt = result.CompletedAt.AsTime()
			executedAt = completedAt.Add(-time.Duration(result.DurationMs) * time.Millisecond)
		} else {
			// Fallback to current time if agent didn't provide timestamp
			completedAt = time.Now()
			executedAt = completedAt.Add(-time.Duration(result.DurationMs) * time.Millisecond)
		}

		// Only create ExecutionCreated event if this is a new execution (agent-scheduled action)
		if needsCreate {
			// Look up the action to get its details for the ExecutionCreated event
			action, err := h.store.Queries().GetActionByID(ctx, actionID)
			if err != nil {
				h.logger.Warn("could not look up action for execution result",
					"action_id", actionID,
					"error", err,
				)
				// Fall back to creating execution with minimal data
				action.ActionType = 0 // UNSPECIFIED
				action.Params = nil
				action.TimeoutSeconds = 300
			}

			createdData := map[string]any{
				"device_id":       deviceID,
				"action_id":       actionID,
				"action_type":     action.ActionType,
				"desired_state":   0, // Default to PRESENT for agent-reported results
				"params":          json.RawMessage(action.Params),
				"timeout_seconds": action.TimeoutSeconds,
				"executed_at":     executedAt.Format(time.RFC3339Nano), // When execution started on agent
			}
			if err := h.store.AppendEvent(ctx, store.Event{
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

		// Now append the completion/result event
		var eventType string
		var data map[string]any

		switch result.Status {
		case pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS:
			eventType = "ExecutionCompleted"
			data = map[string]any{
				"duration_ms":  result.DurationMs,
				"completed_at": completedAt.Format(time.RFC3339Nano),
				"changed":      result.Changed,
			}
			if result.Output != nil {
				data["output"] = map[string]any{
					"stdout":    result.Output.Stdout,
					"stderr":    result.Output.Stderr,
					"exit_code": result.Output.ExitCode,
				}
			}

		case pm.ExecutionStatus_EXECUTION_STATUS_FAILED:
			eventType = "ExecutionFailed"
			data = map[string]any{
				"error":        result.Error,
				"duration_ms":  result.DurationMs,
				"completed_at": completedAt.Format(time.RFC3339Nano),
				"changed":      result.Changed,
			}
			if result.Output != nil {
				data["output"] = map[string]any{
					"stdout":    result.Output.Stdout,
					"stderr":    result.Output.Stderr,
					"exit_code": result.Output.ExitCode,
				}
			}

		case pm.ExecutionStatus_EXECUTION_STATUS_RUNNING:
			eventType = "ExecutionStarted"
			data = map[string]any{}

		case pm.ExecutionStatus_EXECUTION_STATUS_TIMEOUT:
			eventType = "ExecutionTimedOut"
			data = map[string]any{
				"error":        result.Error,
				"duration_ms":  result.DurationMs,
				"completed_at": completedAt.Format(time.RFC3339Nano),
			}
			if result.Output != nil {
				data["output"] = map[string]any{
					"stdout":    result.Output.Stdout,
					"stderr":    result.Output.Stderr,
					"exit_code": result.Output.ExitCode,
				}
			}

		case pm.ExecutionStatus_EXECUTION_STATUS_SKIPPED:
			eventType = "ExecutionSkipped"
			data = map[string]any{}
			if result.Error != "" {
				data["reason"] = result.Error
			}

		default:
			return fmt.Errorf("unknown execution status: %v", result.Status)
		}

		// Check for LPS password rotations and store each separately
		if result.Metadata != nil {
			if rotationsJSON, ok := result.Metadata["lps.rotations"]; ok && rotationsJSON != "" {
				var rotations []struct {
					Username  string `json:"username"`
					Password  string `json:"password"`
					RotatedAt string `json:"rotated_at"`
					Reason    string `json:"reason"`
				}
				if err := json.Unmarshal([]byte(rotationsJSON), &rotations); err == nil {
					for _, r := range rotations {
						lpsStreamID := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
						h.store.AppendEvent(ctx, store.Event{
							StreamType: "lps_password",
							StreamID:   lpsStreamID,
							EventType:  "LpsPasswordRotated",
							Data: map[string]any{
								"device_id":       deviceID,
								"action_id":       actionID,
								"username":        r.Username,
								"password":        r.Password,
								"rotated_at":      r.RotatedAt,
								"rotation_reason": r.Reason,
							},
							ActorType: "device",
							ActorID:   deviceID,
						})
					}
				}
			}
		}

		return h.store.AppendEvent(ctx, store.Event{
			StreamType: "execution",
			StreamID:   executionID,
			EventType:  eventType,
			Data:       data,
			ActorType:  "device",
			ActorID:    deviceID,
		})

	case *pm.AgentMessage_OutputChunk:
		// Store output chunk as an event for later retrieval
		chunk := p.OutputChunk
		if chunk.ExecutionId == "" {
			return fmt.Errorf("output chunk missing execution ID")
		}

		streamType := "stdout"
		if chunk.Stream == pm.OutputStreamType_OUTPUT_STREAM_TYPE_STDERR {
			streamType = "stderr"
		}

		h.logger.Debug("received output chunk",
			"device_id", deviceID,
			"execution_id", chunk.ExecutionId,
			"stream", streamType,
			"sequence", chunk.Sequence,
			"size", len(chunk.Data),
		)

		return h.store.AppendEvent(ctx, store.Event{
			StreamType: "execution",
			StreamID:   chunk.ExecutionId,
			EventType:  "OutputChunk",
			Data: map[string]any{
				"stream":   streamType,
				"data":     string(chunk.Data),
				"sequence": chunk.Sequence,
			},
			ActorType: "device",
			ActorID:   deviceID,
		})

	case *pm.AgentMessage_QueryResult:
		// For now, just log query results
		h.logger.Info("received query result",
			"device_id", deviceID,
			"query_id", p.QueryResult.QueryId,
		)
		return nil

	case *pm.AgentMessage_SecurityAlert:
		alert := p.SecurityAlert
		h.logger.Warn("received security alert from device",
			"device_id", deviceID,
			"alert_type", alert.Type.String(),
			"message", alert.Message,
			"details", alert.Details,
		)

		// Store security alert as an event for audit trail
		return h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   deviceID,
			EventType:  "SecurityAlert",
			Data: map[string]any{
				"alert_type": alert.Type.String(),
				"message":    alert.Message,
				"details":    alert.Details,
			},
			ActorType: "device",
			ActorID:   deviceID,
		})

	default:
		return fmt.Errorf("unknown message type: %T", msg.Payload)
	}
}

// SyncActions returns all actions currently assigned to a device.
// The agent calls this on successful connection to sync its local action store.
func (h *AgentHandler) SyncActions(ctx context.Context, req *connect.Request[pm.SyncActionsRequest]) (*connect.Response[pm.SyncActionsResponse], error) {
	deviceID := req.Msg.DeviceId.GetValue()
	if deviceID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id is required"))
	}

	h.logger.Info("agent syncing actions", "device_id", deviceID)

	// Get all resolved actions for this device (with desired_state computed from assignment modes)
	dbActions, err := h.store.Queries().ListResolvedActionsForDevice(ctx, deviceID)
	if err != nil {
		h.logger.Error("failed to list resolved actions", "device_id", deviceID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get assigned actions"))
	}

	// Get the effective sync interval for this device
	syncInterval, err := h.store.Queries().GetDeviceSyncInterval(ctx, deviceID)
	if err != nil {
		h.logger.Warn("failed to get sync interval, using default", "device_id", deviceID, "error", err)
		syncInterval = 0 // Use default
	}

	// Convert to wire format (Action messages)
	actions := make([]*pm.Action, 0, len(dbActions))
	for _, dbAction := range dbActions {
		action := dbResolvedActionToWireAction(dbAction)
		if action != nil {
			actions = append(actions, action)
		}
	}

	h.logger.Info("returning synced actions", "device_id", deviceID, "count", len(actions), "sync_interval_minutes", syncInterval)

	return connect.NewResponse(&pm.SyncActionsResponse{
		Actions:             actions,
		SyncIntervalMinutes: syncInterval,
	}), nil
}

// dbResolvedActionToWireAction converts a resolved action row (with computed desired_state) to wire format.
func dbResolvedActionToWireAction(a db.ListResolvedActionsForDeviceRow) *pm.Action {
	action := &pm.Action{
		Id:              &pm.ActionId{Value: a.ID},
		Type:            pm.ActionType(a.ActionType),
		DesiredState:    pm.DesiredState(a.DesiredState),
		TimeoutSeconds:  a.TimeoutSeconds,
		Signature:       a.Signature,
		ParamsCanonical: a.ParamsCanonical,
	}

	// Parse params based on action type
	if len(a.Params) > 0 {
		parseActionParams(action, a.ActionType, a.Params)
	}

	return action
}

// dbActionToWireAction converts a database action projection to the wire format Action message.
func dbActionToWireAction(a db.ActionsProjection) *pm.Action {
	action := &pm.Action{
		Id:              &pm.ActionId{Value: a.ID},
		Type:            pm.ActionType(a.ActionType),
		DesiredState:    pm.DesiredState_DESIRED_STATE_PRESENT,
		TimeoutSeconds:  a.TimeoutSeconds,
		Signature:       a.Signature,
		ParamsCanonical: a.ParamsCanonical,
	}

	if len(a.Params) > 0 {
		parseActionParams(action, a.ActionType, a.Params)
	}

	return action
}

// parseActionParams populates the oneof Params field on a wire Action from JSON and action type.
func parseActionParams(action *pm.Action, actionType int32, paramsJSON []byte) {
	unmarshal := protojson.UnmarshalOptions{DiscardUnknown: true}

	switch pm.ActionType(actionType) {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		var p pm.PackageParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Package{Package: &p}
		}
	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		var p pm.AppInstallParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_App{App: &p}
		}
	case pm.ActionType_ACTION_TYPE_FLATPAK:
		var p pm.FlatpakParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Flatpak{Flatpak: &p}
		}
	case pm.ActionType_ACTION_TYPE_SHELL:
		var p pm.ShellParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Shell{Shell: &p}
		}
	case pm.ActionType_ACTION_TYPE_SYSTEMD:
		var p pm.SystemdParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Systemd{Systemd: &p}
		}
	case pm.ActionType_ACTION_TYPE_FILE:
		var p pm.FileParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_File{File: &p}
		}
	case pm.ActionType_ACTION_TYPE_UPDATE:
		var p pm.UpdateParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Update{Update: &p}
		}
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		var p pm.RepositoryParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Repository{Repository: &p}
		}
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		var p pm.DirectoryParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Directory{Directory: &p}
		}
	case pm.ActionType_ACTION_TYPE_USER:
		var p pm.UserParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_User{User: &p}
		}
	case pm.ActionType_ACTION_TYPE_GROUP:
		var p pm.GroupParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Group{Group: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSH:
		var p pm.SshParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Ssh{Ssh: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSHD:
		var p pm.SshdParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Sshd{Sshd: &p}
		}
	case pm.ActionType_ACTION_TYPE_SUDO:
		var p pm.SudoParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Sudo{Sudo: &p}
		}
	case pm.ActionType_ACTION_TYPE_LPS:
		var p pm.LpsParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Lps{Lps: &p}
		}
	}
}
