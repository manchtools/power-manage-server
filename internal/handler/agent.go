// Package handler implements the Connect-RPC service handlers.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/gateway"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
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

	manager       *connection.Manager
	aqClient      *taskqueue.Client
	controlProxy  *ControlProxy
	workerMgr     *gateway.DeviceWorkerManager
	logger        *slog.Logger
	serverVersion string
	requireTLS    bool
}

// NewAgentHandler creates a new agent handler.
func NewAgentHandler(
	manager *connection.Manager,
	aqClient *taskqueue.Client,
	controlProxy *ControlProxy,
	workerMgr *gateway.DeviceWorkerManager,
	serverVersion string,
	logger *slog.Logger,
) *AgentHandler {
	return &AgentHandler{
		manager:       manager,
		aqClient:      aqClient,
		controlProxy:  controlProxy,
		workerMgr:     workerMgr,
		serverVersion: serverVersion,
		logger:        logger,
		requireTLS:    false,
	}
}

// NewAgentHandlerWithTLS creates a new agent handler that requires mTLS.
func NewAgentHandlerWithTLS(
	manager *connection.Manager,
	aqClient *taskqueue.Client,
	controlProxy *ControlProxy,
	workerMgr *gateway.DeviceWorkerManager,
	serverVersion string,
	logger *slog.Logger,
) *AgentHandler {
	return &AgentHandler{
		manager:       manager,
		aqClient:      aqClient,
		controlProxy:  controlProxy,
		workerMgr:     workerMgr,
		serverVersion: serverVersion,
		logger:        logger,
		requireTLS:    true,
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

	// Verify the device exists and is not deleted on the control server.
	if err := h.controlProxy.VerifyDevice(ctx, deviceID); err != nil {
		h.logger.Warn("device verification failed, rejecting connection",
			"device_id", deviceID,
			"error", err,
		)
		return connect.NewError(connect.CodePermissionDenied, errors.New("device not found or deleted"))
	}

	h.logger.Info("agent connected",
		"device_id", deviceID,
		"hostname", hello.Hostname,
		"version", hello.AgentVersion,
		"mtls", h.requireTLS,
	)

	// Register the agent connection
	agent := h.manager.Register(deviceID, hello.Hostname, hello.AgentVersion, stream)

	// Start per-device Asynq worker to process action dispatches
	if err := h.workerMgr.StartWorker(deviceID); err != nil {
		h.logger.Warn("failed to start device worker", "device_id", deviceID, "error", err)
	}

	defer func() {
		// Only clean up if this is still the current agent connection.
		// A newer connection may have already replaced us via Register(),
		// and we must not stop its worker or unregister it.
		if current, ok := h.manager.Get(deviceID); ok && current == agent {
			h.workerMgr.StopWorker(deviceID)
		}
		// Re-check after StopWorker because it blocks during Shutdown().
		// The agent may have reconnected and replaced us while we waited.
		if current, ok := h.manager.Get(deviceID); ok && current == agent {
			h.manager.Unregister(deviceID)
		}
		h.logger.Info("agent disconnected", "device_id", deviceID)
	}()

	// Notify control server about agent connection so it can dispatch pending actions
	if err := h.aqClient.EnqueueToControl(taskqueue.TypeDeviceHello, taskqueue.DeviceHelloPayload{
		DeviceID:     deviceID,
		Hostname:     hello.Hostname,
		AgentVersion: hello.AgentVersion,
	}); err != nil {
		h.logger.Warn("failed to enqueue device hello", "error", err)
	}

	// Send Welcome message to agent with server version.
	welcome := &pm.Welcome{
		ServerVersion: h.serverVersion,
	}

	if err := h.manager.Send(deviceID, &pm.ServerMessage{
		Payload: &pm.ServerMessage_Welcome{Welcome: welcome},
	}); err != nil {
		h.logger.Warn("failed to send Welcome", "device_id", deviceID, "error", err)
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

// handleAgentMessage processes messages from the agent.
// All state changes are forwarded to the control server via Asynq or Connect-RPC proxy.
func (h *AgentHandler) handleAgentMessage(ctx context.Context, deviceID string, msg *pm.AgentMessage) error {
	switch p := msg.Payload.(type) {
	case *pm.AgentMessage_Heartbeat:
		payload := taskqueue.DeviceHeartbeatPayload{
			DeviceID: deviceID,
		}
		if p.Heartbeat.Uptime != nil {
			payload.UptimeSeconds = p.Heartbeat.Uptime.Seconds
		}
		if p.Heartbeat.CpuPercent > 0 {
			payload.CpuPercent = p.Heartbeat.CpuPercent
		}
		if p.Heartbeat.MemoryPercent > 0 {
			payload.MemoryPercent = p.Heartbeat.MemoryPercent
		}
		if p.Heartbeat.DiskPercent > 0 {
			payload.DiskPercent = p.Heartbeat.DiskPercent
		}
		return h.aqClient.EnqueueToControl(taskqueue.TypeDeviceHeartbeat, payload)

	case *pm.AgentMessage_ActionResult:
		result := p.ActionResult
		if result.ActionId == nil {
			return fmt.Errorf("action result missing action ID")
		}
		resultID := result.ActionId.GetValue()
		if resultID == "" {
			return fmt.Errorf("action result has empty action ID")
		}

		h.logger.Info("received action result",
			"device_id", deviceID,
			"result_id", resultID,
			"status", result.Status.String(),
			"duration_ms", result.DurationMs,
		)

		// Extract and proxy LPS password rotations via encrypted RPC.
		// Retry semantics: handleAgentMessage is called from the streaming
		// message loop. Unmarshal failures strip the key immediately (data is
		// malformed, retry won't help). StoreLpsPasswords failures return an
		// error — the agent will resend the result via SendActionResult on
		// reconnect, preserving the metadata for retry. The key is only
		// deleted after successful storage so plaintext passwords never reach
		// Valkey.
		if result.Metadata != nil {
			if rotationsJSON, ok := result.Metadata["lps.rotations"]; ok && rotationsJSON != "" {
				var rotations []struct {
					Username  string `json:"username"`
					Password  string `json:"password"`
					RotatedAt string `json:"rotated_at"`
					Reason    string `json:"reason"`
				}
				if err := json.Unmarshal([]byte(rotationsJSON), &rotations); err != nil {
					// Malformed — strip and log, retry won't help
					delete(result.Metadata, "lps.rotations")
					h.logger.Error("failed to unmarshal lps.rotations metadata", "error", err)
				} else if len(rotations) > 0 {
					protoRotations := make([]*pm.LpsPasswordRotation, len(rotations))
					for i, r := range rotations {
						protoRotations[i] = &pm.LpsPasswordRotation{
							Username:  r.Username,
							Password:  r.Password,
							RotatedAt: r.RotatedAt,
							Reason:    r.Reason,
						}
					}
					if err := h.controlProxy.StoreLpsPasswords(ctx, deviceID, resultID, protoRotations); err != nil {
						// Return to preserve metadata for retry on reconnect
						return fmt.Errorf("store lps passwords: %w", err)
					}
					// Stored successfully — safe to strip
					delete(result.Metadata, "lps.rotations")
				} else {
					// Empty array — strip unnecessary metadata
					delete(result.Metadata, "lps.rotations")
				}
			}
		}

		// Serialize ActionResult to protojson and enqueue to control:inbox
		resultJSON, err := protojson.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshal action result: %w", err)
		}

		return h.aqClient.EnqueueToControl(taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
			DeviceID:         deviceID,
			ActionResultJSON: resultJSON,
		})

	case *pm.AgentMessage_OutputChunk:
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

		return h.aqClient.EnqueueToControl(taskqueue.TypeExecutionOutputChunk, taskqueue.ExecutionOutputChunkPayload{
			DeviceID:    deviceID,
			ExecutionID: chunk.ExecutionId,
			Stream:      streamType,
			Data:        string(chunk.Data),
			Sequence:    int64(chunk.Sequence),
		})

	case *pm.AgentMessage_QueryResult:
		result := p.QueryResult
		h.logger.Info("received query result",
			"device_id", deviceID,
			"query_id", result.QueryId,
			"success", result.Success,
		)

		// Convert rows to JSON for storage
		var rowsJSON []map[string]string
		for _, row := range result.Rows {
			rowsJSON = append(rowsJSON, row.Data)
		}
		rowsBytes, err := json.Marshal(rowsJSON)
		if err != nil {
			rowsBytes = []byte("[]")
		}

		return h.aqClient.EnqueueToControl(taskqueue.TypeOSQueryResult, taskqueue.OSQueryResultPayload{
			DeviceID: deviceID,
			QueryID:  result.QueryId,
			Success:  result.Success,
			Error:    result.Error,
			RowsJSON: rowsBytes,
		})

	case *pm.AgentMessage_Inventory:
		inventory := p.Inventory
		h.logger.Info("received device inventory",
			"device_id", deviceID,
			"tables", len(inventory.Tables),
		)

		tables := make([]taskqueue.InventoryTable, 0, len(inventory.Tables))
		for _, table := range inventory.Tables {
			var rowsJSON []map[string]string
			for _, row := range table.Rows {
				rowsJSON = append(rowsJSON, row.Data)
			}
			rowsBytes, err := json.Marshal(rowsJSON)
			if err != nil {
				continue
			}
			tables = append(tables, taskqueue.InventoryTable{
				TableName: table.TableName,
				RowsJSON:  rowsBytes,
			})
		}

		return h.aqClient.EnqueueToControl(taskqueue.TypeInventoryUpdate, taskqueue.InventoryUpdatePayload{
			DeviceID: deviceID,
			Tables:   tables,
		})

	case *pm.AgentMessage_SecurityAlert:
		alert := p.SecurityAlert
		h.logger.Warn("received security alert from device",
			"device_id", deviceID,
			"alert_type", alert.Type.String(),
			"message", alert.Message,
			"details", alert.Details,
		)

		return h.aqClient.EnqueueToControl(taskqueue.TypeSecurityAlert, taskqueue.SecurityAlertPayload{
			DeviceID:  deviceID,
			AlertType: alert.Type.String(),
			Message:   alert.Message,
			Details:   alert.Details,
		})

	case *pm.AgentMessage_GetLuksKey:
		resp, err := h.controlProxy.GetLuksKey(ctx, deviceID, p.GetLuksKey.ActionId)
		if err != nil {
			return h.manager.Send(deviceID, &pm.ServerMessage{
				Id: msg.Id,
				Payload: &pm.ServerMessage_Error{
					Error: &pm.Error{
						Code:    connect.CodeNotFound.String(),
						Message: "no LUKS key found for this action",
					},
				},
			})
		}
		return h.manager.Send(deviceID, &pm.ServerMessage{
			Id: msg.Id,
			Payload: &pm.ServerMessage_GetLuksKey{
				GetLuksKey: resp,
			},
		})

	case *pm.AgentMessage_StoreLuksKey:
		req := p.StoreLuksKey
		resp, err := h.controlProxy.StoreLuksKey(ctx, deviceID, req.ActionId, req.DevicePath, req.Passphrase, req.RotationReason)
		if err != nil {
			return h.manager.Send(deviceID, &pm.ServerMessage{
				Id: msg.Id,
				Payload: &pm.ServerMessage_Error{
					Error: &pm.Error{
						Code:    connect.CodeInternal.String(),
						Message: fmt.Sprintf("failed to store LUKS key: %v", err),
					},
				},
			})
		}
		return h.manager.Send(deviceID, &pm.ServerMessage{
			Id: msg.Id,
			Payload: &pm.ServerMessage_StoreLuksKey{
				StoreLuksKey: resp,
			},
		})

	case *pm.AgentMessage_RevokeLuksDeviceKeyResult:
		result := p.RevokeLuksDeviceKeyResult
		h.logger.Info("received LUKS device key revocation result",
			"device_id", deviceID,
			"action_id", result.ActionId,
			"success", result.Success,
			"error", result.Error,
		)

		return h.aqClient.EnqueueToControl(taskqueue.TypeRevokeLuksDeviceKeyResult, taskqueue.RevokeLuksDeviceKeyResultPayload{
			DeviceID: deviceID,
			ActionID: result.ActionId,
			Success:  result.Success,
			Error:    result.Error,
		})

	case *pm.AgentMessage_LogQueryResult:
		result := p.LogQueryResult
		h.logger.Info("received log query result",
			"device_id", deviceID,
			"query_id", result.QueryId,
			"success", result.Success,
		)

		return h.aqClient.EnqueueToControl(taskqueue.TypeLogQueryResult, taskqueue.LogQueryResultPayload{
			DeviceID: deviceID,
			QueryID:  result.QueryId,
			Success:  result.Success,
			Error:    result.Error,
			Logs:     result.Logs,
		})

	default:
		return fmt.Errorf("unknown message type: %T", msg.Payload)
	}
}

// ValidateLuksToken validates and consumes a one-time LUKS token via the control server.
func (h *AgentHandler) ValidateLuksToken(ctx context.Context, req *connect.Request[pm.ValidateLuksTokenRequest]) (*connect.Response[pm.ValidateLuksTokenResponse], error) {
	if req.Msg.DeviceId == "" || req.Msg.Token == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id and token are required"))
	}

	resp, err := h.controlProxy.ValidateLuksToken(ctx, req.Msg.DeviceId, req.Msg.Token)
	if err != nil {
		h.logger.Warn("LUKS token validation failed", "device_id", req.Msg.DeviceId, "error", err)
		return nil, connect.NewError(connect.CodeNotFound, errors.New("token is invalid or has expired"))
	}

	return connect.NewResponse(resp), nil
}

// SyncActions returns all actions currently assigned to a device via the control server.
func (h *AgentHandler) SyncActions(ctx context.Context, req *connect.Request[pm.SyncActionsRequest]) (*connect.Response[pm.SyncActionsResponse], error) {
	deviceID := req.Msg.DeviceId.GetValue()
	if deviceID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id is required"))
	}

	// Verify mTLS certificate matches requested device ID
	if h.requireTLS {
		certDeviceID, ok := DeviceIDFromContext(ctx)
		if !ok {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("mTLS authentication required"))
		}
		if certDeviceID != deviceID {
			h.logger.Warn("SyncActions device ID mismatch", "cert_device_id", certDeviceID, "requested_device_id", deviceID)
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("device ID does not match certificate"))
		}
	}

	h.logger.Info("agent syncing actions", "device_id", deviceID)

	resp, err := h.controlProxy.SyncActions(ctx, deviceID)
	if err != nil {
		h.logger.Error("failed to proxy sync actions", "device_id", deviceID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get assigned actions"))
	}

	h.logger.Info("returning synced actions", "device_id", deviceID, "count", len(resp.Actions), "sync_interval_minutes", resp.SyncIntervalMinutes)

	return connect.NewResponse(resp), nil
}
