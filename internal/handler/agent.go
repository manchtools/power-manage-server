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
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
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

	// Multi-gateway routing. registry and gatewayID are set via
	// SetGatewayRouting at startup. nil registry means single-
	// gateway mode: device→gateway entries are not published and
	// the control server falls back to its static gateway URL.
	registry  *registry.Registry
	gatewayID string

	// terminalSessions is the gateway-side registry of active
	// WebSocket terminal bridge sessions. Set via
	// SetTerminalSessions at startup. When the bidi stream handler
	// receives TerminalOutput/TerminalStateChange from an agent,
	// it routes the message to the matching bridge goroutine via
	// this registry. nil means no terminal bridge is configured.
	terminalSessions *connection.TerminalSessionRegistry
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

// SetGatewayRouting wires the multi-gateway registry into the
// handler. Called from cmd/gateway/main.go at startup. After this
// is set, every agent connect / heartbeat / disconnect publishes
// the device→gateway mapping to Valkey so the control server can
// route terminal sessions to the correct gateway. nil registry
// disables routing (single-gateway deployments).
func (h *AgentHandler) SetGatewayRouting(reg *registry.Registry, gatewayID string) {
	h.registry = reg
	h.gatewayID = gatewayID
}

// SetTerminalSessions wires the terminal session registry so the
// bidi stream handler can route TerminalOutput/TerminalStateChange
// messages from agents to the matching WebSocket bridge goroutine.
func (h *AgentHandler) SetTerminalSessions(reg *connection.TerminalSessionRegistry) {
	h.terminalSessions = reg
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

// BootstrapRedirectMiddleware returns HTTP 307 redirects when an
// agent connects to the wildcard root hostname (bootstrapHost), so
// the agent reconnects directly to this gateway's per-instance
// hostname (assignedHost) for all subsequent connections. The path
// and query are preserved verbatim, and only requests to
// bootstrapHost are intercepted — requests already addressed to
// assignedHost (or any other host) pass through unchanged.
//
// In multi-gateway HA, the load balancer routes wildcard-root
// connections to any gateway. The first gateway that receives the
// agent issues this redirect to its own hostname; the agent
// follows it (Connect-RPC's HTTP/2 client follows 307s
// transparently) and from then on every connection lands on the
// same gateway, so the connection manager has a stable
// device→gateway mapping the control server can route terminal
// sessions through.
//
// Both bootstrapHost and assignedHost are bare hostnames (no
// scheme, no port). Empty bootstrapHost disables the middleware
// entirely — single-gateway deployments don't need it. Empty
// assignedHost is a programming error and panics at construction
// time so we never silently emit redirects to an empty Location.
func BootstrapRedirectMiddleware(next http.Handler, bootstrapHost, assignedHost string, logger *slog.Logger) http.Handler {
	if bootstrapHost == "" {
		// Bootstrap not configured — pass through unchanged.
		return next
	}
	if assignedHost == "" {
		panic("handler: BootstrapRedirectMiddleware: assignedHost must not be empty when bootstrapHost is set")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.Host is the value of the Host header (or HTTP/2
		// :authority pseudo-header). Strip any port so we compare
		// just the hostname — the agent may include the port,
		// the bootstrap config typically doesn't.
		reqHost := r.Host
		if i := indexByte(reqHost, ':'); i >= 0 {
			reqHost = reqHost[:i]
		}
		if reqHost != bootstrapHost {
			next.ServeHTTP(w, r)
			return
		}
		target := "https://" + assignedHost + r.URL.RequestURI()
		logger.Debug("bootstrap redirect",
			"from", reqHost,
			"to", assignedHost,
			"path", r.URL.Path,
		)
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})
}

// indexByte is a tiny stdlib-free helper so this file doesn't need
// the strings import for one call.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
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

	// Publish the device→gateway mapping in the multi-gateway
	// registry so ControlService.StartTerminal can route the user's
	// WebSocket to this specific gateway. Best-effort: a Valkey
	// failure here is logged but does not refuse the connection,
	// because terminal sessions are an optional feature on top of
	// the existing agent stream.
	if h.registry != nil {
		if err := h.registry.AttachDevice(ctx, deviceID, h.gatewayID, registry.DefaultDeviceTTL); err != nil {
			h.logger.Warn("failed to publish device→gateway mapping",
				"device_id", deviceID, "gateway_id", h.gatewayID, "error", err)
		}
	}

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
			// Detach from the registry too. Same race-aware pattern:
			// only delete if we're still the current connection,
			// otherwise we'd evict a freshly-attached entry from a
			// reconnect that already happened. Use Background ctx
			// because the request ctx is being torn down.
			if h.registry != nil {
				if err := h.registry.DetachDevice(context.Background(), deviceID, h.gatewayID); err != nil {
					h.logger.Warn("failed to remove device→gateway mapping",
						"device_id", deviceID, "error", err)
				}
			}
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
		return h.handleHeartbeat(deviceID, p.Heartbeat)
	case *pm.AgentMessage_ActionResult:
		return h.handleActionResult(ctx, deviceID, p.ActionResult)
	case *pm.AgentMessage_OutputChunk:
		return h.handleOutputChunk(deviceID, p.OutputChunk)
	case *pm.AgentMessage_QueryResult:
		return h.handleQueryResult(deviceID, p.QueryResult)
	case *pm.AgentMessage_Inventory:
		return h.handleInventory(deviceID, p.Inventory)
	case *pm.AgentMessage_SecurityAlert:
		return h.handleSecurityAlert(deviceID, p.SecurityAlert)
	case *pm.AgentMessage_GetLuksKey:
		return h.handleGetLuksKey(ctx, deviceID, msg.Id, p.GetLuksKey)
	case *pm.AgentMessage_StoreLuksKey:
		return h.handleStoreLuksKey(ctx, deviceID, msg.Id, p.StoreLuksKey)
	case *pm.AgentMessage_RevokeLuksDeviceKeyResult:
		return h.handleRevokeLuksResult(deviceID, p.RevokeLuksDeviceKeyResult)
	case *pm.AgentMessage_LogQueryResult:
		return h.handleLogQueryResult(deviceID, p.LogQueryResult)
	case *pm.AgentMessage_TerminalOutput:
		if h.terminalSessions != nil {
			if !h.terminalSessions.RouteAgentMessage(p.TerminalOutput.SessionId, msg) {
				h.logger.Debug("terminal output for unknown session",
					"device_id", deviceID, "session_id", p.TerminalOutput.SessionId)
			}
		}
		return nil
	case *pm.AgentMessage_TerminalStateChange:
		if h.terminalSessions != nil {
			if !h.terminalSessions.RouteAgentMessage(p.TerminalStateChange.SessionId, msg) {
				h.logger.Debug("terminal state change for unknown session",
					"device_id", deviceID, "session_id", p.TerminalStateChange.SessionId,
					"state", p.TerminalStateChange.State.String())
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown message type: %T", msg.Payload)
	}
}

func (h *AgentHandler) handleHeartbeat(deviceID string, hb *pm.Heartbeat) error {
	payload := taskqueue.DeviceHeartbeatPayload{DeviceID: deviceID}
	if hb.Uptime != nil {
		payload.UptimeSeconds = hb.Uptime.Seconds
	}
	if hb.CpuPercent > 0 {
		payload.CpuPercent = hb.CpuPercent
	}
	if hb.MemoryPercent > 0 {
		payload.MemoryPercent = hb.MemoryPercent
	}
	if hb.DiskPercent > 0 {
		payload.DiskPercent = hb.DiskPercent
	}
	// Refresh the device→gateway TTL on every heartbeat. Best-effort:
	// a Valkey failure here is logged but does not refuse the
	// heartbeat — the existing UpdateLastSeen path is the source of
	// truth for connection liveness.
	if h.registry != nil {
		if err := h.registry.RefreshDevice(context.Background(), deviceID, h.gatewayID, registry.DefaultDeviceTTL); err != nil {
			h.logger.Warn("failed to refresh device→gateway mapping",
				"device_id", deviceID, "error", err)
		}
	}
	return h.aqClient.EnqueueToControl(taskqueue.TypeDeviceHeartbeat, payload)
}

func (h *AgentHandler) handleActionResult(ctx context.Context, deviceID string, result *pm.ActionResult) error {
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

	if err := h.proxyLpsRotations(ctx, deviceID, resultID, result); err != nil {
		return err
	}

	resultJSON, err := protojson.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal action result: %w", err)
	}
	return h.aqClient.EnqueueToControl(taskqueue.TypeExecutionResult, taskqueue.ExecutionResultPayload{
		DeviceID:         deviceID,
		ActionResultJSON: resultJSON,
	})
}

// proxyLpsRotations extracts LPS password rotations from metadata, proxies them
// via encrypted RPC, and strips the key before the result is enqueued to Valkey.
// Unmarshal failures strip immediately (malformed, retry won't help).
// StoreLpsPasswords failures return an error — the agent will resend the result
// on reconnect, preserving the metadata for retry.
func (h *AgentHandler) proxyLpsRotations(ctx context.Context, deviceID, resultID string, result *pm.ActionResult) error {
	if result.Metadata == nil {
		return nil
	}
	rotationsJSON, ok := result.Metadata["lps.rotations"]
	if !ok || rotationsJSON == "" {
		return nil
	}

	var rotations []struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		RotatedAt string `json:"rotated_at"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(rotationsJSON), &rotations); err != nil {
		delete(result.Metadata, "lps.rotations")
		h.logger.Error("failed to unmarshal lps.rotations metadata", "error", err)
		return nil
	}
	if len(rotations) == 0 {
		delete(result.Metadata, "lps.rotations")
		return nil
	}

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
		return fmt.Errorf("store lps passwords: %w", err)
	}
	delete(result.Metadata, "lps.rotations")
	return nil
}

func (h *AgentHandler) handleOutputChunk(deviceID string, chunk *pm.OutputChunk) error {
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
}

func (h *AgentHandler) handleQueryResult(deviceID string, result *pm.OSQueryResult) error {
	h.logger.Info("received query result",
		"device_id", deviceID,
		"query_id", result.QueryId,
		"success", result.Success,
	)
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
}

func (h *AgentHandler) handleInventory(deviceID string, inventory *pm.DeviceInventory) error {
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
}

func (h *AgentHandler) handleSecurityAlert(deviceID string, alert *pm.SecurityAlert) error {
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
}

func (h *AgentHandler) handleGetLuksKey(ctx context.Context, deviceID, msgID string, req *pm.GetLuksKeyRequest) error {
	resp, err := h.controlProxy.GetLuksKey(ctx, deviceID, req.ActionId)
	if err != nil {
		return h.manager.Send(deviceID, &pm.ServerMessage{
			Id: msgID,
			Payload: &pm.ServerMessage_Error{
				Error: &pm.Error{
					Code:    connect.CodeNotFound.String(),
					Message: "no LUKS key found for this action",
				},
			},
		})
	}
	return h.manager.Send(deviceID, &pm.ServerMessage{
		Id: msgID,
		Payload: &pm.ServerMessage_GetLuksKey{
			GetLuksKey: resp,
		},
	})
}

func (h *AgentHandler) handleStoreLuksKey(ctx context.Context, deviceID, msgID string, req *pm.StoreLuksKeyRequest) error {
	resp, err := h.controlProxy.StoreLuksKey(ctx, deviceID, req.ActionId, req.DevicePath, req.Passphrase, req.RotationReason)
	if err != nil {
		return h.manager.Send(deviceID, &pm.ServerMessage{
			Id: msgID,
			Payload: &pm.ServerMessage_Error{
				Error: &pm.Error{
					Code:    connect.CodeInternal.String(),
					Message: fmt.Sprintf("failed to store LUKS key: %v", err),
				},
			},
		})
	}
	return h.manager.Send(deviceID, &pm.ServerMessage{
		Id: msgID,
		Payload: &pm.ServerMessage_StoreLuksKey{
			StoreLuksKey: resp,
		},
	})
}

func (h *AgentHandler) handleRevokeLuksResult(deviceID string, result *pm.RevokeLuksDeviceKeyResult) error {
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
}

func (h *AgentHandler) handleLogQueryResult(deviceID string, result *pm.LogQueryResult) error {
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
