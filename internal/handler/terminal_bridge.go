package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/taskqueue"

	"github.com/oklog/ulid/v2"
)

const (
	// terminalStartTimeout is how long we wait for the agent to
	// respond with STARTED after sending TerminalStart.
	terminalStartTimeout = 30 * time.Second
)

// TerminalBridgeHandler is the HTTP handler for the gateway's
// WebSocket terminal endpoint. It validates the session token against
// the control server, bridges WebSocket frames to/from the agent's
// bidi stream via the connection manager and terminal session
// registry, and tees stdin to the audit queue.
type TerminalBridgeHandler struct {
	manager       *connection.Manager
	sessions      *connection.TerminalSessionRegistry
	controlProxy  *ControlProxy
	aqClient      *taskqueue.Client
	logger        *slog.Logger
}

// NewTerminalBridgeHandler constructs a bridge handler.
func NewTerminalBridgeHandler(
	manager *connection.Manager,
	sessions *connection.TerminalSessionRegistry,
	controlProxy *ControlProxy,
	aqClient *taskqueue.Client,
	logger *slog.Logger,
) *TerminalBridgeHandler {
	return &TerminalBridgeHandler{
		manager:      manager,
		sessions:     sessions,
		controlProxy: controlProxy,
		aqClient:     aqClient,
		logger:       logger,
	}
}

// ServeHTTP handles the /terminal WebSocket endpoint.
func (h *TerminalBridgeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	token := r.URL.Query().Get("token")
	if sessionID == "" || token == "" {
		http.Error(w, "session_id and token query parameters are required", http.StatusBadRequest)
		return
	}

	logger := h.logger.With("session_id", sessionID)

	// Validate the token against the control server. This returns
	// the session metadata (device_id, tty_user, cols, rows, user_id)
	// or an error if the token is invalid/expired.
	validated, err := h.controlProxy.ValidateTerminalToken(r.Context(), sessionID, token)
	if err != nil {
		logger.Warn("terminal token validation failed", "error", err)
		http.Error(w, "invalid or expired session token", http.StatusUnauthorized)
		return
	}
	logger = logger.With("device_id", validated.DeviceId, "user_id", validated.UserId)

	// Verify the agent is connected to THIS gateway.
	if !h.manager.IsConnected(validated.DeviceId) {
		logger.Warn("device not connected to this gateway")
		http.Error(w, "device not connected to this gateway", http.StatusServiceUnavailable)
		return
	}

	// Upgrade to WebSocket.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The gateway sits behind a reverse proxy that may strip the
		// Origin header. InsecureSkipVerify is safe here because the
		// session token is the authentication mechanism, not CORS.
		InsecureSkipVerify: true,
	})
	if err != nil {
		logger.Warn("websocket upgrade failed", "error", err)
		return
	}
	defer ws.CloseNow()

	// Register the session so agent messages get routed to us.
	sess := connection.NewTerminalSession(
		sessionID,
		validated.DeviceId,
		validated.UserId,
		validated.TtyUser,
		validated.Cols,
		validated.Rows,
	)
	h.sessions.Register(sess)
	defer h.sessions.Unregister(sessionID)

	logger.Info("terminal bridge session started",
		"tty_user", validated.TtyUser,
		"cols", validated.Cols,
		"rows", validated.Rows,
	)

	// Send TerminalStart to the agent.
	startMsg := &pm.ServerMessage{
		Id: ulid.Make().String(),
		Payload: &pm.ServerMessage_TerminalStart{
			TerminalStart: &pm.TerminalStart{
				SessionId: sessionID,
				TtyUser:   validated.TtyUser,
				Cols:      validated.Cols,
				Rows:      validated.Rows,
			},
		},
	}
	if err := h.manager.Send(validated.DeviceId, startMsg); err != nil {
		logger.Error("failed to send TerminalStart to agent", "error", err)
		ws.Close(websocket.StatusInternalError, "failed to start terminal on device")
		return
	}

	// Wait for the agent to respond with STARTED or ERROR.
	if err := h.waitForStarted(sess, ws, logger); err != nil {
		// waitForStarted already closed the WebSocket with an
		// appropriate status. Just return.
		return
	}

	// Enter the bidirectional I/O bridge. Two goroutines: one reads
	// from the WebSocket and forwards to the agent, the other reads
	// from the agent (via the session's OutputCh) and forwards to
	// the WebSocket. When either side ends, the other is cancelled.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Track whether we've sent TerminalStop to avoid double-stop.
	var stopSent atomic.Bool

	sendStop := func(reason string) {
		if !stopSent.CompareAndSwap(false, true) {
			return
		}
		stopMsg := &pm.ServerMessage{
			Id: ulid.Make().String(),
			Payload: &pm.ServerMessage_TerminalStop{
				TerminalStop: &pm.TerminalStop{
					SessionId: sessionID,
					Reason:    reason,
				},
			},
		}
		if err := h.manager.Send(validated.DeviceId, stopMsg); err != nil {
			logger.Debug("failed to send TerminalStop (agent may have disconnected)",
				"error", err)
		}
	}
	defer sendStop("websocket closed")

	// WS → agent goroutine.
	wsErrCh := make(chan error, 1)
	go func() {
		wsErrCh <- h.bridgeWSToAgent(ctx, ws, sess, validated, logger)
	}()

	// Agent → WS goroutine.
	agentErrCh := make(chan error, 1)
	go func() {
		agentErrCh <- h.bridgeAgentToWS(ctx, ws, sess, logger)
	}()

	// Wait for either side to finish. Cancel the other.
	select {
	case err := <-wsErrCh:
		if err != nil {
			logger.Debug("ws→agent bridge ended", "error", err)
		}
		cancel()
		sendStop("client disconnected")
	case err := <-agentErrCh:
		if err != nil {
			logger.Debug("agent→ws bridge ended", "error", err)
		}
		cancel()
		// Don't send TerminalStop — the agent initiated the close.
		stopSent.Store(true)
	}

	// Wait for the other goroutine to finish so we don't leak it.
	select {
	case <-wsErrCh:
	case <-agentErrCh:
	case <-time.After(5 * time.Second):
	}

	ws.Close(websocket.StatusNormalClosure, "session ended")
	logger.Info("terminal bridge session ended")
}

// waitForStarted blocks until the agent sends a TerminalStateChange
// with state STARTED, or returns an error (and closes the WebSocket)
// if it sees ERROR or times out.
func (h *TerminalBridgeHandler) waitForStarted(sess *connection.TerminalSession, ws *websocket.Conn, logger *slog.Logger) error {
	timer := time.NewTimer(terminalStartTimeout)
	defer timer.Stop()

	for {
		select {
		case msg, ok := <-sess.OutputCh:
			if !ok {
				ws.Close(websocket.StatusInternalError, "session channel closed unexpectedly")
				return fmt.Errorf("output channel closed before STARTED")
			}
			sc, ok := msg.Payload.(*pm.AgentMessage_TerminalStateChange)
			if !ok {
				// Unexpected message type before STARTED — could be
				// output from a previous session's stale frame. Drop it.
				continue
			}
			switch sc.TerminalStateChange.State {
			case pm.TerminalSessionState_TERMINAL_SESSION_STATE_STARTED:
				logger.Info("agent confirmed terminal session started")
				return nil
			case pm.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR:
				errMsg := sc.TerminalStateChange.Error
				logger.Warn("agent rejected terminal session", "error", errMsg)
				ws.Close(websocket.StatusInternalError, "agent error: "+errMsg)
				return fmt.Errorf("agent error: %s", errMsg)
			case pm.TerminalSessionState_TERMINAL_SESSION_STATE_EXITED:
				logger.Warn("agent session exited before STARTED",
					"exit_code", sc.TerminalStateChange.ExitCode)
				ws.Close(websocket.StatusInternalError, "session exited prematurely")
				return fmt.Errorf("session exited before STARTED")
			}
		case <-timer.C:
			logger.Warn("timed out waiting for agent STARTED")
			ws.Close(websocket.StatusInternalError, "terminal start timed out")
			return fmt.Errorf("terminal start timed out")
		}
	}
}

// resizeMessage is the JSON control message the web client sends in
// a text WebSocket frame to request a terminal window resize.
type resizeMessage struct {
	Type string `json:"type"`
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

// bridgeWSToAgent reads frames from the WebSocket and forwards them
// to the agent. Binary frames become TerminalInput; text frames are
// parsed as JSON control messages (currently only "resize").
// Also tees stdin to the audit queue.
func (h *TerminalBridgeHandler) bridgeWSToAgent(
	ctx context.Context,
	ws *websocket.Conn,
	sess *connection.TerminalSession,
	validated *pm.InternalValidateTerminalTokenResponse,
	logger *slog.Logger,
) error {
	var auditSeq int64

	for {
		msgType, data, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		sess.Touch()

		switch msgType {
		case websocket.MessageBinary:
			// Forward as TerminalInput.
			inputMsg := &pm.ServerMessage{
				Id: ulid.Make().String(),
				Payload: &pm.ServerMessage_TerminalInput{
					TerminalInput: &pm.TerminalInput{
						SessionId: sess.SessionID,
						Data:      data,
					},
				},
			}
			if err := h.manager.Send(validated.DeviceId, inputMsg); err != nil {
				return fmt.Errorf("send terminal input: %w", err)
			}

			// Audit tee: enqueue stdin to control:inbox.
			auditSeq++
			h.enqueueAuditChunk(sess, validated, data, auditSeq)

		case websocket.MessageText:
			// JSON control message.
			var ctrl resizeMessage
			if err := json.Unmarshal(data, &ctrl); err != nil {
				logger.Debug("invalid terminal control message", "error", err)
				continue
			}
			if ctrl.Type == "resize" && ctrl.Cols > 0 && ctrl.Rows > 0 {
				resizeMsg := &pm.ServerMessage{
					Id: ulid.Make().String(),
					Payload: &pm.ServerMessage_TerminalResize{
						TerminalResize: &pm.TerminalResize{
							SessionId: sess.SessionID,
							Cols:      ctrl.Cols,
							Rows:      ctrl.Rows,
						},
					},
				}
				if err := h.manager.Send(validated.DeviceId, resizeMsg); err != nil {
					logger.Warn("failed to send resize", "error", err)
				}
			}
		}
	}
}

// bridgeAgentToWS reads messages from the session's OutputCh and
// forwards them to the WebSocket. TerminalOutput becomes a binary
// frame; TerminalStateChange with EXITED or ERROR ends the bridge.
func (h *TerminalBridgeHandler) bridgeAgentToWS(
	ctx context.Context,
	ws *websocket.Conn,
	sess *connection.TerminalSession,
	logger *slog.Logger,
) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-sess.OutputCh:
			if !ok {
				return fmt.Errorf("output channel closed")
			}
			sess.Touch()

			switch p := msg.Payload.(type) {
			case *pm.AgentMessage_TerminalOutput:
				if err := ws.Write(ctx, websocket.MessageBinary, p.TerminalOutput.Data); err != nil {
					return fmt.Errorf("write terminal output: %w", err)
				}
			case *pm.AgentMessage_TerminalStateChange:
				switch p.TerminalStateChange.State {
				case pm.TerminalSessionState_TERMINAL_SESSION_STATE_EXITED:
					logger.Info("agent session exited",
						"exit_code", p.TerminalStateChange.ExitCode)
					return nil
				case pm.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR:
					logger.Warn("agent session error",
						"error", p.TerminalStateChange.Error)
					return fmt.Errorf("agent error: %s", p.TerminalStateChange.Error)
				}
			}
		}
	}
}

// enqueueAuditChunk sends a stdin chunk to the control:inbox queue
// for audit persistence. Best-effort: a failure is logged but does
// not break the session.
func (h *TerminalBridgeHandler) enqueueAuditChunk(
	sess *connection.TerminalSession,
	validated *pm.InternalValidateTerminalTokenResponse,
	data []byte,
	seq int64,
) {
	if h.aqClient == nil {
		return
	}
	payload := taskqueue.TerminalAuditChunkPayload{
		SessionID: sess.SessionID,
		DeviceID:  validated.DeviceId,
		UserID:    validated.UserId,
		Data:      data,
		Sequence:  seq,
	}
	if err := h.aqClient.EnqueueToControl(taskqueue.TypeTerminalAuditChunk, payload); err != nil {
		h.logger.Debug("failed to enqueue terminal audit chunk",
			"session_id", sess.SessionID, "error", err)
	}
}
