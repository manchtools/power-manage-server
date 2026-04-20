package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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

	// Set up TerminalStop tracking early — before sending
	// TerminalStart — so that if the handshake fails or times out,
	// the deferred cleanup still sends TerminalStop to the agent
	// and the orphaned PTY is cleaned up.
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

	// Send TerminalStart to the agent. If this fails, the deferred
	// sendStop above still fires (cleaning up any agent-side state
	// if the start was partially processed).
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

	// Wait for the agent to respond with STARTED or ERROR. If this
	// fails (timeout, agent error), the deferred sendStop fires.
	if err := h.waitForStarted(sess, ws, logger); err != nil {
		return
	}

	// Enter the bidirectional I/O bridge.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

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

	// Wait for either side to finish. Cancel the other. Track the
	// close reason so we can use an appropriate WebSocket close code.
	var closeCode websocket.StatusCode
	var closeReason string

	select {
	case err := <-wsErrCh:
		if err != nil {
			logger.Debug("ws→agent bridge ended", "error", err)
			closeCode = websocket.StatusInternalError
			closeReason = "client error"
		} else {
			closeCode = websocket.StatusNormalClosure
			closeReason = "client disconnected"
		}
		cancel()
		sendStop("client disconnected")
	case err := <-agentErrCh:
		if err != nil {
			logger.Debug("agent→ws bridge ended", "error", err)
			closeCode = websocket.StatusInternalError
			closeReason = err.Error()
		} else {
			closeCode = websocket.StatusNormalClosure
			closeReason = "session ended"
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

	ws.Close(closeCode, closeReason)
	logger.Info("terminal bridge session ended", "close_code", closeCode, "reason", closeReason)
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
				// Agent ERROR covers a mixed bag of failure paths —
				// explicit policy refusals (tty.enabled=false, locked
				// pm-tty user) alongside genuinely internal errors
				// (pty allocation, config write, etc.). Default to
				// StatusInternalError (1011, retry may help) and only
				// lift to StatusPolicyViolation (1008, retry pointless)
				// when the message is a known policy refusal. A false
				// 1008 would make clients stop retrying a transient
				// problem, which is the harm to avoid; a false 1011
				// just means the client retries a policy refusal once
				// and gets the same answer.
				//
				// Prefix matching is a stopgap — the proper fix is a
				// structured refusal reason on TerminalStateChange.
				// That requires a coordinated SDK+agent change, so it
				// lives on the roadmap.
				errMsg := sc.TerminalStateChange.Error
				closeCode := websocket.StatusInternalError
				logReason := "internal agent error"
				if isTerminalPolicyRefusal(errMsg) {
					closeCode = websocket.StatusPolicyViolation
					logReason = "agent policy refusal"
				}
				logger.Warn(logReason, "error", errMsg, "close_code", closeCode)
				ws.Close(closeCode, "agent error: "+errMsg)
				return fmt.Errorf("agent error: %s", errMsg)
			case pm.TerminalSessionState_TERMINAL_SESSION_STATE_EXITED:
				logger.Warn("agent session exited before STARTED",
					"exit_code", sc.TerminalStateChange.ExitCode)
				ws.Close(websocket.StatusInternalError, "session exited prematurely")
				return fmt.Errorf("session exited before STARTED")
			}
		case <-timer.C:
			// rc6: timeout is transient — the agent's bidi stream may
			// be briefly stalled (network hiccup, slow pty spawn).
			// StatusTryAgainLater (1013) tells clients that a retry
			// is likely to succeed, distinct from the hard-policy and
			// internal-bug cases.
			logger.Warn("timed out waiting for agent STARTED")
			ws.Close(websocket.StatusTryAgainLater, "terminal start timed out")
			return fmt.Errorf("terminal start timed out")
		}
	}
}

// isTerminalPolicyRefusal returns true iff the agent's error message
// identifies a policy / configuration refusal that no retry will
// recover from — so the bridge can close the WebSocket with
// StatusPolicyViolation (1008) instead of the retryable
// StatusInternalError (1011).
//
// Conservative by design: unknown messages fall back to the
// retryable code. The strings here are matched against the exact
// failTerminalStart messages emitted by the agent's terminal
// handler; see agent/internal/handler/terminal.go.
func isTerminalPolicyRefusal(errMsg string) bool {
	switch {
	case strings.HasPrefix(errMsg, "terminal sessions are disabled on this device"):
		// agent tty.enabled=false — requires local root at the
		// device console to flip. Retrying from the browser
		// achieves nothing.
		return true
	case strings.HasPrefix(errMsg, "tty user ") && strings.HasSuffix(errMsg, " is disabled"):
		// Locked pm-tty-* account. Operator has to unlock the
		// account on the device before the session will open.
		return true
	}
	return false
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
// Also tees stdin to the audit queue via a batcher that coalesces
// per-keystroke frames into 4 KiB / 1 s chunks — xterm.js sends one
// WS frame per keystroke, so a raw one-event-per-frame tee produces
// one audit event per character, flooding the event store with
// opaque single-byte blobs. See terminal_audit_batcher.go for the
// exact tuning rationale.
func (h *TerminalBridgeHandler) bridgeWSToAgent(
	ctx context.Context,
	ws *websocket.Conn,
	sess *connection.TerminalSession,
	validated *pm.InternalValidateTerminalTokenResponse,
	logger *slog.Logger,
) error {
	audit := newTerminalAuditBatcher(func(data []byte, seq int64) {
		h.enqueueAuditChunk(sess, validated, data, seq)
	})
	defer audit.Close()

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

			// Audit tee (batched): the batcher owns sequence and
			// flush cadence, so the hot WS read path stays a bare
			// append. See terminal_audit_batcher.go.
			audit.Write(data)

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
			default:
				// Agents are only supposed to route TerminalOutput and
				// TerminalStateChange into a terminal session's channel.
				// Anything else is a protocol violation and would
				// otherwise vanish silently.
				logger.Warn("unexpected message type in terminal output channel",
					"type", fmt.Sprintf("%T", p))
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
