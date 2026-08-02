// Package terminalbridge connects an authenticated browser WebSocket directly
// to an agent's existing mTLS stream.
package terminalbridge

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

const (
	terminalSubprotocolPrefix = "bearer."
	defaultStartTimeout       = 30 * time.Second
	maxClientFrameBytes       = 64 << 10
)

var (
	errAgentTerminalFailure = errors.New("agent terminal failed")
	errTerminalEnded        = errors.New("terminal ended before it started")
)

// Config supplies the one-process terminal state and transport.
type Config struct {
	Manager        *connection.Manager
	Sessions       *connection.TerminalSessionRegistry
	Tokens         *terminal.TokenStore
	Store          *store.Store
	Logger         *slog.Logger
	OriginPatterns []string
	StartTimeout   time.Duration
	Now            func() time.Time
}

// Handler serves the control-owned terminal WebSocket endpoint.
type Handler struct {
	manager        *connection.Manager
	sessions       *connection.TerminalSessionRegistry
	tokens         *terminal.TokenStore
	store          *store.Store
	logger         *slog.Logger
	originPatterns []string
	startTimeout   time.Duration
	now            func() time.Time
}

// New constructs a direct terminal bridge.
func New(cfg Config) *Handler {
	if cfg.Manager == nil || cfg.Sessions == nil || cfg.Tokens == nil || cfg.Store == nil {
		panic("terminalbridge: manager, sessions, tokens, and store are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = defaultStartTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Handler{
		manager: cfg.Manager, sessions: cfg.Sessions, tokens: cfg.Tokens, store: cfg.Store,
		logger: cfg.Logger, originPatterns: append([]string(nil), cfg.OriginPatterns...),
		startTimeout: cfg.StartTimeout, now: cfg.Now,
	}
}

// ServeHTTP redeems one short-lived token and owns the bridge until either
// endpoint closes. No terminal bytes are logged or copied into audit records.
func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	sessionID := request.URL.Query().Get("session_id")
	token, subprotocol := terminalToken(request)
	if !validID(sessionID) || token == "" || subprotocol == "" {
		http.Error(response, "terminal session credentials required", http.StatusUnauthorized)
		return
	}
	metadata, err := h.tokens.Validate(request.Context(), sessionID, token)
	if err != nil {
		if errors.Is(err, terminal.ErrTokenNotFound) || errors.Is(err, terminal.ErrTokenMismatch) {
			http.Error(response, "invalid or expired terminal session", http.StatusUnauthorized)
		} else {
			http.Error(response, "terminal session unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	if metadata == nil || !validID(metadata.DeviceID) || !validID(metadata.UserID) || metadata.TtyUser == "" {
		http.Error(response, "invalid terminal session", http.StatusUnauthorized)
		return
	}
	if !h.manager.IsConnected(metadata.DeviceID) {
		http.Error(response, "device unavailable", http.StatusServiceUnavailable)
		return
	}
	// The public server bounds ordinary request bodies with ReadTimeout. A
	// WebSocket becomes a long-lived terminal transport after the upgrade, so
	// it must not inherit that one-request deadline. Fail closed if the concrete
	// server response writer cannot remove it; accepting would produce a shell
	// that is guaranteed to die when the original deadline expires.
	if err := http.NewResponseController(response).SetReadDeadline(time.Time{}); err != nil {
		h.logger.Error("clear terminal read deadline", "code", "TRANSPORT_UNSUPPORTED")
		http.Error(response, "terminal session unavailable", http.StatusServiceUnavailable)
		return
	}

	ws, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		OriginPatterns: h.originPatterns,
		Subprotocols:   []string{subprotocol},
	})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(maxClientFrameBytes)

	session := connection.NewTerminalSession(sessionID, metadata.DeviceID, metadata.UserID,
		metadata.TtyUser, metadata.Cols, metadata.Rows)
	h.sessions.Register(session)
	defer h.sessions.Unregister(sessionID)

	var stopSent atomic.Bool
	sendStop := func(reason string) {
		if !stopSent.CompareAndSwap(false, true) {
			return
		}
		_ = h.manager.Send(metadata.DeviceID, &pmv1.ServerMessage{
			Id: ulid.Make().String(), Payload: &pmv1.ServerMessage_TerminalStop{
				TerminalStop: &pmv1.TerminalStop{SessionId: sessionID, Reason: reason},
			},
		})
	}
	closeReason := "bridge_closed"
	defer func() {
		sendStop(closeReason)
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), 5*time.Second)
		defer cancel()
		if err := h.recordClosed(closeCtx, sessionID, closeReason); err != nil {
			h.logger.Error("record terminal closure", "session_id", sessionID, "code", "STORE_ERROR")
		}
	}()

	if err := h.manager.Send(metadata.DeviceID, &pmv1.ServerMessage{
		Id: ulid.Make().String(), Payload: &pmv1.ServerMessage_TerminalStart{
			TerminalStart: &pmv1.TerminalStart{
				SessionId: sessionID, TtyUser: metadata.TtyUser, Cols: metadata.Cols, Rows: metadata.Rows,
			},
		},
	}); err != nil {
		closeReason = "device_unavailable"
		_ = ws.Close(websocket.StatusTryAgainLater, "device unavailable")
		return
	}
	if err := h.waitForStarted(request.Context(), session, ws); err != nil {
		closeReason = "start_failed"
		return
	}

	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	clientDone := make(chan error, 1)
	agentDone := make(chan error, 1)
	go func() { clientDone <- h.clientToAgent(ctx, ws, session, metadata.DeviceID) }()
	go func() { agentDone <- h.agentToClient(ctx, ws, session) }()

	status := websocket.StatusNormalClosure
	message := "terminal closed"
	select {
	case err := <-clientDone:
		cancel()
		closeReason = "client_closed"
		if err != nil && !isNormalWebSocketClose(err) {
			status, message = websocket.StatusInternalError, "client stream failed"
		}
	case err := <-agentDone:
		cancel()
		stopSent.Store(true)
		closeReason = "agent_closed"
		if err != nil {
			status, message = websocket.StatusInternalError, "device terminal failed"
		}
	}
	_ = ws.Close(status, message)
}

func terminalToken(request *http.Request) (string, string) {
	for _, raw := range request.Header.Values("Sec-WebSocket-Protocol") {
		for _, offered := range strings.Split(raw, ",") {
			offered = strings.TrimSpace(offered)
			if strings.HasPrefix(offered, terminalSubprotocolPrefix) {
				token := strings.TrimPrefix(offered, terminalSubprotocolPrefix)
				if token != "" {
					return token, offered
				}
			}
		}
	}
	return "", ""
}

func (h *Handler) waitForStarted(ctx context.Context, session *connection.TerminalSession, ws *websocket.Conn) error {
	timer := time.NewTimer(h.startTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			_ = ws.Close(websocket.StatusTryAgainLater, "terminal start timed out")
			return context.DeadlineExceeded
		case message, ok := <-session.OutputCh:
			if !ok {
				return errTerminalEnded
			}
			state, ok := message.Payload.(*pmv1.AgentMessage_TerminalStateChange)
			if !ok || state.TerminalStateChange == nil {
				continue
			}
			switch state.TerminalStateChange.State {
			case pmv1.TerminalSessionState_TERMINAL_SESSION_STATE_STARTED:
				return nil
			case pmv1.TerminalSessionState_TERMINAL_SESSION_STATE_EXITED:
				_ = ws.Close(websocket.StatusInternalError, "terminal ended before start")
				return errTerminalEnded
			case pmv1.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR:
				_ = ws.Close(websocket.StatusInternalError, "device terminal failed")
				return errAgentTerminalFailure
			}
		}
	}
}

type resizeMessage struct {
	Type string `json:"type"`
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

func (h *Handler) clientToAgent(ctx context.Context, ws *websocket.Conn, session *connection.TerminalSession, deviceID string) error {
	for {
		messageType, data, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		session.Touch()
		switch messageType {
		case websocket.MessageBinary:
			if err := h.manager.Send(deviceID, &pmv1.ServerMessage{
				Id: ulid.Make().String(), Payload: &pmv1.ServerMessage_TerminalInput{
					TerminalInput: &pmv1.TerminalInput{SessionId: session.SessionID, Data: data},
				},
			}); err != nil {
				return connection.ErrAgentNotConnected
			}
		case websocket.MessageText:
			var resize resizeMessage
			if json.Unmarshal(data, &resize) != nil || resize.Type != "resize" || resize.Cols == 0 || resize.Rows == 0 {
				continue
			}
			if err := h.manager.Send(deviceID, &pmv1.ServerMessage{
				Id: ulid.Make().String(), Payload: &pmv1.ServerMessage_TerminalResize{
					TerminalResize: &pmv1.TerminalResize{SessionId: session.SessionID, Cols: resize.Cols, Rows: resize.Rows},
				},
			}); err != nil {
				return connection.ErrAgentNotConnected
			}
		}
	}
}

func (h *Handler) agentToClient(ctx context.Context, ws *websocket.Conn, session *connection.TerminalSession) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case message, ok := <-session.OutputCh:
			if !ok {
				return nil
			}
			session.Touch()
			switch payload := message.Payload.(type) {
			case *pmv1.AgentMessage_TerminalOutput:
				if payload.TerminalOutput == nil {
					return errAgentTerminalFailure
				}
				if err := ws.Write(ctx, websocket.MessageBinary, payload.TerminalOutput.Data); err != nil {
					return err
				}
			case *pmv1.AgentMessage_TerminalStateChange:
				if payload.TerminalStateChange == nil {
					return errAgentTerminalFailure
				}
				if payload.TerminalStateChange.State == pmv1.TerminalSessionState_TERMINAL_SESSION_STATE_EXITED {
					return nil
				}
				if payload.TerminalStateChange.State == pmv1.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
					return errAgentTerminalFailure
				}
			}
		}
	}
}

func (h *Handler) recordClosed(ctx context.Context, sessionID, reason string) error {
	stoppedAt := h.now().UTC().Truncate(time.Microsecond)
	_, err := h.store.WithAudit(ctx, store.AuditOperation{
		Class: store.ClassBackgroundWriter, ActorType: "control", Origin: "terminal_bridge",
		RequestDescriptor: "terminal.bridge/Close", AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result: store.ResultSuccess, ResultCode: "OK",
	}, func(ctx context.Context, tx *store.Tx, recorder *store.AuditRecorder) error {
		rows, err := tx.StopTerminalSession(ctx, db.StopTerminalSessionParams{
			StoppedAt: &stoppedAt, ExitReason: &reason, SessionID: sessionID,
		})
		if err != nil {
			return err
		}
		if rows == 0 {
			return nil
		}
		recorder.Effect(store.AuditEffect{
			ResourceType: "terminal_session", ResourceID: sessionID, Action: "CLOSE",
			Outcome: store.EffectApplied, ChangedFields: []string{"exit_reason", "stopped_at"},
		})
		return nil
	})
	return err
}

func isNormalWebSocketClose(err error) bool {
	status := websocket.CloseStatus(err)
	return status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway
}

func validID(value string) bool {
	_, err := ulid.ParseStrict(value)
	return err == nil
}
