package api

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sdkterminal "github.com/manchtools/power-manage/sdk/go/sys/terminal"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

// TerminalHandler handles the four ControlService terminal session
// RPCs from manchtools/power-manage-sdk#16 step 5. The List/Terminate
// admin RPCs land in a follow-up PR alongside the gateway-side
// inventory; this handler implements the user-initiated open and
// graceful stop paths.
type TerminalHandler struct {
	store      *store.Store
	tokenStore *terminal.TokenStore
	gatewayURL string
	logger     *slog.Logger
}

// NewTerminalHandler constructs a TerminalHandler. gatewayURL is the
// publicly-resolvable WebSocket URL of the gateway endpoint, e.g.
// "wss://gateway.example.com/terminal". Clients append
// ?token=<session_token> to it themselves; the handler returns the
// token-free base URL per the StartTerminalResponse contract in the
// SDK proto.
func NewTerminalHandler(st *store.Store, tokenStore *terminal.TokenStore, gatewayURL string, logger *slog.Logger) *TerminalHandler {
	return &TerminalHandler{
		store:      st,
		tokenStore: tokenStore,
		gatewayURL: gatewayURL,
		logger:     logger,
	}
}

// StartTerminal verifies the caller is authenticated, resolves the
// dedicated TTY username from the user's stored linux_username,
// validates the target device, mints a short-lived session token, and
// returns the gateway WebSocket URL the web client should connect to.
//
// Permission gating happens in the AuthzInterceptor (the permission
// key is "StartTerminal" — same convention as every other handler),
// so this method only runs for callers that already hold it.
func (h *TerminalHandler) StartTerminal(ctx context.Context, req *connect.Request[pm.StartTerminalRequest]) (*connect.Response[pm.StartTerminalResponse], error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	user, err := h.store.Queries().GetUserByID(ctx, userCtx.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to look up user")
	}
	if user.Disabled || user.IsDeleted {
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "user account is disabled")
	}
	linuxUsername := strings.TrimSpace(user.LinuxUsername)
	if linuxUsername == "" {
		return nil, apiErrorCtx(ctx, ErrTerminalLinuxUsernameNotSet, connect.CodeFailedPrecondition,
			"user has no linux username configured; cannot resolve TTY user")
	}
	ttyUser := sdkterminal.TTYUsername(linuxUsername)

	if _, err := h.store.Queries().GetDeviceByID(ctx, generated.GetDeviceByIDParams{ID: req.Msg.DeviceId}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to look up device")
	}

	cols := req.Msg.Cols
	if cols == 0 {
		cols = sdkterminal.DefaultCols
	}
	rows := req.Msg.Rows
	if rows == 0 {
		rows = sdkterminal.DefaultRows
	}

	mintRes, err := h.tokenStore.Mint(ctx, terminal.MintParams{
		UserID:   user.ID,
		DeviceID: req.Msg.DeviceId,
		TtyUser:  ttyUser,
		Cols:     cols,
		Rows:     rows,
	})
	if err != nil {
		h.logger.Error("failed to mint terminal session token",
			"user_id", user.ID, "device_id", req.Msg.DeviceId, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to mint session token")
	}

	// Audit: TerminalSessionStarted on the device stream so the
	// existing audit/search infrastructure picks it up automatically.
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.DeviceId,
		EventType:  "TerminalSessionStarted",
		Data: map[string]any{
			"session_id": mintRes.SessionID,
			"tty_user":   ttyUser,
			"cols":       cols,
			"rows":       rows,
		},
		ActorType: "user",
		ActorID:   user.ID,
	}); err != nil {
		// Terminal sessions without an audit trail are a security gap:
		// someone has interactive shell access with no record. Revoke
		// the freshly-minted token and refuse the session so the
		// invariant "every session has a start event" holds.
		h.logger.Error("failed to append TerminalSessionStarted event; revoking session",
			"session_id", mintRes.SessionID, "error", err)
		_ = h.tokenStore.Revoke(ctx, mintRes.SessionID)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create audit record for terminal session")
	}

	h.logger.Info("terminal session started",
		"session_id", mintRes.SessionID,
		"user_id", user.ID,
		"device_id", req.Msg.DeviceId,
		"tty_user", ttyUser,
	)

	return connect.NewResponse(&pm.StartTerminalResponse{
		SessionId:    mintRes.SessionID,
		SessionToken: mintRes.Token,
		GatewayUrl:   h.gatewayURL,
		ExpiresAt:    timestamppb.New(mintRes.ExpiresAt),
		TtyUser:      ttyUser,
	}), nil
}

// StopTerminal is the user-initiated graceful stop. The caller must
// be the user that opened the session — admins kill someone else's
// session via TerminateTerminalSession.
//
// Idempotent: an unknown or already-stopped session returns OK with
// no body, NOT NotFound, so clients can fire and forget on disconnect.
// This matches the contract documented above StopTerminalRequest in
// the SDK proto.
func (h *TerminalHandler) StopTerminal(ctx context.Context, req *connect.Request[pm.StopTerminalRequest]) (*connect.Response[pm.StopTerminalResponse], error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	session, err := h.tokenStore.Lookup(ctx, req.Msg.SessionId)
	if err != nil {
		if errors.Is(err, terminal.ErrTokenNotFound) {
			// Idempotent: session already gone is success.
			return connect.NewResponse(&pm.StopTerminalResponse{}), nil
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to look up session")
	}

	// Ownership check: only the user that opened the session may stop
	// it. Admins use TerminateTerminalSession (separate permission).
	if session.UserID != userCtx.ID {
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied,
			"only the session owner may stop a terminal session; admins must use TerminateTerminalSession")
	}

	if err := h.tokenStore.Revoke(ctx, req.Msg.SessionId); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to revoke session")
	}

	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   session.DeviceID,
		EventType:  "TerminalSessionStopped",
		Data: map[string]any{
			"session_id": session.SessionID,
			"reason":     "user_stopped",
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}); err != nil {
		// The token is already revoked (above), so the session is
		// stopped regardless. But we still fail the RPC so the client
		// knows the audit gap exists and operators see a clear error.
		h.logger.Error("failed to append TerminalSessionStopped event",
			"session_id", session.SessionID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create audit record for terminal session stop")
	}

	h.logger.Info("terminal session stopped",
		"session_id", session.SessionID,
		"user_id", userCtx.ID,
		"device_id", session.DeviceID,
	)
	return connect.NewResponse(&pm.StopTerminalResponse{}), nil
}

// GatewayBaseURL normalises the configured gateway URL into the
// token-free form returned by StartTerminalResponse.gateway_url:
// any query string, fragment, or trailing slash is stripped so the
// web client can safely append ?token=<session_token> when opening
// its WebSocket. Exported so main.go can call it once at startup.
func GatewayBaseURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return strings.TrimRight(raw, "/")
	}
	u.RawQuery = ""
	u.Fragment = ""
	s := u.String()
	return strings.TrimRight(s, "/")
}
