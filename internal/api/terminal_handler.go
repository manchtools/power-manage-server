package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	sdkterminal "github.com/manchtools/power-manage/sdk/go/sys/terminal"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/gateway/registry"
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
	registry   *registry.Registry // multi-gateway routing; may be nil for single-gateway fallback
	fallbackURL string             // used only when registry is nil
	logger     *slog.Logger

	// internalHTTPClient is an mTLS-configured HTTP client used to
	// call GatewayService on each live gateway for admin fan-out
	// (ListActiveTerminalSessions, TerminateTerminalSession). Set
	// via SetInternalHTTPClient at startup. nil means admin RPCs
	// return Unavailable.
	internalHTTPClient *http.Client
}

// SetInternalHTTPClient configures the mTLS HTTP client used for
// gateway fan-out. Called from main.go with the same mTLS client
// used for the InternalService proxy.
func (h *TerminalHandler) SetInternalHTTPClient(c *http.Client) {
	h.internalHTTPClient = c
}

// NewTerminalHandler constructs a TerminalHandler.
//
// reg is the multi-gateway registry; when non-nil, StartTerminal
// looks up the gateway hosting each device and returns its specific
// terminal URL. fallbackURL is the static gateway URL used when
// reg is nil (single-gateway deployments without a registry).
//
// In production at least one of reg or fallbackURL must be supplied,
// or every StartTerminal call returns Unavailable.
func NewTerminalHandler(st *store.Store, tokenStore *terminal.TokenStore, reg *registry.Registry, fallbackURL string, logger *slog.Logger) *TerminalHandler {
	return &TerminalHandler{
		store:       st,
		tokenStore:  tokenStore,
		registry:    reg,
		fallbackURL: GatewayBaseURL(fallbackURL),
		logger:      logger,
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

	// Filter by the authenticated user's ID so users can only open
	// terminal sessions on devices assigned to them (directly or via
	// user groups). The SQL query's FilterUserID clause handles the
	// assignment check — a non-assigned device looks like ErrNoRows,
	// same as a genuinely missing device.
	filterUserID := userCtx.ID
	if _, err := h.store.Queries().GetDeviceByID(ctx, generated.GetDeviceByIDParams{
		ID:           req.Msg.DeviceId,
		FilterUserID: &filterUserID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found or not assigned to you")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to look up device")
	}

	// Resolve which gateway is currently hosting this device. In a
	// multi-gateway deployment we MUST return the URL of the
	// specific gateway holding the agent's bidi stream — any other
	// gateway has no way to bridge the WebSocket to the agent. The
	// device→gateway mapping is published by the gateway side via
	// internal/gateway/registry as part of the agent connect/heart-
	// beat lifecycle.
	//
	// Single-gateway deployments without a registry fall back to
	// the static fallbackURL passed at construction time. If both
	// the registry and the fallback are unset, we have no way to
	// route — return Unavailable so operators see a clear failure
	// instead of minting tokens against a URL that doesn't exist.
	resolvedURL, err := h.resolveGatewayURL(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, err
	}

	cols := req.Msg.Cols
	if cols == 0 {
		cols = sdkterminal.DefaultCols
	}
	rows := req.Msg.Rows
	if rows == 0 {
		rows = sdkterminal.DefaultRows
	}

	// CQRS: the event is the source of truth for terminal session
	// authorization. Write the event FIRST; if it fails, nothing
	// happened — no token, no session, no audit gap. The Valkey
	// token is derived state (like a projection), minted only after
	// the event is safely persisted.
	sessionID := ulid.Make().String()
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.DeviceId,
		EventType:  "TerminalSessionStarted",
		Data: map[string]any{
			"session_id": sessionID,
			"tty_user":   ttyUser,
			"cols":       cols,
			"rows":       rows,
		},
		ActorType: "user",
		ActorID:   user.ID,
	}); err != nil {
		h.logger.Error("failed to append TerminalSessionStarted event",
			"session_id", sessionID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to persist terminal session event")
	}

	// rc7: upsert the terminal_sessions row so the session is visible
	// in the history list from this point forward. Best-effort — the
	// audit event is the authorization record of truth; the row is a
	// derived view. If the upsert loses (e.g. transient DB hiccup),
	// the first chunk's INSERT ... ON CONFLICT still creates the row,
	// it just lands with empty tty_user until a later lifecycle event
	// or a reconciliation job fills it in.
	if err := h.store.Queries().UpsertTerminalSessionStart(ctx, generated.UpsertTerminalSessionStartParams{
		SessionID: sessionID,
		DeviceID:  req.Msg.DeviceId,
		UserID:    user.ID,
		TtyUser:   ttyUser,
		StartedAt: time.Now(),
		Cols:      int32(cols),
		Rows:      int32(rows),
	}); err != nil {
		h.logger.Warn("failed to upsert terminal_sessions start row (event persisted; row will recover)",
			"session_id", sessionID, "error", err)
	}

	// Derived state: mint the short-lived bearer token in Valkey.
	// If this fails, the event is already persisted (recording the
	// authorization intent), but the session is unusable. The client
	// retries and gets a new session with a new event — the orphaned
	// event is a harmless record of a failed attempt.
	mintRes, err := h.tokenStore.MintWithID(ctx, sessionID, terminal.MintParams{
		UserID:   user.ID,
		DeviceID: req.Msg.DeviceId,
		TtyUser:  ttyUser,
		Cols:     cols,
		Rows:     rows,
	})
	if err != nil {
		h.logger.Error("failed to mint terminal session token",
			"session_id", sessionID, "user_id", user.ID,
			"device_id", req.Msg.DeviceId, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to mint session token")
	}

	h.logger.Info("terminal session started",
		"session_id", sessionID,
		"user_id", user.ID,
		"device_id", req.Msg.DeviceId,
		"tty_user", ttyUser,
	)

	return connect.NewResponse(&pm.StartTerminalResponse{
		SessionId:    sessionID,
		SessionToken: mintRes.Token,
		GatewayUrl:   resolvedURL,
		ExpiresAt:    timestamppb.New(mintRes.ExpiresAt),
		TtyUser:      ttyUser,
	}), nil
}

// resolveGatewayURL returns the public terminal WebSocket URL for
// the gateway currently hosting the given device. Lookup chain:
//
//  1. If the registry is configured, look up
//     pm:device:gateway:<deviceID> → gatewayID, then
//     pm:gateway:terminal:<gatewayID> → URL. Returns
//     FailedPrecondition if the device isn't connected to any
//     gateway, Unavailable if the gateway has expired between the
//     two lookups (race during failover).
//  2. If the registry is not configured, return the static
//     fallbackURL passed at construction. This is the
//     single-gateway path.
//  3. If neither is configured, return Unavailable so operators
//     see a clear misconfiguration error rather than minting
//     tokens against an empty URL.
func (h *TerminalHandler) resolveGatewayURL(ctx context.Context, deviceID string) (string, error) {
	if h.registry == nil {
		if h.fallbackURL == "" {
			return "", apiErrorCtx(ctx, ErrUnimplemented, connect.CodeUnavailable,
				"remote terminal sessions are not configured on this control instance")
		}
		return h.fallbackURL, nil
	}

	gatewayID, err := h.registry.LookupDeviceGateway(ctx, deviceID)
	if err != nil {
		if errors.Is(err, registry.ErrNoGateway) {
			return "", apiErrorCtx(ctx, ErrDeviceNotConnected, connect.CodeFailedPrecondition,
				"device is not currently connected to any gateway")
		}
		h.logger.Error("device gateway lookup failed",
			"device_id", deviceID, "error", err)
		return "", apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable,
			"device gateway lookup failed (registry unavailable)")
	}

	terminalURL, err := h.registry.LookupGatewayTerminalURL(ctx, gatewayID)
	if err != nil {
		if errors.Is(err, registry.ErrNoGateway) {
			// The gateway died between the device lookup and the
			// URL lookup. Surface as Unavailable so the client
			// retries — by then the agent has reconnected
			// elsewhere and the next StartTerminal call resolves
			// to a live gateway.
			h.logger.Warn("gateway hosting device is no longer registered",
				"device_id", deviceID, "gateway_id", gatewayID)
			return "", apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable,
				"gateway hosting this device is no longer registered; retry shortly")
		}
		h.logger.Error("gateway URL lookup failed",
			"gateway_id", gatewayID, "error", err)
		return "", apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable,
			"gateway URL lookup failed (registry unavailable)")
	}
	return terminalURL, nil
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

	// CQRS: event first (source of truth), then Valkey revoke
	// (derived state). If the event fails, the session stays active
	// — no silent stop without an audit trail. If the revoke fails,
	// the event is recorded and the Valkey TTL will clean up the
	// orphaned token anyway.
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
		h.logger.Error("failed to append TerminalSessionStopped event",
			"session_id", session.SessionID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to persist terminal session stop event")
	}

	// rc7: finalize the terminal_sessions row. Best-effort — see the
	// upsert rationale in StartTerminal. No exit code at this call
	// site; the session ended on user request, not on shell exit.
	now := time.Now()
	if err := h.store.Queries().MarkTerminalSessionStopped(ctx, generated.MarkTerminalSessionStoppedParams{
		SessionID: session.SessionID,
		StoppedAt: &now,
		ExitCode:  nil,
	}); err != nil {
		h.logger.Warn("failed to mark terminal_sessions row stopped (event persisted)",
			"session_id", session.SessionID, "error", err)
	}

	if err := h.tokenStore.Revoke(ctx, req.Msg.SessionId); err != nil {
		// The stop event is persisted, but the token remains valid
		// until its Valkey TTL expires (up to 60s). That's a window
		// where the session could theoretically be reconnected. Fail
		// the RPC so the client knows the stop didn't fully land and
		// can retry.
		h.logger.Error("failed to revoke terminal session token",
			"session_id", session.SessionID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to revoke terminal session token")
	}

	h.logger.Info("terminal session stopped",
		"session_id", session.SessionID,
		"user_id", userCtx.ID,
		"device_id", session.DeviceID,
	)
	return connect.NewResponse(&pm.StopTerminalResponse{}), nil
}

// ListActiveTerminalSessions fans out to every live gateway via the
// registry and merges the results. Each gateway returns its local
// session snapshot; the control enriches with user/device metadata
// from the database and returns the merged list.
func (h *TerminalHandler) ListActiveTerminalSessions(ctx context.Context, req *connect.Request[pm.ListActiveTerminalSessionsRequest]) (*connect.Response[pm.ListActiveTerminalSessionsResponse], error) {
	if h.registry == nil || h.internalHTTPClient == nil {
		return nil, apiErrorCtx(ctx, ErrTerminalNotConfigured, connect.CodeUnavailable,
			"terminal admin RPCs require a configured registry and internal HTTP client")
	}

	gateways, err := h.registry.ListGatewayInternalURLs(ctx)
	if err != nil {
		h.logger.Error("failed to list gateways for session fan-out", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable,
			"failed to enumerate gateways")
	}

	var (
		mu       sync.Mutex
		all      []*pm.TerminalSessionInfo
		wg       sync.WaitGroup
	)

	for gwID, gwURL := range gateways {
		wg.Add(1)
		go func(gwID, gwURL string) {
			defer wg.Done()
			childCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			client := pmv1connect.NewGatewayServiceClient(h.internalHTTPClient, gwURL)
			resp, err := client.ListGatewayTerminalSessions(childCtx, connect.NewRequest(&pm.ListGatewayTerminalSessionsRequest{}))
			if err != nil {
				h.logger.Warn("gateway fan-out failed",
					"gateway_id", gwID, "url", gwURL, "error", err)
				return
			}
			mu.Lock()
			for _, s := range resp.Msg.Sessions {
				all = append(all, &pm.TerminalSessionInfo{
					SessionId:      s.SessionId,
					UserId:         s.UserId,
					DeviceId:       s.DeviceId,
					TtyUser:        s.TtyUser,
					StartedAt:      s.StartedAt,
					LastActivityAt: s.LastActivityAt,
					GatewayId:      gwID,
				})
			}
			mu.Unlock()
		}(gwID, gwURL)
	}
	wg.Wait()

	// TODO: enrich with user email / device hostname from DB for
	// the admin view. For now the IDs are returned directly.

	return connect.NewResponse(&pm.ListActiveTerminalSessionsResponse{
		Sessions:   all,
		TotalCount: int32(len(all)),
	}), nil
}

// TerminateTerminalSession finds which gateway hosts the session
// (via the token store's device_id → registry lookup) and calls
// TerminateGatewayTerminalSession on that gateway.
func (h *TerminalHandler) TerminateTerminalSession(ctx context.Context, req *connect.Request[pm.TerminateTerminalSessionRequest]) (*connect.Response[pm.TerminateTerminalSessionResponse], error) {
	if h.registry == nil || h.internalHTTPClient == nil {
		return nil, apiErrorCtx(ctx, ErrTerminalNotConfigured, connect.CodeUnavailable,
			"terminal admin RPCs require a configured registry and internal HTTP client")
	}

	// Look up the session to find the device, then the gateway.
	session, err := h.tokenStore.Lookup(ctx, req.Msg.SessionId)
	if err != nil {
		if errors.Is(err, terminal.ErrTokenNotFound) {
			// Idempotent: session already gone is success.
			return connect.NewResponse(&pm.TerminateTerminalSessionResponse{}), nil
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			"failed to look up session")
	}

	gatewayID, err := h.registry.LookupDeviceGateway(ctx, session.DeviceID)
	if err != nil {
		if errors.Is(err, registry.ErrNoGateway) {
			// Device not connected — session may have already ended.
			// Revoke the token anyway and return success.
			if rErr := h.tokenStore.Revoke(ctx, req.Msg.SessionId); rErr != nil {
				h.logger.Error("failed to revoke terminal session token after no-gateway",
					"session_id", req.Msg.SessionId, "error", rErr)
				return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
					"failed to revoke terminal session token")
			}
			return connect.NewResponse(&pm.TerminateTerminalSessionResponse{}), nil
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeUnavailable,
			"failed to look up gateway for device")
	}

	gwURL, err := h.registry.LookupGatewayInternalURL(ctx, gatewayID)
	if err != nil {
		// Gateway disappeared between lookups. Revoke token and return.
		if rErr := h.tokenStore.Revoke(ctx, req.Msg.SessionId); rErr != nil {
			h.logger.Error("failed to revoke terminal session token after gateway disappearance",
				"session_id", req.Msg.SessionId, "error", rErr)
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
				"failed to revoke terminal session token")
		}
		return connect.NewResponse(&pm.TerminateTerminalSessionResponse{}), nil
	}

	// Call the gateway to terminate the session.
	client := pmv1connect.NewGatewayServiceClient(h.internalHTTPClient, gwURL)
	resp, err := client.TerminateGatewayTerminalSession(ctx, connect.NewRequest(&pm.TerminateGatewayTerminalSessionRequest{
		SessionId: req.Msg.SessionId,
		Reason:    req.Msg.Reason,
	}))
	if err != nil {
		h.logger.Error("gateway terminate fan-out failed",
			"gateway_id", gatewayID, "session_id", req.Msg.SessionId, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			"failed to terminate session on gateway")
	}

	if !resp.Msg.Found {
		h.logger.Debug("session not found on gateway (may have ended naturally)",
			"gateway_id", gatewayID, "session_id", req.Msg.SessionId)
	}

	// Revoke the token and emit audit event.
	if err := h.tokenStore.Revoke(ctx, req.Msg.SessionId); err != nil {
		h.logger.Error("failed to revoke terminal session token after gateway termination",
			"session_id", req.Msg.SessionId, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			"failed to revoke terminal session token")
	}

	actorID := func() string {
		if u, ok := auth.UserFromContext(ctx); ok {
			return u.ID
		}
		return "system"
	}()
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   session.DeviceID,
		EventType:  "TerminalSessionTerminated",
		Data: map[string]any{
			"session_id": session.SessionID,
			"reason":     req.Msg.Reason,
		},
		ActorType: "user",
		ActorID:   actorID,
	}); err != nil {
		h.logger.Error("failed to append TerminalSessionTerminated event",
			"session_id", session.SessionID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			"failed to persist terminal session termination event")
	}

	// rc7: finalize the terminal_sessions row with the forced-stop
	// metadata. Best-effort — see the rationale in StartTerminal.
	now := time.Now()
	terminatedBy := actorID
	if err := h.store.Queries().MarkTerminalSessionTerminated(ctx, generated.MarkTerminalSessionTerminatedParams{
		SessionID:    session.SessionID,
		StoppedAt:    &now,
		TerminatedBy: &terminatedBy,
	}); err != nil {
		h.logger.Warn("failed to mark terminal_sessions row terminated (event persisted)",
			"session_id", session.SessionID, "error", err)
	}

	return connect.NewResponse(&pm.TerminateTerminalSessionResponse{}), nil
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
		// Even on parse failure, strip userinfo/query/fragment so
		// credentials and tokens can't leak through the fallback.
		s := raw
		if i := strings.IndexByte(s, '@'); i >= 0 {
			// Strip everything up to and including the '@'. This is
			// a best-effort heuristic — the parse already failed, so
			// the URL is malformed anyway.
			if schemeEnd := strings.Index(s, "://"); schemeEnd >= 0 && i > schemeEnd {
				s = s[:schemeEnd+3] + s[i+1:]
			}
		}
		if i := strings.IndexByte(s, '?'); i >= 0 {
			s = s[:i]
		}
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = s[:i]
		}
		return strings.TrimRight(s, "/")
	}
	// Reject non-WebSocket schemes so an http:// or ftp:// misconfig
	// fails at startup rather than producing a broken URL in responses.
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	s := u.String()
	return strings.TrimRight(s, "/")
}
