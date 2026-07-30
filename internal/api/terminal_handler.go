package api

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sdkterminal "github.com/manchtools/power-manage-sdk/sys/terminal"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

// TerminalHandler handles the four ControlService terminal session RPCs.
//
// Spec 41 collapsed the routing this used to do. Terminal frames always
// travelled to the agent over the AgentService bidi stream; the gateway was
// only the WebSocket bridge for the browser and the registry that answered
// "which gateway holds this device". With one process, control holds every
// stream, so there is nothing to route to and nothing to fan out across.
type TerminalHandler struct {
	store       *store.Store
	tokenStore  *terminal.TokenStore
	terminalURL string // public WebSocket URL of control's own terminal endpoint
	logger      *slog.Logger

	// liveSessions enumerates every live terminal session with NO caller-scope
	// filtering, and stopSession closes one on the agent that holds it. Both are
	// injected by main.go over the connection manager rather than imported,
	// keeping this package free of a dependency on the stream layer — and both
	// stay function seams because tests override them.
	//
	// The scoped RPC (ListActiveTerminalSessions) layers scopedSessions on top of
	// liveSessions; the internal revocation path (TerminateUserSessions) uses it
	// raw so a system-initiated revocation sees every session (H1 / #391 —
	// routing revocation through the scoped RPC under a user-less context
	// silently filtered to zero and terminated nothing).
	//
	// nil means the terminal transport was never wired: the admin RPCs return
	// Unavailable, exactly as the unset-registry path did before.
	liveSessions func(ctx context.Context) ([]*pm.TerminalSessionInfo, error)

	// stopSession closes a session on the agent holding it. It reports found
	// SEPARATELY from err on purpose: "the session is not there" and "we could
	// not tell whether it stopped" are different answers. Conflating them lets
	// an operational failure be reported to the operator as a successful
	// termination while the privileged shell is still live.
	stopSession func(ctx context.Context, deviceID, sessionID, reason string) (found bool, err error)

	// isConnected reports whether the device currently holds a stream on this
	// control instance. Terminal sessions are bridged over that stream, so
	// without it there is nothing to bridge to.
	isConnected func(deviceID string) bool

	now func() time.Time // clock seam; defaults to time.Now, overridden in tests
}

// SetTerminalTransport wires the live-session source and the stop path. Called
// from main.go once the connection manager exists. Leaving it unset disables
// the admin RPCs rather than failing open.
func (h *TerminalHandler) SetTerminalTransport(
	list func(ctx context.Context) ([]*pm.TerminalSessionInfo, error),
	stop func(ctx context.Context, deviceID, sessionID, reason string) (bool, error),
	connected func(deviceID string) bool,
) {
	h.liveSessions = list
	h.stopSession = stop
	h.isConnected = connected
}

// NewTerminalHandler constructs a TerminalHandler. terminalURL is control's own
// public WebSocket endpoint; when empty, StartTerminal returns Unavailable so
// operators see a clear misconfiguration rather than a token minted against a
// URL that does not exist.
func NewTerminalHandler(st *store.Store, tokenStore *terminal.TokenStore, terminalURL string, logger *slog.Logger) *TerminalHandler {
	return &TerminalHandler{
		store:       st,
		tokenStore:  tokenStore,
		terminalURL: TerminalBaseURL(terminalURL),
		logger:      logger,
		now:         time.Now,
	}
}

// StartTerminal verifies the caller is authenticated, resolves the
// dedicated TTY username from the user's stored linux_username,
// validates the target device, mints a short-lived session token, and
// returns the WebSocket URL the web client should connect to.
//
// Permission gating happens in the AuthzInterceptor (the permission
// key is "StartTerminal" — same convention as every other handler),
// so this method only runs for callers that already hold it.
func (h *TerminalHandler) StartTerminal(ctx context.Context, req *connect.Request[pm.StartTerminalRequest]) (*connect.Response[pm.StartTerminalResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	user, err := h.store.Repos().User.Get(ctx, userCtx.ID)
	if err != nil {
		if store.IsNotFound(err) {
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

	// Filter by the authenticated user's ID when the caller only has
	// scoped (:assigned) access — they can only open sessions on
	// devices assigned to them. Users with the unrestricted
	// StartTerminal permission see all devices, matching the
	// userFilterID(...) pattern used by every other handler that
	// reads from the device projection. Pre-fix this was hardcoded
	// to userCtx.ID, which masked admin access to bulk-enrolled
	// (unassigned) devices.
	//
	// Security note (audit F-27): the unscoped StartTerminal
	// permission deliberately grants cross-user terminal access — an
	// admin can open a session that runs as ANY device user's TTY
	// account, not only their own (subject to the caller having a
	// linux_username configured on their own profile, which becomes
	// the TTY user inside the session). This is the intended admin
	// behaviour for incident response; the audit trail captures
	// caller identity via `actor_id = userCtx.ID` on the emitted
	// TerminalSessionStarted event so post-hoc attribution works
	// even though the in-session UID belongs to a different user.
	// If a deployment needs the no-cross-user variant, add a
	// `StartTerminal:self` scope that checks the device's
	// linux_username matches userCtx.LinuxUsername.
	filterUserID := userFilterID(ctx, "StartTerminal")
	// #7 device-group scope: a StartTerminal:scope=dgX holder may open a
	// session only on devices in dgX. Applies to the unrestricted tier
	// (filterUserID == nil means the caller holds the base StartTerminal
	// permission — scoped or global); the :assigned tier is governed by
	// the owner filter below. Checked before the lookup so an out-of-scope
	// device is denied, not leaked via NotFound-vs-PermissionDenied.
	if filterUserID == nil {
		if err := auth.EnforceDeviceScope(ctx, newScopeResolver(h.store), "StartTerminal", req.Msg.DeviceId); err != nil {
			return nil, err
		}
	}
	if _, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId, OwnerScope: filterUserID}); err != nil {
		if store.IsNotFound(err) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to look up device")
	}

	// Control bridges every session itself, so there is no per-device routing
	// left to do — the URL is the same for every device. Unset means terminals
	// were never configured on this instance.
	if h.terminalURL == "" {
		return nil, apiErrorCtx(ctx, ErrUnimplemented, connect.CodeUnavailable,
			"remote terminal sessions are not configured on this control instance")
	}

	// The device must actually be connected. Routing used to answer this
	// implicitly — resolving a device to its gateway failed when no gateway
	// held it — so when routing collapsed the liveness check had to become
	// explicit or it would simply be gone. Checked BEFORE the append and the
	// mint: otherwise an offline device yields a TerminalSessionStarted event
	// and a usable token for a session that can never be bridged.
	if h.isConnected == nil {
		return nil, apiErrorCtx(ctx, ErrTerminalNotConfigured, connect.CodeUnavailable,
			"terminal transport is not configured on this control instance")
	}
	if !h.isConnected(req.Msg.DeviceId) {
		return nil, apiErrorCtx(ctx, ErrDeviceNotConnected, connect.CodeFailedPrecondition,
			"device is not currently connected")
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
		EventType:  string(eventtypes.TerminalSessionStarted),
		Data: payloads.TerminalSessionStarted{
			SessionID: sessionID,
			TtyUser:   ttyUser,
			Cols:      cols,
			Rows:      rows,
		},
		ActorType: "user",
		ActorID:   user.ID,
	}); err != nil {
		h.logger.Error("failed to append TerminalSessionStarted event",
			"session_id", sessionID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to persist terminal session event")
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

	// rc7: upsert the terminal_sessions row so the session is visible
	// in the history list from this point forward. Runs AFTER the
	// mint so a mint failure doesn't leave a row for a session the
	// client never uses. Best-effort — the audit event is the
	// authorization record of truth; the row is a derived view. If
	// the upsert loses (transient DB hiccup), the first chunk's
	// INSERT ... ON CONFLICT still creates the row, it just lands
	// with empty tty_user until a later lifecycle event fills it in.
	if err := h.store.Repos().TerminalSession.UpsertStart(ctx, store.StartTerminalSession{
		SessionID: sessionID,
		DeviceID:  req.Msg.DeviceId,
		UserID:    user.ID,
		TtyUser:   ttyUser,
		StartedAt: h.now(),
		Cols:      int32(cols),
		Rows:      int32(rows),
	}); err != nil {
		h.logger.Warn("failed to upsert terminal_sessions start row (event persisted; row will recover)",
			"session_id", sessionID, "error", err)
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
		TerminalUrl:  h.terminalURL,
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

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

	// Ownership check: only the user that opened the session may stop it. A
	// non-owner gets the SAME idempotent empty OK as an unknown/already-stopped
	// session (above), never PermissionDenied, so the owner-vs-not distinction
	// can't be used as an existence oracle for another user's opaque session id
	// (audit L4). The session is not stopped — only the owner's request mutates
	// it. Admins kill others' sessions via TerminateTerminalSession.
	if session.UserID != userCtx.ID {
		h.logger.Debug("StopTerminal on non-owned session; returning idempotent OK",
			"session_id", req.Msg.SessionId)
		return connect.NewResponse(&pm.StopTerminalResponse{}), nil
	}

	// Scope (#3): a device-group-scoped StopTerminal holder may stop only sessions
	// on devices within their scope. Ordinary users hold StopTerminal unscoped, so
	// this is a no-op for them.
	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "StopTerminal", session.DeviceID); err != nil {
		return nil, err
	}

	// CQRS: event first (source of truth), then Valkey revoke
	// (derived state). If the event fails, the session stays active
	// — no silent stop without an audit trail. If the revoke fails,
	// the event is recorded and the Valkey TTL will clean up the
	// orphaned token anyway.
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   session.DeviceID,
		EventType:  string(eventtypes.TerminalSessionStopped),
		Data: payloads.TerminalSessionStopped{
			SessionID: session.SessionID,
			Reason:    "user_stopped",
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}); err != nil {
		h.logger.Error("failed to append TerminalSessionStopped event",
			"session_id", session.SessionID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to persist terminal session stop event")
	}

	// rc7: finalize the terminal_sessions row. Upsert form so a row
	// materialises even if neither the Start upsert nor any chunk
	// landed first — the session stays visible in history either way.
	// Best-effort for the current goroutine: the event is the
	// authorization record of truth; a DB hiccup here just means the
	// history row is slightly incomplete. No exit code at this call
	// site; the session ended on user request, not on shell exit.
	now := h.now()
	if err := h.store.Repos().TerminalSession.MarkStopped(ctx, store.StopTerminalSession{
		SessionID: session.SessionID,
		StoppedAt: &now,
		ExitCode:  nil,
		DeviceID:  session.DeviceID,
		UserID:    userCtx.ID,
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

// ListActiveTerminalSessions returns the live sessions this control instance is
// bridging, confined to the caller's device-group scope.
func (h *TerminalHandler) ListActiveTerminalSessions(ctx context.Context, req *connect.Request[pm.ListActiveTerminalSessionsRequest]) (*connect.Response[pm.ListActiveTerminalSessionsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	all, err := h.listSessions(ctx)
	if err != nil {
		return nil, err
	}

	// Scope (#3): confine the merged list to sessions on devices in the caller's
	// ListActiveTerminalSessions device-group scope. A global holder sees all.
	// The internal revocation path (TerminateUserSessions) deliberately does NOT
	// apply this — it enumerates via h.listSessions directly (H1 / #391).
	scoped, err := h.scopedSessions(ctx, all)
	if err != nil {
		return nil, err
	}

	// TODO: enrich with user email / device hostname from DB for
	// the admin view. For now the IDs are returned directly.

	return connect.NewResponse(&pm.ListActiveTerminalSessionsResponse{
		Sessions:   scoped,
		TotalCount: int32(len(scoped)),
	}), nil
}

// listSessions returns every live terminal session with NO caller-scope
// filtering, via the transport wired by SetTerminalTransport. It replaces a
// concurrent HTTP fan-out across every registered gateway: with one process the
// sessions are in memory, so there is no merge, no per-gateway timeout, and no
// partial result when one peer is unreachable.
//
// The wiring guard lives here so both callers (the scoped RPC and the internal
// revocation path) get the same Unavailable behaviour when the transport is
// unset — unchanged from the unset-registry behaviour it replaces.
func (h *TerminalHandler) listSessions(ctx context.Context) ([]*pm.TerminalSessionInfo, error) {
	if h.liveSessions == nil {
		return nil, apiErrorCtx(ctx, ErrTerminalNotConfigured, connect.CodeUnavailable,
			"terminal admin RPCs require a configured terminal transport")
	}
	return h.liveSessions(ctx)
}

// scopedSessions filters a merged terminal-session list to those on devices
// within the caller's ListActiveTerminalSessions device-group scope. A global (or
// no-scoping-grant) caller is unrestricted; a scope-limited caller keeps only
// sessions whose device is a member of one of their scope groups; a caller with
// only a wrong-kind grant or no auth context sees nothing (fail closed).
func (h *TerminalHandler) scopedSessions(ctx context.Context, sessions []*pm.TerminalSessionInfo) ([]*pm.TerminalSessionInfo, error) {
	groupIDs, restricted := auth.DeviceScopeListFilter(ctx, "ListActiveTerminalSessions")
	if !restricted {
		return sessions, nil
	}
	if len(groupIDs) == 0 {
		return nil, nil // wrong-kind grant / no auth → restrict to nothing
	}
	scopeSet := make(map[string]struct{}, len(groupIDs))
	for _, id := range groupIDs {
		scopeSet[id] = struct{}{}
	}
	resolver := newScopeResolver(h.store)
	out := make([]*pm.TerminalSessionInfo, 0, len(sessions))
	for _, s := range sessions {
		devGroups, err := resolver.DeviceGroupsForDevice(ctx, s.DeviceId)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve session device scope")
		}
		for _, g := range devGroups {
			if _, ok := scopeSet[g]; ok {
				out = append(out, s)
				break
			}
		}
	}
	return out, nil
}

// TerminateTerminalSession closes a session on the agent holding it and
// revokes its token. Admin path; StopTerminal is the user-initiated one.
func (h *TerminalHandler) TerminateTerminalSession(ctx context.Context, req *connect.Request[pm.TerminateTerminalSessionRequest]) (*connect.Response[pm.TerminateTerminalSessionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Explicit auth check at the handler boundary, matching the pattern
	// used by StartTerminal and StopTerminal above. The auth interceptor
	// also enforces admin access to this RPC, but a missing auth context
	// here is a configuration bug — surface it loudly rather than silently
	// attributing the audit event to "system".
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Look up the session to find the device, then authorize the scope BEFORE the
	// infra-config check below — a caller must be told "denied" for an
	// out-of-scope session regardless of whether the terminal transport is wired.
	session, err := h.tokenStore.Lookup(ctx, req.Msg.SessionId)
	if err != nil {
		if errors.Is(err, terminal.ErrTokenNotFound) {
			// Idempotent: session already gone is success.
			return connect.NewResponse(&pm.TerminateTerminalSessionResponse{}), nil
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			"failed to look up session")
	}

	// Scope (#3): a device-group-scoped TerminateTerminalSession holder may
	// terminate only sessions on devices within their scope.
	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "TerminateTerminalSession", session.DeviceID); err != nil {
		return nil, err
	}

	if h.stopSession == nil {
		return nil, apiErrorCtx(ctx, ErrTerminalNotConfigured, connect.CodeUnavailable,
			"terminal admin RPCs require a configured terminal transport")
	}

	// Close the session on the agent holding it. This replaces a device→gateway
	// lookup, a gateway→URL lookup, and a TerminateGatewayTerminalSession call
	// over mTLS; control holds the stream, so it sends TerminalStop on it.
	//
	// A session that is genuinely ABSENT is not an error: it ended with the
	// stream, and the token must still be revoked and the termination still
	// audited. An INDETERMINATE stop is different — we cannot say the shell is
	// closed, so reporting success would tell an operator a root shell is gone
	// while it is still running. Fail the RPC instead and let them retry.
	found, err := h.stopSession(ctx, session.DeviceID, req.Msg.SessionId, req.Msg.Reason)
	if err != nil {
		h.logger.Error("terminal stop failed; session may still be live",
			"session_id", req.Msg.SessionId, "device_id", session.DeviceID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			"failed to terminate session on the device")
	}
	if !found {
		h.logger.Info("terminal session was already gone; revoking and auditing anyway",
			"session_id", req.Msg.SessionId, "device_id", session.DeviceID)
	}

	// Revoke the token and emit audit event.
	if err := h.tokenStore.Revoke(ctx, req.Msg.SessionId); err != nil {
		h.logger.Error("failed to revoke terminal session token after termination",
			"session_id", req.Msg.SessionId, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			"failed to revoke terminal session token")
	}

	actorID := userCtx.ID
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   session.DeviceID,
		EventType:  string(eventtypes.TerminalSessionTerminated),
		Data: payloads.TerminalSessionTerminated{
			SessionID: session.SessionID,
			Reason:    req.Msg.Reason,
		},
		ActorType: "user",
		ActorID:   actorID,
	}); err != nil {
		h.logger.Error("failed to append TerminalSessionTerminated event",
			"session_id", session.SessionID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			"failed to persist terminal session termination event")
	}

	// rc7: finalize the terminal_sessions row. Upsert form so a row
	// materialises even if neither the Start upsert nor any chunk
	// landed first — see rationale in StopTerminal.
	now := h.now()
	terminatedBy := actorID
	// The terminated session may have been opened by a different
	// user than the admin calling Terminate, so use the session's
	// recorded UserID (validated via the token store), not actorID.
	sessionUserID := session.UserID
	if err := h.store.Repos().TerminalSession.MarkTerminated(ctx, store.TerminateTerminalSession{
		SessionID:    session.SessionID,
		StoppedAt:    &now,
		TerminatedBy: &terminatedBy,
		DeviceID:     session.DeviceID,
		UserID:       sessionUserID,
	}); err != nil {
		h.logger.Warn("failed to mark terminal_sessions row terminated (event persisted)",
			"session_id", session.SessionID, "error", err)
	}

	return connect.NewResponse(&pm.TerminateTerminalSessionResponse{}), nil
}

// TerminateUserSessions force-closes every LIVE terminal session belonging to
// userID. It's the revocation path (audit l.174): a disabled
// or deleted user's already-open, root-capable shell must be killed, not left
// running until they happen to disconnect. The single-use token already blocks
// NEW sessions and pending tokens expire within the token TTL, so this closes
// the gap of an ALREADY-ACCEPTED session.
//
// Best-effort and non-fatal: per-session failures are logged so one stuck
// session can't strand the others. Reuses the admin RPCs — ListActiveTerminal
// Sessions has no in-method auth gate, and Terminate is invoked under a
// synthetic system actor so the audit event is correctly attributed to the
// system, not an admin. Intended to run on a background goroutine (see
// TerminalRevocationListener) so it never blocks the disable/delete that
// triggered it.
func (h *TerminalHandler) TerminateUserSessions(ctx context.Context, userID string) {
	sysCtx := auth.WithUser(ctx, &auth.UserContext{ID: "system", Email: "system@power-manage"})

	// Enumerate UNSCOPED: this is a system-initiated revocation, not a scoped
	// admin's list. Going through ListActiveTerminalSessions would apply
	// scopedSessions, which under this user-less context fails closed to zero
	// sessions — terminating nothing (H1 / #391).
	targets, err := h.sessionsForUser(sysCtx, userID)
	if err != nil {
		h.logger.Error("revocation: failed to list terminal sessions", "user_id", userID, "error", err)
		return
	}

	for _, s := range targets {
		if _, err := h.TerminateTerminalSession(sysCtx, connect.NewRequest(&pm.TerminateTerminalSessionRequest{
			SessionId: s.SessionId,
			Reason:    "user access revoked",
		})); err != nil {
			h.logger.Error("revocation: failed to terminate terminal session",
				"user_id", userID, "session_id", s.SessionId, "error", err)
		} else {
			h.logger.Info("revocation: terminated terminal session",
				"user_id", userID, "session_id", s.SessionId)
		}
	}
}

// sessionsForUser returns the live terminal sessions belonging to userID,
// WITHOUT caller-scope filtering. The internal revocation path is
// a system operation and must see every session regardless of any device-group
// scope; routing it through the scoped ListActiveTerminalSessions RPC under a
// user-less context silently filtered to zero and terminated nothing (H1 /
// #391).
func (h *TerminalHandler) sessionsForUser(ctx context.Context, userID string) ([]*pm.TerminalSessionInfo, error) {
	all, err := h.listSessions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*pm.TerminalSessionInfo, 0, len(all))
	for _, s := range all {
		if s.UserId == userID {
			out = append(out, s)
		}
	}
	return out, nil
}

// TerminalBaseURL normalises the configured terminal URL into the
// token-free form returned by StartTerminalResponse.terminal_url:
// any query string, fragment, or trailing slash is stripped so the
// web client can safely append ?token=<session_token> when opening
// its WebSocket. Exported so main.go can call it once at startup.
func TerminalBaseURL(raw string) string {
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
