package device

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	sdkterminal "github.com/manchtools/power-manage-sdk/sys/terminal"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

// StartTerminal persists the authorized session and mints one short-lived,
// single-use bearer for control's process-local WebSocket bridge.
func (h *Handlers) StartTerminal(ctx context.Context, req *connect.Request[pmv1.StartTerminalRequest]) (*connect.Response[pmv1.StartTerminalResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.requireTerminalPermission(ctx, "StartTerminal", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	// Apply device-group confinement before existence lookup so a scoped caller
	// cannot distinguish an out-of-scope device from an unknown one.
	if err := h.enforceDeviceScope(ctx, "StartTerminal", req.Msg.DeviceId); err != nil {
		return nil, err
	}
	if _, err := h.store.GetDevice(ctx, req.Msg.DeviceId); err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errDeviceNotFound, "device not found")
		}
		return nil, h.internal(ctx, "read terminal device", err)
	}
	if !h.isConnected(req.Msg.DeviceId) {
		return nil, rpcError(ctx, errDeviceNotConnected, connect.CodeFailedPrecondition, "device is not connected")
	}
	user, err := h.store.GetUser(ctx, actor.ID)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errUserNotFound, "user not found")
		}
		return nil, h.internal(ctx, "read terminal user", err)
	}
	if user.Disabled || user.IsDeleted {
		return nil, rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "user account is disabled")
	}
	linuxUsername := strings.TrimSpace(user.LinuxUsername)
	if linuxUsername == "" {
		return nil, rpcError(ctx, errTerminalUsernameMissing, connect.CodeFailedPrecondition,
			"user has no Linux username")
	}
	ttyUser := sdkterminal.TTYUsername(linuxUsername)
	cols, rows := req.Msg.Cols, req.Msg.Rows
	if cols == 0 {
		cols = sdkterminal.DefaultCols
	}
	if rows == 0 {
		rows = sdkterminal.DefaultRows
	}

	sessionID := ulid.Make().String()
	minted, err := h.terminalTokens.MintWithID(ctx, sessionID, terminal.MintParams{
		UserID: actor.ID, DeviceID: req.Msg.DeviceId, TtyUser: ttyUser, Cols: cols, Rows: rows,
	})
	if err != nil {
		return nil, h.internal(ctx, "mint terminal token", err)
	}
	startedAt := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceStartTerminalProcedure, "StartTerminal"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if err := tx.InsertTerminalSession(ctx, db.InsertTerminalSessionParams{
				SessionID: sessionID, DeviceID: req.Msg.DeviceId, UserID: actor.ID,
				TtyUser: ttyUser, StartedAt: startedAt, Cols: int32(cols), Rows: int32(rows),
			}); err != nil {
				return fmt.Errorf("insert terminal session: %w", err)
			}
			rec.Effect(terminalEffect(sessionID, "START", store.EffectApplied,
				"cols", "device_id", "rows", "started_at", "tty_user", "user_id"))
			return nil
		})
	if err != nil {
		if revokeErr := h.terminalTokens.Revoke(ctx, sessionID); revokeErr != nil {
			h.logger.Error("failed to revoke uncommitted terminal token", "session_id", sessionID, "error", revokeErr)
		}
		return nil, h.internal(ctx, "commit terminal session", err)
	}
	return connect.NewResponse(&pmv1.StartTerminalResponse{
		SessionId: sessionID, SessionToken: minted.Token, TerminalUrl: h.terminalURL,
		ExpiresAt: timestamppb.New(minted.ExpiresAt), TtyUser: ttyUser,
	}), nil
}

// StopTerminal accepts an idempotent owner stop, commits it, and then closes
// the live bridge and agent PTY on a best-effort basis as required by contract.
func (h *Handlers) StopTerminal(ctx context.Context, req *connect.Request[pmv1.StopTerminalRequest]) (*connect.Response[pmv1.StopTerminalResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.requireTerminalPermission(ctx, "StopTerminal", req.Msg.SessionId); err != nil {
		return nil, err
	}
	session, err := h.store.GetOpenTerminalSession(ctx, req.Msg.SessionId)
	if err != nil {
		if store.IsNotFound(err) {
			return connect.NewResponse(&pmv1.StopTerminalResponse{}), nil
		}
		return nil, h.internal(ctx, "read terminal session", err)
	}
	if session.UserID != actor.ID {
		return nil, rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "terminal session belongs to another user")
	}
	if err := h.enforceDeviceScope(ctx, "StopTerminal", session.DeviceID); err != nil {
		return nil, err
	}

	stoppedAt := h.now().UTC()
	reason := "user stopped"
	_, err = h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceStopTerminalProcedure, "StopTerminal"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			rows, err := tx.StopTerminalSession(ctx, db.StopTerminalSessionParams{
				StoppedAt: &stoppedAt, ExitReason: &reason, SessionID: session.SessionID,
			})
			if err != nil {
				return fmt.Errorf("stop terminal session: %w", err)
			}
			outcome := store.EffectApplied
			if rows == 0 {
				outcome = store.EffectRejected
			}
			rec.Effect(terminalEffect(session.SessionID, "STOP", outcome, "exit_reason", "stopped_at"))
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "commit terminal stop", err)
	}
	h.sendTerminalStop(session.DeviceID, session.SessionID, reason)
	h.terminalSessions.Unregister(session.SessionID)
	if err := h.terminalTokens.Revoke(ctx, session.SessionID); err != nil {
		h.logger.Error("failed to revoke stopped terminal token", "session_id", session.SessionID, "error", err)
	}
	return connect.NewResponse(&pmv1.StopTerminalResponse{}), nil
}

// ListActiveTerminalSessions enumerates only sessions with a live bridge in
// this single control process, then applies exact filters, scope, and paging.
func (h *Handlers) ListActiveTerminalSessions(ctx context.Context, req *connect.Request[pmv1.ListActiveTerminalSessionsRequest]) (*connect.Response[pmv1.ListActiveTerminalSessionsResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	if req.Msg.PageToken != "" {
		if _, err := ulid.ParseStrict(req.Msg.PageToken); err != nil {
			return nil, rpcError(ctx, errInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.requireTerminalPermission(ctx, "ListActiveTerminalSessions", ""); err != nil {
		return nil, err
	}

	live := h.terminalSessions.List()
	sort.Slice(live, func(i, j int) bool { return live[i].SessionID > live[j].SessionID })
	all := make([]*pmv1.TerminalSessionInfo, 0, len(live))
	for _, current := range live {
		if req.Msg.DeviceId != "" && current.DeviceID != req.Msg.DeviceId {
			continue
		}
		if req.Msg.UserId != "" && current.UserID != req.Msg.UserId {
			continue
		}
		row, err := h.store.GetOpenTerminalSession(ctx, current.SessionID)
		if err != nil {
			if store.IsNotFound(err) {
				continue
			}
			return nil, h.internal(ctx, "read live terminal session", err)
		}
		allowed, err := h.terminalDeviceInScope(ctx, row.DeviceID)
		if err != nil {
			return nil, h.internal(ctx, "resolve terminal session scope", err)
		}
		if !allowed {
			continue
		}
		if row.DeviceID != current.DeviceID || row.UserID != current.UserID || row.TtyUser != current.TtyUser {
			return nil, h.internal(ctx, "verify live terminal session",
				fmt.Errorf("registry metadata does not match session %s", current.SessionID))
		}
		all = append(all, &pmv1.TerminalSessionInfo{
			SessionId: row.SessionID, UserId: row.UserID, UserEmail: row.UserEmail,
			DeviceId: row.DeviceID, DeviceHostname: row.DeviceHostname, TtyUser: row.TtyUser,
			StartedAt: timestamppb.New(row.StartedAt), LastActivityAt: timestamppb.New(current.LastActivity()),
		})
	}
	total := len(all)
	pageSize := req.Msg.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	page := make([]*pmv1.TerminalSessionInfo, 0, pageSize)
	for _, session := range all {
		if req.Msg.PageToken != "" && session.SessionId >= req.Msg.PageToken {
			continue
		}
		if len(page) == int(pageSize) {
			break
		}
		page = append(page, session)
	}
	next := ""
	if len(page) == int(pageSize) {
		lastID := page[len(page)-1].SessionId
		for _, session := range all {
			if session.SessionId < lastID {
				next = lastID
				break
			}
		}
	}
	op := h.operation(req, actor, powermanagev1connect.ControlServiceListActiveTerminalSessionsProcedure,
		"ListActiveTerminalSessions")
	op.Class = store.ClassSensitiveRead
	if _, err := h.store.RecordOperation(ctx, op); err != nil {
		return nil, h.internal(ctx, "record terminal session list", err)
	}
	return connect.NewResponse(&pmv1.ListActiveTerminalSessionsResponse{
		Sessions: page, NextPageToken: next, TotalCount: int32(total),
	}), nil
}

// TerminateTerminalSession is the forcible admin path. It records intent before
// sending, surfaces a failed agent write, and only then commits terminal state.
func (h *Handlers) TerminateTerminalSession(ctx context.Context, req *connect.Request[pmv1.TerminateTerminalSessionRequest]) (*connect.Response[pmv1.TerminateTerminalSessionResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.requireTerminalPermission(ctx, "TerminateTerminalSession", req.Msg.SessionId); err != nil {
		return nil, err
	}
	session, err := h.store.GetOpenTerminalSession(ctx, req.Msg.SessionId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, errTerminalSessionMissing, "terminal session not found")
		}
		return nil, h.internal(ctx, "read terminal session", err)
	}
	if err := h.enforceDeviceScope(ctx, "TerminateTerminalSession", session.DeviceID); err != nil {
		return nil, err
	}
	live := h.terminalSessions.Get(session.SessionID)
	if live != nil && (live.DeviceID != session.DeviceID || live.UserID != session.UserID) {
		return nil, h.internal(ctx, "verify terminal termination target",
			fmt.Errorf("registry metadata does not match session %s", session.SessionID))
	}
	if live == nil {
		if _, lookupErr := h.terminalTokens.Lookup(ctx, session.SessionID); lookupErr != nil {
			if errors.Is(lookupErr, terminal.ErrTokenNotFound) {
				return nil, notFound(ctx, errTerminalSessionMissing, "terminal session not found")
			}
			return nil, h.internal(ctx, "read pending terminal token", lookupErr)
		}
	}
	record, err := h.store.RecordOperation(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceTerminateTerminalSessionProcedure, "TerminateTerminalSession"),
		terminalEffect(session.SessionID, "TERMINATE", store.EffectApplied))
	if err != nil {
		return nil, h.internal(ctx, "record terminal termination intent", err)
	}

	if live != nil {
		err = h.agentSender.Send(session.DeviceID, &pmv1.ServerMessage{
			Id: ulid.Make().String(),
			Payload: &pmv1.ServerMessage_TerminalStop{TerminalStop: &pmv1.TerminalStop{
				SessionId: session.SessionID, Reason: req.Msg.Reason,
			}},
		})
		if err != nil {
			_, auditErr := h.store.WithAuditEffects(ctx, record.OperationID,
				func(_ context.Context, _ *store.Tx, rec *store.AuditRecorder) error {
					rec.Effect(terminalEffect(session.SessionID, "TERMINATE", store.EffectFailed))
					return nil
				})
			if auditErr != nil {
				return nil, h.internal(ctx, "record terminal termination failure", auditErr)
			}
			return nil, rpcError(ctx, errDeviceUnavailable, connect.CodeUnavailable, "device is unavailable")
		}
	}
	stoppedAt := h.now().UTC()
	reason := req.Msg.Reason
	_, err = h.store.WithAuditEffects(ctx, record.OperationID,
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			rows, err := tx.StopTerminalSession(ctx, db.StopTerminalSessionParams{
				StoppedAt: &stoppedAt, ExitReason: &reason, TerminatedBy: &actor.ID,
				SessionID: session.SessionID,
			})
			if err != nil {
				return fmt.Errorf("terminate terminal session: %w", err)
			}
			outcome := store.EffectApplied
			if rows == 0 {
				outcome = store.EffectRejected
			}
			rec.Effect(terminalEffect(session.SessionID, "TERMINATE", outcome,
				"exit_reason", "stopped_at", "terminated_by"))
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "commit terminal termination", err)
	}
	h.terminalSessions.Unregister(session.SessionID)
	if err := h.terminalTokens.Revoke(ctx, session.SessionID); err != nil {
		h.logger.Error("failed to revoke terminated terminal token", "session_id", session.SessionID, "error", err)
	}
	return connect.NewResponse(&pmv1.TerminateTerminalSessionResponse{}), nil
}

func (h *Handlers) requireTerminalPermission(ctx context.Context, permission, resourceID string) error {
	if !auth.HasPermission(ctx, permission) {
		return rpcError(ctx, errPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	return h.authorize(ctx, permission, resourceID)
}

func (h *Handlers) terminalDeviceInScope(ctx context.Context, deviceID string) (bool, error) {
	groupIDs, restricted := auth.DeviceScopeListFilter(ctx, "ListActiveTerminalSessions")
	if !restricted {
		return true, nil
	}
	if len(groupIDs) == 0 {
		return false, nil
	}
	deviceGroups, err := h.store.ListDeviceGroupIDs(ctx, deviceID)
	if err != nil {
		return false, err
	}
	allowed := make(map[string]struct{}, len(groupIDs))
	for _, id := range groupIDs {
		allowed[id] = struct{}{}
	}
	for _, id := range deviceGroups {
		if _, ok := allowed[id]; ok {
			return true, nil
		}
	}
	return false, nil
}

func (h *Handlers) sendTerminalStop(deviceID, sessionID, reason string) {
	if err := h.agentSender.Send(deviceID, &pmv1.ServerMessage{
		Id: ulid.Make().String(),
		Payload: &pmv1.ServerMessage_TerminalStop{TerminalStop: &pmv1.TerminalStop{
			SessionId: sessionID, Reason: reason,
		}},
	}); err != nil {
		h.logger.Warn("terminal stop could not reach device", "session_id", sessionID, "device_id", deviceID)
	}
}

func terminalEffect(sessionID, action string, outcome store.EffectOutcome, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "terminal_session", ResourceID: sessionID, Action: action,
		Outcome: outcome, ChangedFields: fields,
	}
}

func normalizeTerminalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "wss" || u.Host == "" {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}
