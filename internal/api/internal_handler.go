package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/resolution"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

// InternalHandler implements the InternalService for gateway → control proxying.
// This service is only accessible on the internal network, not exposed externally.
type InternalHandler struct {
	pmv1connect.UnimplementedInternalServiceHandler

	store     *store.Store
	encryptor *crypto.Encryptor
	logger    *slog.Logger

	// terminalTokenStore is set via SetTerminalTokenStore after the
	// Valkey-backed store is constructed in main.go. nil when terminal
	// sessions are not configured on this control instance, in which
	// case ProxyValidateTerminalToken returns Unavailable so the
	// gateway gets a clean error rather than the InternalService
	// default 'method not implemented'.
	terminalTokenStore *terminal.TokenStore
}

// NewInternalHandler creates a new internal service handler.
func NewInternalHandler(st *store.Store, enc *crypto.Encryptor, logger *slog.Logger) *InternalHandler {
	return &InternalHandler{
		store:     st,
		encryptor: enc,
		logger:    logger,
	}
}

// SetTerminalTokenStore wires the Valkey-backed terminal token store
// so ProxyValidateTerminalToken can validate the bearer tokens minted
// by ControlService.StartTerminal. Called from main.go alongside
// ControlService.SetTerminalHandler so the two paths share one store.
func (h *InternalHandler) SetTerminalTokenStore(s *terminal.TokenStore) {
	h.terminalTokenStore = s
}

// VerifyDevice checks that a device exists and is not deleted.
// Called by the gateway before registering an agent connection.
func (h *InternalHandler) VerifyDevice(ctx context.Context, req *connect.Request[pm.VerifyDeviceRequest]) (*connect.Response[pm.VerifyDeviceResponse], error) {
	deviceID := req.Msg.DeviceId
	if deviceID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id is required"))
	}

	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: deviceID})
	if err != nil {
		h.logger.Warn("device verification failed", "device_id", deviceID, "error", err)
		return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found or deleted"))
	}

	return connect.NewResponse(&pm.VerifyDeviceResponse{}), nil
}

// ProxySyncActions resolves all assigned actions for a device.
func (h *InternalHandler) ProxySyncActions(ctx context.Context, req *connect.Request[pm.InternalSyncActionsRequest]) (*connect.Response[pm.SyncActionsResponse], error) {
	deviceID := req.Msg.DeviceId
	if deviceID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id is required"))
	}

	// Verify the device exists and is not deleted.
	if _, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: deviceID}); err != nil {
		h.logger.Warn("sync actions for unknown/deleted device", "device_id", deviceID)
		return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found or deleted"))
	}

	h.logger.Debug("proxy sync actions", "device_id", deviceID)

	dbActions, err := resolution.ResolveActionsForDevice(ctx, h.store.Queries(), deviceID)
	if err != nil {
		h.logger.Error("failed to resolve actions", "device_id", deviceID, "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to resolve actions"))
	}

	syncInterval, err := h.store.Queries().GetDeviceSyncInterval(ctx, deviceID)
	if err != nil {
		h.logger.Warn("failed to get sync interval, using default", "device_id", deviceID, "error", err)
		syncInterval = 0
	}

	actions := make([]*pm.Action, 0, len(dbActions))
	for _, dbAction := range dbActions {
		action := dbResolvedActionToWireAction(dbAction)
		if action != nil {
			actions = append(actions, action)
		}
	}

	h.logger.Debug("proxy sync actions completed", "device_id", deviceID, "count", len(actions), "sync_interval_minutes", syncInterval)

	return connect.NewResponse(&pm.SyncActionsResponse{
		Actions:             actions,
		SyncIntervalMinutes: syncInterval,
	}), nil
}

// ProxyValidateLuksToken validates and consumes a one-time LUKS token.
func (h *InternalHandler) ProxyValidateLuksToken(ctx context.Context, req *connect.Request[pm.InternalValidateLuksTokenRequest]) (*connect.Response[pm.ValidateLuksTokenResponse], error) {
	if req.Msg.DeviceId == "" || req.Msg.Token == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id and token are required"))
	}

	token, err := h.store.Queries().ValidateAndConsumeLuksToken(ctx, db.ValidateAndConsumeLuksTokenParams{
		Token:    req.Msg.Token,
		DeviceID: req.Msg.DeviceId,
	})
	if err != nil {
		h.logger.Warn("LUKS token validation failed", "device_id", req.Msg.DeviceId, "error", err)
		return nil, connect.NewError(connect.CodeNotFound, errors.New("token is invalid or has expired"))
	}

	devicePath := ""
	key, err := h.store.Queries().GetCurrentLuksKeyForAction(ctx, db.GetCurrentLuksKeyForActionParams{
		DeviceID: req.Msg.DeviceId,
		ActionID: token.ActionID,
	})
	if err == nil {
		devicePath = key.DevicePath
	}

	return connect.NewResponse(&pm.ValidateLuksTokenResponse{
		ActionId:   token.ActionID,
		DevicePath: devicePath,
		MinLength:  token.MinLength,
		Complexity: pm.LpsPasswordComplexity(token.Complexity),
	}), nil
}

// ProxyGetLuksKey retrieves and decrypts the current LUKS key for a device+action.
func (h *InternalHandler) ProxyGetLuksKey(ctx context.Context, req *connect.Request[pm.InternalGetLuksKeyRequest]) (*connect.Response[pm.GetLuksKeyResponse], error) {
	if req.Msg.DeviceId == "" || req.Msg.ActionId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id and action_id are required"))
	}

	key, err := h.store.Queries().GetCurrentLuksKeyForAction(ctx, db.GetCurrentLuksKeyForActionParams{
		DeviceID: req.Msg.DeviceId,
		ActionID: req.Msg.ActionId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no LUKS key found for this action"))
	}

	passphrase, err := h.encryptor.Decrypt(key.Passphrase)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to decrypt passphrase"))
	}

	return connect.NewResponse(&pm.GetLuksKeyResponse{
		Passphrase: passphrase,
	}), nil
}

// ProxyStoreLuksKey encrypts and stores a new LUKS key.
func (h *InternalHandler) ProxyStoreLuksKey(ctx context.Context, req *connect.Request[pm.InternalStoreLuksKeyRequest]) (*connect.Response[pm.StoreLuksKeyResponse], error) {
	if req.Msg.DeviceId == "" || req.Msg.ActionId == "" || req.Msg.Passphrase == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id, action_id, and passphrase are required"))
	}

	encPassphrase, err := h.encryptor.Encrypt(req.Msg.Passphrase)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to encrypt passphrase"))
	}

	luksStreamID := ulid.Make().String()
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   luksStreamID,
		EventType:  "LuksKeyRotated",
		Data: map[string]any{
			"device_id":       req.Msg.DeviceId,
			"action_id":       req.Msg.ActionId,
			"device_path":     req.Msg.DevicePath,
			"passphrase":      encPassphrase,
			"rotated_at":      time.Now().Format(time.RFC3339),
			"rotation_reason": req.Msg.RotationReason,
		},
		ActorType: "device",
		ActorID:   req.Msg.DeviceId,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store LUKS key: %w", err))
	}

	return connect.NewResponse(&pm.StoreLuksKeyResponse{
		Success: true,
	}), nil
}

// ProxyStoreLpsPasswords encrypts and stores LPS password rotation entries.
func (h *InternalHandler) ProxyStoreLpsPasswords(ctx context.Context, req *connect.Request[pm.InternalStoreLpsPasswordsRequest]) (*connect.Response[pm.InternalStoreLpsPasswordsResponse], error) {
	if req.Msg.DeviceId == "" || req.Msg.ActionId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id and action_id are required"))
	}

	// Persistence MUST fail-closed. LPS rotation is irreversible:
	// the agent has already run chpasswd locally, so the old password
	// is gone. If the server silently fails to persist the new one,
	// the user loses the only copy that LPS was meant to retain —
	// and the gateway's post-RPC cleanup in agent.go clears the
	// lps.rotations metadata from the execution result the moment
	// this RPC returns success, so there is no second chance. Return
	// an error on any append failure so the gateway leaves the
	// metadata in place and the next retry replays the rotation
	// persistence without needing a second local rotation.
	//
	// Encryption failures are already fail-closed above. Append
	// failures now join that policy.
	var (
		persisted int
		firstErr  error
	)
	for _, r := range req.Msg.Rotations {
		encPassword, err := h.encryptor.Encrypt(r.Password)
		if err != nil {
			h.logger.Error("failed to encrypt LPS password", "error", err)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to encrypt password for user %s", r.Username))
		}

		lpsStreamID := ulid.Make().String()
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "lps_password",
			StreamID:   lpsStreamID,
			EventType:  "LpsPasswordRotated",
			Data: map[string]any{
				"device_id":       req.Msg.DeviceId,
				"action_id":       req.Msg.ActionId,
				"username":        r.Username,
				"password":        encPassword,
				"rotated_at":      r.RotatedAt,
				"rotation_reason": r.Reason,
			},
			ActorType: "device",
			ActorID:   req.Msg.DeviceId,
		}); err != nil {
			h.logger.Error("failed to append LpsPasswordRotated event",
				"device_id", req.Msg.DeviceId,
				"action_id", req.Msg.ActionId,
				"username", r.Username,
				"persisted_before_failure", persisted,
				"total_rotations", len(req.Msg.Rotations),
				"error", err,
			)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		persisted++
	}
	if firstErr != nil {
		// Partial success is indistinguishable from full failure
		// from the agent's perspective: the gateway will leave the
		// execution-result metadata alone and the inbox task will
		// retry. The retry will re-attempt the full rotation list.
		// Already-persisted rotations will append a second event
		// with the same (device_id, username, password) payload —
		// not ideal, but harmless: the projection deduplicates by
		// (device_id, username) and keeps the most recent, and the
		// event stream is an append-only audit record where a
		// duplicate tells the truth ("we saw this twice during a
		// retry") rather than lying.
		//
		// Route through apiErrorCtx so the response carries the
		// same `internal_error` ErrorDetail code the rest of the
		// handlers emit — the agent's inbox retry loop keys off
		// that code to decide whether to retry.
		h.logger.Error("LPS rotation persistence failed, returning error to trigger inbox retry",
			"device_id", req.Msg.DeviceId,
			"action_id", req.Msg.ActionId,
			"persisted", persisted,
			"total_rotations", len(req.Msg.Rotations),
			"first_error", firstErr,
		)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal,
			fmt.Sprintf("failed to persist %d of %d LPS rotations",
				len(req.Msg.Rotations)-persisted, len(req.Msg.Rotations)))
	}

	return connect.NewResponse(&pm.InternalStoreLpsPasswordsResponse{}), nil
}

// ProxyValidateTerminalToken validates the bearer token a web client
// presents when opening the gateway's WebSocket terminal endpoint and
// returns the session metadata the gateway needs to bridge the
// connection.
//
// rc10 single-use contract: a successful validation CONSUMES the
// token atomically (Valkey GETDEL), so a second call with the same
// bearer returns Unauthenticated. This blocks the replay surface
// where a token leaks via a reverse-proxy access log that captured
// the query-string — the attacker can no longer mint additional
// WebSocket connections during the 60 s TTL.
//
// Real flow only validates once per WS: the gateway calls this RPC
// from terminal_bridge.go at connection acceptance, stashes the
// returned metadata for the WebSocket's lifetime, and never re-
// validates. So the single-use contract is consistent with normal
// operation; only attacker replays break.
//
// Forgery attempts (valid session_id, wrong bearer) do NOT consume
// the entry — the terminal store restores the session with its
// remaining TTL so a legitimate client isn't locked out by a guess.
//
// Distinguishes 'unknown / expired / already consumed' (Unauthenticated,
// with a generic message so a forgery probe cannot tell the
// difference) from 'mismatched token' (Unauthenticated, but logged
// separately so the audit pipeline can flag forgery attempts). 'Token
// store not configured' is Unavailable — operator misconfiguration,
// not a client bug.
func (h *InternalHandler) ProxyValidateTerminalToken(ctx context.Context, req *connect.Request[pm.InternalValidateTerminalTokenRequest]) (*connect.Response[pm.InternalValidateTerminalTokenResponse], error) {
	if h.terminalTokenStore == nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("remote terminal sessions are not configured on this control instance"))
	}

	sessionID := req.Msg.SessionId
	bearer := req.Msg.Token
	if sessionID == "" || bearer == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("session_id and token are required"))
	}

	session, err := h.terminalTokenStore.Validate(ctx, sessionID, bearer)
	if err != nil {
		// Map the two possible store errors to the same gRPC code so a
		// forgery probe cannot tell expired from mismatched, but log
		// them differently so operators can spot active attacks.
		switch {
		case errors.Is(err, terminal.ErrTokenMismatch):
			h.logger.Warn("terminal token mismatch (possible forgery attempt)",
				"session_id", sessionID)
		case errors.Is(err, terminal.ErrTokenNotFound):
			h.logger.Debug("terminal token unknown or expired",
				"session_id", sessionID)
		default:
			h.logger.Error("terminal token validation failed",
				"session_id", sessionID, "error", err)
			return nil, connect.NewError(connect.CodeInternal,
				errors.New("failed to validate session token"))
		}
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("invalid or expired session token"))
	}

	h.logger.Debug("terminal token validated",
		"session_id", sessionID,
		"user_id", session.UserID,
		"device_id", session.DeviceID,
	)
	return connect.NewResponse(&pm.InternalValidateTerminalTokenResponse{
		UserId:   session.UserID,
		DeviceId: session.DeviceID,
		TtyUser:  session.TtyUser,
		Cols:     session.Cols,
		Rows:     session.Rows,
	}), nil
}

// dbResolvedActionToWireAction converts a resolved action row to wire format.
// Note: This is also defined in handler/agent.go — when the gateway migration
// is complete, only this version will remain.
func dbResolvedActionToWireAction(a db.ListResolvedActionsForDeviceRow) *pm.Action {
	action := &pm.Action{
		Id:              &pm.ActionId{Value: a.ID},
		Type:            pm.ActionType(a.ActionType),
		DesiredState:    pm.DesiredState(a.DesiredState),
		TimeoutSeconds:  a.TimeoutSeconds,
		Signature:       a.Signature,
		ParamsCanonical: a.ParamsCanonical,
	}

	if len(a.Params) > 0 {
		actionparams.PopulateAction(action, a.ActionType, a.Params)
	}

	if len(a.Schedule) > 0 {
		action.Schedule = scheduleFromJSON(a.Schedule)
	}

	return action
}

