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
)

// InternalHandler implements the InternalService for gateway → control proxying.
// This service is only accessible on the internal network, not exposed externally.
type InternalHandler struct {
	pmv1connect.UnimplementedInternalServiceHandler

	store     *store.Store
	encryptor *crypto.Encryptor
	logger    *slog.Logger
}

// NewInternalHandler creates a new internal service handler.
func NewInternalHandler(st *store.Store, enc *crypto.Encryptor, logger *slog.Logger) *InternalHandler {
	return &InternalHandler{
		store:     st,
		encryptor: enc,
		logger:    logger,
	}
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
				"error", err,
			)
		}
	}

	return connect.NewResponse(&pm.InternalStoreLpsPasswordsResponse{}), nil
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

// parseActionParams consolidated into internal/actionparams.PopulateAction.
