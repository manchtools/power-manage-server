package api

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/resolution"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// InternalHandler implements the InternalService for gateway → control proxying.
// This service is only accessible on the internal network, not exposed externally.
type InternalHandler struct {
	pmv1connect.UnimplementedInternalServiceHandler

	store                     *store.Store
	encryptor                 *crypto.Encryptor
	logger                    *slog.Logger
	autoProvisionAssignedUser bool
}

// NewInternalHandler creates a new internal service handler.
func NewInternalHandler(st *store.Store, enc *crypto.Encryptor, logger *slog.Logger, autoProvision bool) *InternalHandler {
	return &InternalHandler{
		store:                     st,
		encryptor:                 enc,
		logger:                    logger,
		autoProvisionAssignedUser: autoProvision,
	}
}

// ProxySyncActions resolves all assigned actions for a device.
func (h *InternalHandler) ProxySyncActions(ctx context.Context, req *connect.Request[pm.InternalSyncActionsRequest]) (*connect.Response[pm.SyncActionsResponse], error) {
	deviceID := req.Msg.DeviceId
	if deviceID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device_id is required"))
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

	// Inject auto-provision USER action if enabled and device has an assigned user
	if h.autoProvisionAssignedUser {
		if provAction := h.buildAutoProvisionAction(ctx, deviceID); provAction != nil {
			actions = append(actions, provAction)
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

	luksStreamID := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
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
			continue
		}

		lpsStreamID := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
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

// buildAutoProvisionAction builds a synthetic USER action (PRESENT) for the
// device's assigned user. Returns nil if the device has no assigned user or
// if the username cannot be derived.
func (h *InternalHandler) buildAutoProvisionAction(ctx context.Context, deviceID string) *pm.Action {
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: deviceID})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			h.logger.Warn("auto-provision: failed to get device", "error", err, "device_id", deviceID)
		}
		return nil
	}
	if device.AssignedUserID == nil || *device.AssignedUserID == "" {
		return nil
	}

	user, err := h.store.Queries().GetUserByID(ctx, *device.AssignedUserID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			h.logger.Warn("auto-provision: failed to get assigned user", "error", err, "user_id", *device.AssignedUserID)
		}
		return nil
	}

	username := deriveLinuxUsername(user.Email, user.PreferredUsername)
	if username == "" {
		h.logger.Warn("auto-provision: could not derive username", "user_id", *device.AssignedUserID, "email", user.Email)
		return nil
	}

	comment := user.DisplayName
	if comment == "" {
		comment = user.Email
	}

	return &pm.Action{
		Type:         pm.ActionType_ACTION_TYPE_USER,
		DesiredState: pm.DesiredState_DESIRED_STATE_PRESENT,
		Params: &pm.Action_User{User: &pm.UserParams{
			Username:   username,
			CreateHome: true,
			Comment:    comment,
		}},
	}
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
		parseActionParams(action, a.ActionType, a.Params)
	}

	return action
}

// parseActionParams is also defined in handler/agent.go.
// During dual-mode, both copies coexist. After migration, this remains.
func parseActionParams(action *pm.Action, actionType int32, paramsJSON []byte) {
	unmarshal := protojson.UnmarshalOptions{DiscardUnknown: true}

	switch pm.ActionType(actionType) {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		var p pm.PackageParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Package{Package: &p}
		}
	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		var p pm.AppInstallParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_App{App: &p}
		}
	case pm.ActionType_ACTION_TYPE_FLATPAK:
		var p pm.FlatpakParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Flatpak{Flatpak: &p}
		}
	case pm.ActionType_ACTION_TYPE_SHELL:
		var p pm.ShellParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Shell{Shell: &p}
		}
	case pm.ActionType_ACTION_TYPE_SYSTEMD:
		var p pm.SystemdParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Systemd{Systemd: &p}
		}
	case pm.ActionType_ACTION_TYPE_FILE:
		var p pm.FileParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_File{File: &p}
		}
	case pm.ActionType_ACTION_TYPE_UPDATE:
		var p pm.UpdateParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Update{Update: &p}
		}
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		var p pm.RepositoryParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Repository{Repository: &p}
		}
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		var p pm.DirectoryParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Directory{Directory: &p}
		}
	case pm.ActionType_ACTION_TYPE_USER:
		var p pm.UserParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_User{User: &p}
		}
	case pm.ActionType_ACTION_TYPE_GROUP:
		var p pm.GroupParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Group{Group: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSH:
		var p pm.SshParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Ssh{Ssh: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSHD:
		var p pm.SshdParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Sshd{Sshd: &p}
		}
	case pm.ActionType_ACTION_TYPE_SUDO:
		var p pm.SudoParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Sudo{Sudo: &p}
		}
	case pm.ActionType_ACTION_TYPE_LPS:
		var p pm.LpsParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Lps{Lps: &p}
		}
	case pm.ActionType_ACTION_TYPE_LUKS:
		var p pm.LuksParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Luks{Luks: &p}
		}
	}
}
