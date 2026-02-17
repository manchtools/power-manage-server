package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// DeviceHandler handles device management RPCs.
type DeviceHandler struct {
	store     *store.Store
	encryptor *crypto.Encryptor
}

// NewDeviceHandler creates a new device handler.
func NewDeviceHandler(st *store.Store, enc *crypto.Encryptor) *DeviceHandler {
	return &DeviceHandler{store: st, encryptor: enc}
}

// ListDevices returns a paginated list of devices.
// Admins see all devices; regular users see only their assigned devices.
func (h *DeviceHandler) ListDevices(ctx context.Context, req *connect.Request[pm.ListDevicesRequest]) (*connect.Response[pm.ListDevicesResponse], error) {
	pageSize := int32(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	offset := int32(0)
	if req.Msg.PageToken != "" {
		offset64, err := parsePageToken(req.Msg.PageToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page token"))
		}
		offset = int32(offset64)
	}

	q := h.store.Queries()
	filterUID := userFilterID(ctx)

	var devices []db.DevicesProjection
	var err error

	switch req.Msg.StatusFilter {
	case "online":
		devices, err = q.ListDevicesOnline(ctx, db.ListDevicesOnlineParams{
			Limit:        pageSize,
			Offset:       offset,
			FilterUserID: filterUID,
		})
	case "offline":
		devices, err = q.ListDevicesOffline(ctx, db.ListDevicesOfflineParams{
			Limit:        pageSize,
			Offset:       offset,
			FilterUserID: filterUID,
		})
	default:
		devices, err = q.ListDevices(ctx, db.ListDevicesParams{
			Limit:        pageSize,
			Offset:       offset,
			FilterUserID: filterUID,
		})
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list devices"))
	}

	count, err := q.CountDevices(ctx, filterUID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count devices"))
	}

	var nextPageToken string
	if int32(len(devices)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoDevices := make([]*pm.Device, len(devices))
	for i, d := range devices {
		protoDevices[i] = h.deviceToProto(d)
	}

	return connect.NewResponse(&pm.ListDevicesResponse{
		Devices:       protoDevices,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// GetDevice returns a device by ID.
// Admins see all devices; regular users see only their assigned devices.
func (h *DeviceHandler) GetDevice(ctx context.Context, req *connect.Request[pm.GetDeviceRequest]) (*connect.Response[pm.GetDeviceResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{
		ID:           req.Msg.Id,
		FilterUserID: userFilterID(ctx),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	return connect.NewResponse(&pm.GetDeviceResponse{
		Device: h.deviceToProto(device),
	}), nil
}

// SetDeviceLabel sets a label on a device.
func (h *DeviceHandler) SetDeviceLabel(ctx context.Context, req *connect.Request[pm.SetDeviceLabelRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	// Emit DeviceLabelSet event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.Id,
		EventType:  "DeviceLabelSet",
		Data: map[string]any{
			"key":   req.Msg.Key,
			"value": req.Msg.Value,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to set label"))
	}

	// Read back updated device
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get updated device"))
	}

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProto(device),
	}), nil
}

// RemoveDeviceLabel removes a label from a device.
func (h *DeviceHandler) RemoveDeviceLabel(ctx context.Context, req *connect.Request[pm.RemoveDeviceLabelRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	// Emit DeviceLabelRemoved event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.Id,
		EventType:  "DeviceLabelRemoved",
		Data: map[string]any{
			"key": req.Msg.Key,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to remove label"))
	}

	// Read back updated device
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get updated device"))
	}

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProto(device),
	}), nil
}

// DeleteDevice deletes a device.
func (h *DeviceHandler) DeleteDevice(ctx context.Context, req *connect.Request[pm.DeleteDeviceRequest]) (*connect.Response[pm.DeleteDeviceResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Emit DeviceDeleted event
	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.Id,
		EventType:  "DeviceDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete device"))
	}

	return connect.NewResponse(&pm.DeleteDeviceResponse{}), nil
}

// AssignDevice assigns a device to a user.
func (h *DeviceHandler) AssignDevice(ctx context.Context, req *connect.Request[pm.AssignDeviceRequest]) (*connect.Response[pm.AssignDeviceResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	// Verify user exists
	_, err = h.store.Queries().GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	// Emit DeviceAssigned event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.DeviceId,
		EventType:  "DeviceAssigned",
		Data: map[string]any{
			"user_id": req.Msg.UserId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to assign device"))
	}

	// Read back updated device
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get updated device"))
	}

	return connect.NewResponse(&pm.AssignDeviceResponse{
		Device: h.deviceToProto(device),
	}), nil
}

// UnassignDevice removes a device from its assigned user.
func (h *DeviceHandler) UnassignDevice(ctx context.Context, req *connect.Request[pm.UnassignDeviceRequest]) (*connect.Response[pm.UnassignDeviceResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	// Emit DeviceUnassigned event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.DeviceId,
		EventType:  "DeviceUnassigned",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to unassign device"))
	}

	// Read back updated device
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get updated device"))
	}

	return connect.NewResponse(&pm.UnassignDeviceResponse{
		Device: h.deviceToProto(device),
	}), nil
}

// SetDeviceSyncInterval sets the sync interval for a device.
func (h *DeviceHandler) SetDeviceSyncInterval(ctx context.Context, req *connect.Request[pm.SetDeviceSyncIntervalRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	// Emit DeviceSyncIntervalSet event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.Id,
		EventType:  "DeviceSyncIntervalSet",
		Data: map[string]any{
			"sync_interval_minutes": req.Msg.SyncIntervalMinutes,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to set sync interval"))
	}

	// Read back updated device
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get updated device"))
	}

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProto(device),
	}), nil
}

// deviceToProto converts a database device projection to a protobuf device.
func (h *DeviceHandler) deviceToProto(d db.DevicesProjection) *pm.Device {
	device := &pm.Device{
		Id:                  d.ID,
		Hostname:            d.Hostname,
		AgentVersion:        d.AgentVersion,
		Labels:              make(map[string]string),
		SyncIntervalMinutes: d.SyncIntervalMinutes,
	}

	// Determine status based on last_seen
	if d.LastSeenAt.Valid {
		device.LastSeenAt = timestamppb.New(d.LastSeenAt.Time)
		if time.Since(d.LastSeenAt.Time) < 5*time.Minute {
			device.Status = "online"
		} else {
			device.Status = "offline"
		}
	} else {
		device.Status = "offline"
	}

	if d.RegisteredAt.Valid {
		device.RegisteredAt = timestamppb.New(d.RegisteredAt.Time)
	}

	if d.CertNotAfter.Valid {
		device.CertExpiresAt = timestamppb.New(d.CertNotAfter.Time)
	}

	if d.AssignedUserID != nil {
		device.AssignedUserId = *d.AssignedUserID
	}

	// Parse labels from JSONB
	if len(d.Labels) > 0 {
		var labels map[string]string
		if err := json.Unmarshal(d.Labels, &labels); err == nil {
			device.Labels = labels
		}
	}

	return device
}

// GetDeviceLpsPasswords returns current and historical LPS passwords for a device.
func (h *DeviceHandler) GetDeviceLpsPasswords(ctx context.Context, req *connect.Request[pm.GetDeviceLpsPasswordsRequest]) (*connect.Response[pm.GetDeviceLpsPasswordsResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Get current passwords
	current, err := h.store.Queries().GetCurrentLpsPasswords(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, fmt.Errorf("get current LPS passwords: %w", err)
	}

	// Get password history
	history, err := h.store.Queries().GetLpsPasswordHistory(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, fmt.Errorf("get LPS password history: %w", err)
	}

	// Convert to proto
	resp := &pm.GetDeviceLpsPasswordsResponse{}

	for _, p := range current {
		// Look up action name
		actionName := ""
		action, err := h.store.Queries().GetActionByID(ctx, p.ActionID)
		if err == nil {
			actionName = action.Name
		}

		// Look up device hostname
		deviceHostname := ""
		device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: p.DeviceID})
		if err == nil {
			deviceHostname = device.Hostname
		}

		decPassword, err := h.encryptor.Decrypt(p.Password)
		if err != nil {
			return nil, fmt.Errorf("decrypt LPS password: %w", err)
		}
		entry := &pm.LpsPassword{
			DeviceId:       p.DeviceID,
			DeviceHostname: deviceHostname,
			ActionId:       p.ActionID,
			ActionName:     actionName,
			Username:       p.Username,
			Password:       decPassword,
			RotationReason: p.RotationReason,
		}
		if p.RotatedAt.Valid {
			entry.RotatedAt = timestamppb.New(p.RotatedAt.Time)
		}
		resp.Current = append(resp.Current, entry)
	}

	for _, p := range history {
		actionName := ""
		action, err := h.store.Queries().GetActionByID(ctx, p.ActionID)
		if err == nil {
			actionName = action.Name
		}

		decPassword, err := h.encryptor.Decrypt(p.Password)
		if err != nil {
			return nil, fmt.Errorf("decrypt LPS password: %w", err)
		}
		entry := &pm.LpsPassword{
			DeviceId:       p.DeviceID,
			ActionId:       p.ActionID,
			ActionName:     actionName,
			Username:       p.Username,
			Password:       decPassword,
			RotationReason: p.RotationReason,
		}
		if p.RotatedAt.Valid {
			entry.RotatedAt = timestamppb.New(p.RotatedAt.Time)
		}
		resp.History = append(resp.History, entry)
	}

	return connect.NewResponse(resp), nil
}

// GetDeviceLuksKeys returns current and historical LUKS keys for a device.
func (h *DeviceHandler) GetDeviceLuksKeys(ctx context.Context, req *connect.Request[pm.GetDeviceLuksKeysRequest]) (*connect.Response[pm.GetDeviceLuksKeysResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	current, err := h.store.Queries().GetCurrentLuksKeys(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, fmt.Errorf("get current LUKS keys: %w", err)
	}

	history, err := h.store.Queries().GetLuksKeyHistory(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, fmt.Errorf("get LUKS key history: %w", err)
	}

	resp := &pm.GetDeviceLuksKeysResponse{}

	for _, k := range current {
		actionName := ""
		action, err := h.store.Queries().GetActionByID(ctx, k.ActionID)
		if err == nil {
			actionName = action.Name
		}

		deviceHostname := ""
		device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: k.DeviceID})
		if err == nil {
			deviceHostname = device.Hostname
		}

		decPassphrase, err := h.encryptor.Decrypt(k.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt LUKS passphrase: %w", err)
		}
		entry := &pm.LuksKey{
			DeviceId:       k.DeviceID,
			DeviceHostname: deviceHostname,
			ActionId:       k.ActionID,
			ActionName:     actionName,
			DevicePath:     k.DevicePath,
			Passphrase:     decPassphrase,
			RotationReason: k.RotationReason,
		}
		if k.RotatedAt.Valid {
			entry.RotatedAt = timestamppb.New(k.RotatedAt.Time)
		}
		if k.RevocationStatus != nil {
			entry.RevocationStatus = *k.RevocationStatus
		}
		if k.RevocationError != nil {
			entry.RevocationError = *k.RevocationError
		}
		if k.RevocationAt.Valid {
			entry.RevocationAt = timestamppb.New(k.RevocationAt.Time)
		}
		resp.Current = append(resp.Current, entry)
	}

	for _, k := range history {
		actionName := ""
		action, err := h.store.Queries().GetActionByID(ctx, k.ActionID)
		if err == nil {
			actionName = action.Name
		}

		decPassphrase, err := h.encryptor.Decrypt(k.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt LUKS passphrase: %w", err)
		}
		entry := &pm.LuksKey{
			DeviceId:       k.DeviceID,
			ActionId:       k.ActionID,
			ActionName:     actionName,
			DevicePath:     k.DevicePath,
			Passphrase:     decPassphrase,
			RotationReason: k.RotationReason,
		}
		if k.RotatedAt.Valid {
			entry.RotatedAt = timestamppb.New(k.RotatedAt.Time)
		}
		resp.History = append(resp.History, entry)
	}

	return connect.NewResponse(resp), nil
}

// CreateLuksToken creates a one-time token for setting a user-defined LUKS passphrase.
// Only the device's assigned owner can create a token (admins cannot).
func (h *DeviceHandler) CreateLuksToken(ctx context.Context, req *connect.Request[pm.CreateLuksTokenRequest]) (*connect.Response[pm.CreateLuksTokenResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify device exists and get assigned user
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	// Only the assigned owner can create a LUKS token
	if device.AssignedUserID == nil || *device.AssignedUserID != userCtx.ID {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("only the assigned device owner can create a LUKS passphrase token"))
	}

	// Verify the action exists and is a LUKS action
	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.ActionId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("action not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get action"))
	}
	if pm.ActionType(action.ActionType) != pm.ActionType_ACTION_TYPE_LUKS {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("action is not a LUKS action"))
	}

	// Parse LUKS params to get complexity requirements
	var luksParams pm.LuksParams
	if len(action.Params) > 0 {
		protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(action.Params, &luksParams)
	}

	minLength := luksParams.UserPassphraseMinLength
	if minLength < 16 {
		minLength = 16
	}
	complexity := int32(luksParams.UserPassphraseComplexity)

	// Generate one-time token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate token"))
	}
	token := hex.EncodeToString(tokenBytes)

	// Store in DB
	_, err = h.store.Queries().CreateLuksToken(ctx, db.CreateLuksTokenParams{
		DeviceID:   req.Msg.DeviceId,
		ActionID:   req.Msg.ActionId,
		Token:      token,
		MinLength:  minLength,
		Complexity: complexity,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create token: %w", err))
	}

	uri := fmt.Sprintf("power-manage://luks/set-passphrase?token=%s", token)
	cliCmd := fmt.Sprintf("sudo power-manage-agent luks set-passphrase --token %s", token)

	return connect.NewResponse(&pm.CreateLuksTokenResponse{
		Token:      token,
		Uri:        uri,
		CliCommand: cliCmd,
	}), nil
}

// RevokeLuksDeviceKey sends a revocation request to the agent via pg_notify.
func (h *DeviceHandler) RevokeLuksDeviceKey(ctx context.Context, req *connect.Request[pm.RevokeLuksDeviceKeyRequest]) (*connect.Response[pm.RevokeLuksDeviceKeyResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	// Record dispatched event so the UI can show "dispatched" status
	userCtx, _ := auth.UserFromContext(ctx)
	actorID := ""
	if userCtx != nil {
		actorID = userCtx.ID
	}
	luksStreamID := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   luksStreamID,
		EventType:  "LuksDeviceKeyRevocationDispatched",
		Data: map[string]any{
			"device_id":     req.Msg.DeviceId,
			"action_id":     req.Msg.ActionId,
			"dispatched_at": time.Now().Format(time.RFC3339),
		},
		ActorType: "user",
		ActorID:   actorID,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to record revocation event: %w", err))
	}

	// Send notification to gateway to dispatch to agent
	agentChannel := fmt.Sprintf("agent_%s", req.Msg.DeviceId)
	payload, _ := json.Marshal(map[string]any{
		"type":      "revoke_luks_device_key",
		"action_id": req.Msg.ActionId,
	})
	if err := h.store.Notify(ctx, agentChannel, string(payload)); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to notify agent: %w", err))
	}

	return connect.NewResponse(&pm.RevokeLuksDeviceKeyResponse{}), nil
}
