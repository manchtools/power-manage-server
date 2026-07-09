package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/hibiken/asynq"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/crl"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/inventorysched"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// DeviceHandler handles device management RPCs.
// deviceAssignmentLister reads a device's already-assigned user/group IDs for
// AssignDevice's dedup. It is a seam (defaulting to the store's queries) so a
// test can drive the infra-failure path that must fail closed rather than
// proceed blind on empty dedup sets (WS16 #8).
type deviceAssignmentLister interface {
	ListDeviceAssignedUserIDs(ctx context.Context, deviceID string) ([]string, error)
	ListDeviceAssignedGroupIDs(ctx context.Context, deviceID string) ([]string, error)
}

type DeviceHandler struct {
	taskQueueHolder
	store     *store.Store
	logger    *slog.Logger
	encryptor *crypto.Encryptor
	signer    ca.ActionSigner // signs LUKS device-key revocation dispatches (WS4)
	// crl, when set, receives a deleted device's cert fingerprint so the cert
	// stops working at the gateway. nil disables it (no Valkey / tests).
	crl              *crl.Store
	assignmentLister deviceAssignmentLister // dedup-read seam (WS16 #8); defaults to store queries
	now              func() time.Time       // clock seam; defaults to time.Now, overridden in tests
}

// NewDeviceHandler creates a new device handler.
func NewDeviceHandler(st *store.Store, enc *crypto.Encryptor, logger *slog.Logger, signer ca.ActionSigner) *DeviceHandler {
	return &DeviceHandler{store: st, encryptor: enc, logger: logger, signer: signer, assignmentLister: st.Queries(), now: time.Now}
}

// SetCRLStore wires the certificate revocation list (post-construction).
func (h *DeviceHandler) SetCRLStore(s *crl.Store) { h.crl = s }

// ListDevices returns a paginated list of devices.
// Admins see all devices; regular users see only their assigned devices.
func (h *DeviceHandler) ListDevices(ctx context.Context, req *connect.Request[pm.ListDevicesRequest]) (*connect.Response[pm.ListDevicesResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	q := h.store.Queries()
	filterUID := userFilterID(ctx, "ListDevices")

	// When my_devices_only is set, always filter by the authenticated user's ID
	// regardless of permissions (used by the "My Devices" page).
	if req.Msg.MyDevicesOnly {
		if u, ok := auth.UserFromContext(ctx); ok {
			filterUID = &u.ID
		}
	}

	// Device-group scope (#3): orthogonal to the :assigned OwnerScope above. A
	// scope-limited ListDevices holder sees only devices in their scope groups; a
	// global holder is unrestricted. The same restriction drives the count query
	// so pagination totals stay honest and don't leak the out-of-scope count.
	scopeGroups, scopeRestricted := auth.DeviceScopeListFilter(ctx, "ListDevices")
	scope := store.ScopeGroupFilter{Restricted: scopeRestricted, GroupIDs: scopeGroups}

	var devices []store.Device

	deviceRepo := h.store.Repos().Device
	deviceFilter := store.ListDevicesFilter{
		Limit:      pageSize,
		Offset:     offset,
		OwnerScope: filterUID,
		Scope:      scope,
	}
	switch req.Msg.StatusFilter {
	case pm.DeviceStatus_DEVICE_STATUS_ONLINE:
		devices, err = deviceRepo.ListOnline(ctx, deviceFilter)
	case pm.DeviceStatus_DEVICE_STATUS_OFFLINE:
		devices, err = deviceRepo.ListOffline(ctx, deviceFilter)
	default:
		devices, err = deviceRepo.List(ctx, deviceFilter)
	}
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list devices")
	}

	// Use the matching count query for the active status filter
	var count int64
	switch req.Msg.StatusFilter {
	case pm.DeviceStatus_DEVICE_STATUS_ONLINE:
		count, err = deviceRepo.CountOnline(ctx, filterUID, scope)
	case pm.DeviceStatus_DEVICE_STATUS_OFFLINE:
		count, err = deviceRepo.CountOffline(ctx, filterUID, scope)
	default:
		count, err = deviceRepo.Count(ctx, filterUID, scope)
	}
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count devices")
	}

	nextPageToken := buildNextPageToken(int32(len(devices)), offset, pageSize, count)

	protoDevices := make([]*pm.Device, len(devices))

	// Batch-fetch all assignment IDs for the page to avoid N+1 queries
	deviceIDs := make([]string, len(devices))
	for i, d := range devices {
		deviceIDs[i] = d.ID
	}
	userAssignMap := make(map[string][]string)
	groupAssignMap := make(map[string][]string)
	if len(deviceIDs) > 0 {
		if rows, err := q.ListDeviceAssignedUserIDsBatch(ctx, deviceIDs); err == nil {
			for _, r := range rows {
				userAssignMap[r.DeviceID] = append(userAssignMap[r.DeviceID], r.UserID)
			}
		}
		if rows, err := q.ListDeviceAssignedGroupIDsBatch(ctx, deviceIDs); err == nil {
			for _, r := range rows {
				groupAssignMap[r.DeviceID] = append(groupAssignMap[r.DeviceID], r.GroupID)
			}
		}
	}

	// Freshness fields (spec 22 AC 7) — same batched shape as the
	// assignment maps above, so the page adds one query, not N.
	freshMap := h.inventoryFreshnessMap(ctx, deviceIDs)

	for i, d := range devices {
		protoDevices[i] = h.deviceToProtoWithAssignments(d, userAssignMap[d.ID], groupAssignMap[d.ID])
		fresh, ok := freshMap[d.ID]
		h.applyInventoryFreshness(protoDevices[i], d, fresh, ok)
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "GetDevice", req.Msg.Id); err != nil {
		return nil, err
	}

	device, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{
		ID:         req.Msg.Id,
		OwnerScope: userFilterID(ctx, "GetDevice"),
	})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	return connect.NewResponse(&pm.GetDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// SetDeviceLabel sets a label on a device.
func (h *DeviceHandler) SetDeviceLabel(ctx context.Context, req *connect.Request[pm.SetDeviceLabelRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify device exists
	_, err = h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.Id})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	// Emit DeviceLabelSet event
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceLabelSet),
		Data: payloads.DeviceLabelSet{
			Key:   &req.Msg.Key,
			Value: &req.Msg.Value,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to set label"); err != nil {
		return nil, err
	}

	// Read back updated device
	device, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.Id})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get updated device")
	}

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// RemoveDeviceLabel removes a label from a device.
func (h *DeviceHandler) RemoveDeviceLabel(ctx context.Context, req *connect.Request[pm.RemoveDeviceLabelRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify device exists
	_, err = h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.Id})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	// Emit DeviceLabelRemoved event
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceLabelRemoved),
		Data: payloads.DeviceLabelRemoved{
			Key: &req.Msg.Key,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to remove label"); err != nil {
		return nil, err
	}

	// Read back updated device
	device, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.Id})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get updated device")
	}

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// DeleteDevice deletes a device.
func (h *DeviceHandler) DeleteDevice(ctx context.Context, req *connect.Request[pm.DeleteDeviceRequest]) (*connect.Response[pm.DeleteDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "DeleteDevice", req.Msg.Id); err != nil {
		return nil, err
	}

	// Capture the device's cert fingerprint BEFORE deletion so we can revoke it
	// — otherwise a deleted device's still-valid cert keeps connecting at the
	// gateway until its 1-year expiry. Only loaded when a CRL is configured.
	var revokeFP string
	var revokeUntil time.Time
	if h.crl != nil {
		dev, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.Id})
		if err != nil {
			// Best-effort: don't fail the delete, but log — a swallowed lookup
			// error would leave the deleted device's cert unrevoked silently.
			h.logger.Warn("failed to load device for CRL revocation; its cert may stay valid until expiry", "device_id", req.Msg.Id, "error", err)
		} else if dev.CertFingerprint != nil && dev.CertNotAfter != nil {
			revokeFP = *dev.CertFingerprint
			revokeUntil = *dev.CertNotAfter
		}
	}

	// Emit DeviceDeleted event
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete device"); err != nil {
		return nil, err
	}

	// Revoke the deleted device's cert (best-effort — a CRL failure must not
	// undo the deletion that already committed).
	if revokeFP != "" {
		if err := h.crl.Revoke(ctx, revokeFP, revokeUntil); err != nil {
			h.logger.Error("failed to revoke deleted device cert in CRL", "device_id", req.Msg.Id, "error", err)
		}
	}

	// Search-index removal is handled by api.SearchListener (post-commit
	// dispatch on DeviceDeleted) — handler-side enqueue removed in N005.

	return connect.NewResponse(&pm.DeleteDeviceResponse{}), nil
}

// AssignDevice assigns a device to one or more users and/or user groups.
func (h *DeviceHandler) AssignDevice(ctx context.Context, req *connect.Request[pm.AssignDeviceRequest]) (*connect.Response[pm.AssignDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Collect user IDs from single + repeated fields
	userIDs := append([]string{}, req.Msg.UserIds...)
	if req.Msg.UserId != "" {
		userIDs = append(userIDs, req.Msg.UserId)
	}

	// Collect group IDs from single + repeated fields
	groupIDs := append([]string{}, req.Msg.GroupIds...)
	if req.Msg.GroupId != "" {
		groupIDs = append(groupIDs, req.Msg.GroupId)
	}

	if len(userIDs) == 0 && len(groupIDs) == 0 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one user or group must be specified")
	}

	q := h.store.Queries()

	// Verify device exists
	_, err = h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	// Build sets of already-assigned user/group IDs to prevent duplicate
	// events. WS16 #8: a DB error here must abort — proceeding with empty
	// dedup sets on infra failure re-emits duplicate DeviceAssigned events.
	existingUserIDs, err := h.assignmentLister.ListDeviceAssignedUserIDs(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list device assignments")
	}
	existingUserSet := make(map[string]bool, len(existingUserIDs))
	for _, id := range existingUserIDs {
		existingUserSet[id] = true
	}
	existingGroupIDs, err := h.assignmentLister.ListDeviceAssignedGroupIDs(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list device assignments")
	}
	existingGroupSet := make(map[string]bool, len(existingGroupIDs))
	for _, id := range existingGroupIDs {
		existingGroupSet[id] = true
	}

	for _, userID := range userIDs {
		if existingUserSet[userID] {
			continue // already assigned, skip
		}

		// Verify user exists
		_, err = q.GetUserByID(ctx, userID)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
		}

		uid := userID
		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "device",
			StreamID:   req.Msg.DeviceId,
			EventType:  string(eventtypes.DeviceAssigned),
			Data: payloads.DeviceUserAssignment{
				UserID: &uid,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to assign device"); err != nil {
			return nil, err
		}
	}

	for _, groupID := range groupIDs {
		if existingGroupSet[groupID] {
			continue // already assigned, skip
		}

		// Verify user group exists
		_, err = q.GetUserGroupByID(ctx, groupID)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrUserGroupNotFound, connect.CodeNotFound, "user group not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user group")
		}

		gid := groupID
		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "device",
			StreamID:   req.Msg.DeviceId,
			EventType:  string(eventtypes.DeviceGroupAssigned),
			Data: payloads.DeviceGroupAssignment{
				GroupID: &gid,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to assign device to group"); err != nil {
			return nil, err
		}
	}

	// Read back updated device
	device, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get updated device")
	}

	return connect.NewResponse(&pm.AssignDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// usernameSanitizeRe matches characters not allowed in Linux usernames.
var usernameSanitizeRe = regexp.MustCompile(`[^a-z0-9_.\-]`)

// deriveLinuxUsername derives a Linux username from a PM user's fields.
// Priority: preferred_username > email prefix > email as-is.
// Returns empty string if no valid username can be derived.
func deriveLinuxUsername(email, preferredUsername string) string {
	var username string
	switch {
	case preferredUsername != "":
		username = preferredUsername
	case strings.Contains(email, "@"):
		username = email[:strings.Index(email, "@")]
	default:
		username = email
	}
	username = strings.ToLower(username)
	username = usernameSanitizeRe.ReplaceAllString(username, "_")
	if len(username) > 32 {
		username = username[:32]
	}
	return username
}

// UnassignDevice removes a user or user group assignment from a device.
func (h *DeviceHandler) UnassignDevice(ctx context.Context, req *connect.Request[pm.UnassignDeviceRequest]) (*connect.Response[pm.UnassignDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Exactly one of user_id or group_id must be set
	if (req.Msg.UserId == "") == (req.Msg.GroupId == "") {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "exactly one of user_id or group_id must be set")
	}

	// Verify device exists
	_, err = h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	if req.Msg.UserId != "" {
		// Emit DeviceUnassigned event
		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "device",
			StreamID:   req.Msg.DeviceId,
			EventType:  string(eventtypes.DeviceUnassigned),
			Data: payloads.DeviceUserAssignment{
				UserID: &req.Msg.UserId,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to unassign device"); err != nil {
			return nil, err
		}
	} else {
		// Emit DeviceGroupUnassigned event
		if err := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "device",
			StreamID:   req.Msg.DeviceId,
			EventType:  string(eventtypes.DeviceGroupUnassigned),
			Data: payloads.DeviceGroupAssignment{
				GroupID: &req.Msg.GroupId,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}, "failed to unassign device from group"); err != nil {
			return nil, err
		}
	}

	// Read back updated device
	device, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get updated device")
	}

	return connect.NewResponse(&pm.UnassignDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// SetDeviceSyncInterval sets the sync interval for a device.
func (h *DeviceHandler) SetDeviceSyncInterval(ctx context.Context, req *connect.Request[pm.SetDeviceSyncIntervalRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "SetDeviceSyncInterval", req.Msg.Id); err != nil {
		return nil, err
	}

	// Verify device exists
	_, err = h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.Id})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	// Emit DeviceSyncIntervalSet event
	syncInterval := req.Msg.SyncIntervalMinutes
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceSyncIntervalSet),
		Data: payloads.DeviceSyncIntervalSet{
			SyncIntervalMinutes: &syncInterval,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to set sync interval"); err != nil {
		return nil, err
	}

	// Read back updated device
	device, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.Id})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get updated device")
	}

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// SetDeviceInventoryInterval sets the inventory-collection interval
// override for a device (spec 22 AC 1). 0 = inherit (group minimum,
// then the 1440-minute server default).
func (h *DeviceHandler) SetDeviceInventoryInterval(ctx context.Context, req *connect.Request[pm.SetDeviceInventoryIntervalRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "SetDeviceInventoryInterval", req.Msg.Id); err != nil {
		return nil, err
	}

	// Bounds at the handler in addition to the validate tag (spec 22
	// AC 4: boundary AND handler). Non-zero must land in [120, 10080]
	// minutes (2 h – 7 d); the floor protects devices from osquery
	// hammering.
	if m := req.Msg.InventoryIntervalMinutes; m != 0 && (m < 120 || m > 10080) {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inventory interval out of range")
	}

	// Verify device exists
	_, err = h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.Id})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	interval := req.Msg.InventoryIntervalMinutes
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.DeviceInventoryIntervalSet),
		Data: payloads.DeviceInventoryIntervalSet{
			InventoryIntervalMinutes: &interval,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to set inventory interval"); err != nil {
		return nil, err
	}

	// Read back updated device
	device, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.Id})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get updated device")
	}

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// inventoryFreshness is one device's spec-22 freshness pair as loaded
// by inventoryFreshnessMap.
type inventoryFreshness struct {
	lastInventoryAt *time.Time
	intervalMinutes int32 // resolved: device override > group min > default
}

// inventoryFreshnessMap loads inventory freshness (MAX collected_at +
// resolved interval) for the given devices in one round trip — the
// list path stays free of per-row N+1. A query error degrades to an
// empty map (freshness fields stay unset on the response) with a
// warning: a device listing must not fail because freshness was
// momentarily unavailable.
func (h *DeviceHandler) inventoryFreshnessMap(ctx context.Context, deviceIDs []string) map[string]inventoryFreshness {
	m := make(map[string]inventoryFreshness, len(deviceIDs))
	if len(deviceIDs) == 0 {
		return m
	}
	rows, err := h.store.Queries().ListDeviceInventoryFreshnessBatch(ctx, db.ListDeviceInventoryFreshnessBatchParams{
		DefaultIntervalMinutes: inventorysched.DefaultIntervalMinutes,
		DeviceIds:              deviceIDs,
	})
	if err != nil {
		h.logger.Warn("inventory freshness lookup failed; devices reported without freshness fields",
			"devices", len(deviceIDs), "error", err)
		return m
	}
	for _, r := range rows {
		f := inventoryFreshness{intervalMinutes: r.ResolvedIntervalMinutes}
		if r.LastInventoryAt.Valid {
			t := r.LastInventoryAt.Time
			f.lastInventoryAt = &t
		}
		m[r.DeviceID] = f
	}
	return m
}

// applyInventoryFreshness populates the spec-22 freshness fields on a
// proto device: last_inventory_at and the policy-derived
// inventory_overdue (AC 7) — valid even while the device is offline.
func (h *DeviceHandler) applyInventoryFreshness(pd *pm.Device, d store.Device, f inventoryFreshness, ok bool) {
	if !ok {
		return
	}
	if f.lastInventoryAt != nil {
		pd.LastInventoryAt = timestamppb.New(*f.lastInventoryAt)
	}
	pd.InventoryOverdue = inventorysched.Overdue(f.lastInventoryAt, d.RegisteredAt, f.intervalMinutes, h.now())
}

// deviceToProtoCtx converts a database device projection to a protobuf device,
// populating assigned user/group IDs from junction tables.
func (h *DeviceHandler) deviceToProtoCtx(ctx context.Context, d store.Device) *pm.Device {
	q := h.store.Queries()
	var userIDs, groupIDs []string
	if rows, err := q.ListDeviceAssignedUserIDs(ctx, d.ID); err == nil {
		userIDs = rows
	}
	if rows, err := q.ListDeviceAssignedGroupIDs(ctx, d.ID); err == nil {
		groupIDs = rows
	}
	pd := h.deviceToProtoWithAssignments(d, userIDs, groupIDs)
	fresh, ok := h.inventoryFreshnessMap(ctx, []string{d.ID})[d.ID]
	h.applyInventoryFreshness(pd, d, fresh, ok)
	return pd
}

// deviceToProtoWithAssignments converts a database device projection to a protobuf
// device using pre-fetched assignment data. Used by list endpoints with batch queries.
func (h *DeviceHandler) deviceToProtoWithAssignments(d store.Device, assignedUserIDs, assignedGroupIDs []string) *pm.Device {
	device := &pm.Device{
		Id:                       d.ID,
		Hostname:                 d.Hostname,
		AgentVersion:             d.AgentVersion,
		Labels:                   make(map[string]string),
		SyncIntervalMinutes:      d.SyncIntervalMinutes,
		InventoryIntervalMinutes: d.InventoryIntervalMinutes,
		AssignedUserIds:          assignedUserIDs,
		AssignedGroupIds:         assignedGroupIDs,
	}

	// Determine status based on last_seen
	if d.LastSeenAt != nil {
		device.LastSeenAt = timestamppb.New(*d.LastSeenAt)
		if time.Since(*d.LastSeenAt) < 5*time.Minute {
			device.Status = pm.DeviceStatus_DEVICE_STATUS_ONLINE
		} else {
			device.Status = pm.DeviceStatus_DEVICE_STATUS_OFFLINE
		}
	} else {
		device.Status = pm.DeviceStatus_DEVICE_STATUS_OFFLINE
	}

	if d.RegisteredAt != nil {
		device.RegisteredAt = timestamppb.New(*d.RegisteredAt)
	}

	if d.CertNotAfter != nil {
		device.CertExpiresAt = timestamppb.New(*d.CertNotAfter)
	}

	if len(d.Labels) > 0 {
		device.Labels = d.Labels
	}

	// Compliance fields
	device.ComplianceStatus = pm.ComplianceStatus(d.ComplianceStatus)
	device.ComplianceTotal = d.ComplianceTotal
	device.CompliancePassing = d.CompliancePassing
	if d.ComplianceCheckedAt != nil {
		device.ComplianceCheckedAt = timestamppb.New(*d.ComplianceCheckedAt)
	}

	return device
}

// distinctIDs collects distinct non-empty values from id-typed slices,
// preserving first-seen ordering. Used by the response loops below
// to feed bulk-load queries (GetActionNamesByIDs / GetDeviceHostnamesByIDs)
// that audit F008 introduced — the previous shape made one round-trip
// per row, which on a device with 50 LUKS keys was ~100 sequential
// queries per RPC.
func distinctIDs(idSlices ...[]string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)
	for _, slice := range idSlices {
		for _, id := range slice {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// loadActionNamesByIDs bulk-loads action_id → name. Failed lookups
// (typically: action deleted between when the row was written and
// when the RPC is served) drop out of the map; callers default to
// empty string. Audit F008.
func (h *DeviceHandler) loadActionNamesByIDs(ctx context.Context, ids []string) map[string]string {
	if len(ids) == 0 {
		return nil
	}
	rows, err := h.store.Repos().Action.NamesByIDs(ctx, ids)
	if err != nil {
		logEnrichmentErr("GetActionNamesByIDs", "action_id_count", fmt.Sprint(len(ids)), err)
		return nil
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.ID] = r.Name
	}
	return out
}

// loadDeviceHostnamesByIDs bulk-loads device_id → hostname. Audit F008.
func (h *DeviceHandler) loadDeviceHostnamesByIDs(ctx context.Context, ids []string) map[string]string {
	if len(ids) == 0 {
		return nil
	}
	rows, err := h.store.Repos().Device.HostnamesByIDs(ctx, ids)
	if err != nil {
		logEnrichmentErr("GetDeviceHostnamesByIDs", "device_id_count", fmt.Sprint(len(ids)), err)
		return nil
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.ID] = r.Hostname
	}
	return out
}

// auditSecretRead appends a secret-read audit event (spec 24 / #494).
// Best-effort by design: on the success path the decrypted material is
// already committed to the response, and on the denied path the
// caller-visible error is already fixed — an append failure must not alter
// either, so it is logged loudly instead (AUDIT GAP, mirroring the #496
// dispatch audits).
func (h *DeviceHandler) auditSecretRead(ctx context.Context, deviceID string, eventType eventtypes.EventType, payload any) {
	userCtx, aerr := requireAuth(ctx)
	if aerr != nil {
		h.logger.Error("AUDIT GAP: could not resolve actor for secret-read audit event",
			"event_type", string(eventType), "device_id", deviceID, "error", aerr)
		return
	}
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  string(eventType),
		Data:       payload,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}); err != nil {
		h.logger.Error("AUDIT GAP: failed to append secret-read audit event",
			"event_type", string(eventType), "device_id", deviceID, "error", err)
	}
}

// GetDeviceLpsPasswords returns current and historical LPS passwords for a device.
func (h *DeviceHandler) GetDeviceLpsPasswords(ctx context.Context, req *connect.Request[pm.GetDeviceLpsPasswordsRequest]) (*connect.Response[pm.GetDeviceLpsPasswordsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Spec 24: the audit trail attributes the read to a real device — an
	// absent device is a NotFound denial (audited below), not the empty
	// success it used to be.
	if _, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId}); err != nil {
		if store.IsNotFound(err) {
			h.auditSecretRead(ctx, req.Msg.DeviceId, eventtypes.LpsPasswordsViewDenied,
				payloads.LpsPasswordsViewDenied{DeviceID: req.Msg.DeviceId, Reason: "device not found"})
		}
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	// Get current passwords
	current, err := h.store.Repos().Lps.ListCurrent(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to load current LPS passwords")
	}

	// Get password history
	history, err := h.store.Repos().Lps.ListHistory(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to load LPS password history")
	}

	// Bulk-load enrichment names (audit F008): one round-trip each
	// instead of one per row inside the loops below. Both loops feed
	// the same actionIDs set; only `current` rows have a per-row
	// hostname.
	actionIDsCurrent := make([]string, len(current))
	deviceIDsCurrent := make([]string, len(current))
	for i, p := range current {
		actionIDsCurrent[i] = p.ActionID
		deviceIDsCurrent[i] = p.DeviceID
	}
	actionIDsHistory := make([]string, len(history))
	for i, p := range history {
		actionIDsHistory[i] = p.ActionID
	}
	actionNames := h.loadActionNamesByIDs(ctx, distinctIDs(actionIDsCurrent, actionIDsHistory))
	deviceHostnames := h.loadDeviceHostnamesByIDs(ctx, distinctIDs(deviceIDsCurrent))

	// Convert to proto
	resp := &pm.GetDeviceLpsPasswordsResponse{}

	for _, p := range current {
		decPassword, err := h.encryptor.DecryptWithContext(p.Password, crypto.SecretAAD(p.DeviceID, p.ActionID, "lps"))
		if err != nil {
			// Decrypt failure on stored material is alarming —
			// possible key-rotation drift, corrupted ciphertext,
			// or HSM/KMS issue. Log device + action context so
			// operators can triage without re-running the RPC.
			h.logger.Error("failed to decrypt LPS password (current)",
				"device_id", p.DeviceID, "action_id", p.ActionID, "error", err)
			h.auditSecretRead(ctx, req.Msg.DeviceId, eventtypes.LpsPasswordsViewDenied,
				payloads.LpsPasswordsViewDenied{DeviceID: req.Msg.DeviceId, Reason: "decrypt failure on stored material"})
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to decrypt LPS password")
		}
		entry := &pm.LpsPassword{
			DeviceId:       p.DeviceID,
			DeviceHostname: deviceHostnames[p.DeviceID],
			ActionId:       p.ActionID,
			ActionName:     actionNames[p.ActionID],
			Username:       p.Username,
			Password:       decPassword,
			RotationReason: rotationReasonFromString(p.RotationReason),
		}
		entry.RotatedAt = timestamppb.New(p.RotatedAt)
		resp.Current = append(resp.Current, entry)
	}

	for _, p := range history {
		decPassword, err := h.encryptor.DecryptWithContext(p.Password, crypto.SecretAAD(p.DeviceID, p.ActionID, "lps"))
		if err != nil {
			h.logger.Error("failed to decrypt LPS password (history)",
				"device_id", p.DeviceID, "action_id", p.ActionID, "error", err)
			h.auditSecretRead(ctx, req.Msg.DeviceId, eventtypes.LpsPasswordsViewDenied,
				payloads.LpsPasswordsViewDenied{DeviceID: req.Msg.DeviceId, Reason: "decrypt failure on stored material"})
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to decrypt LPS password")
		}
		entry := &pm.LpsPassword{
			DeviceId:       p.DeviceID,
			ActionId:       p.ActionID,
			ActionName:     actionNames[p.ActionID],
			Username:       p.Username,
			Password:       decPassword,
			RotationReason: rotationReasonFromString(p.RotationReason),
		}
		entry.RotatedAt = timestamppb.New(p.RotatedAt)
		resp.History = append(resp.History, entry)
	}

	// Spec 24 AC 1/5: exactly one view event per successful call, listing
	// the returned entries by identifier — appended before the response,
	// best-effort (the material above is already decrypted for return).
	viewedEntries := make([]payloads.LpsViewedEntry, 0, len(current)+len(history))
	for _, p := range current {
		viewedEntries = append(viewedEntries, payloads.LpsViewedEntry{RotationID: p.ID, Username: p.Username, Current: true})
	}
	for _, p := range history {
		viewedEntries = append(viewedEntries, payloads.LpsViewedEntry{RotationID: p.ID, Username: p.Username})
	}
	h.auditSecretRead(ctx, req.Msg.DeviceId, eventtypes.LpsPasswordsViewed,
		payloads.LpsPasswordsViewed{DeviceID: req.Msg.DeviceId, Entries: viewedEntries})

	return connect.NewResponse(resp), nil
}

// GetDeviceLuksKeys returns current and historical LUKS keys for a device.
func (h *DeviceHandler) GetDeviceLuksKeys(ctx context.Context, req *connect.Request[pm.GetDeviceLuksKeysRequest]) (*connect.Response[pm.GetDeviceLuksKeysResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Spec 24: absent device → audited NotFound denial (see the LPS
	// counterpart above).
	if _, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId}); err != nil {
		if store.IsNotFound(err) {
			h.auditSecretRead(ctx, req.Msg.DeviceId, eventtypes.LuksKeysViewDenied,
				payloads.LuksKeysViewDenied{DeviceID: req.Msg.DeviceId, Reason: "device not found"})
		}
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	current, err := h.store.Repos().Luks.ListCurrent(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to load current LUKS keys")
	}

	history, err := h.store.Repos().Luks.ListHistory(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to load LUKS key history")
	}

	// Bulk-load enrichment names (audit F008): one round-trip each
	// instead of one per row.
	actionIDsCurrent := make([]string, len(current))
	deviceIDsCurrent := make([]string, len(current))
	for i, k := range current {
		actionIDsCurrent[i] = k.ActionID
		deviceIDsCurrent[i] = k.DeviceID
	}
	actionIDsHistory := make([]string, len(history))
	for i, k := range history {
		actionIDsHistory[i] = k.ActionID
	}
	actionNames := h.loadActionNamesByIDs(ctx, distinctIDs(actionIDsCurrent, actionIDsHistory))
	deviceHostnames := h.loadDeviceHostnamesByIDs(ctx, distinctIDs(deviceIDsCurrent))

	resp := &pm.GetDeviceLuksKeysResponse{}

	for _, k := range current {
		decPassphrase, err := h.encryptor.DecryptWithContext(k.Passphrase, crypto.SecretAAD(k.DeviceID, k.ActionID, "luks"))
		if err != nil {
			h.logger.Error("failed to decrypt LUKS passphrase (current)",
				"device_id", k.DeviceID, "action_id", k.ActionID, "device_path", k.DevicePath, "error", err)
			h.auditSecretRead(ctx, req.Msg.DeviceId, eventtypes.LuksKeysViewDenied,
				payloads.LuksKeysViewDenied{DeviceID: req.Msg.DeviceId, Reason: "decrypt failure on stored material"})
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to decrypt LUKS passphrase")
		}
		entry := &pm.LuksKey{
			DeviceId:       k.DeviceID,
			DeviceHostname: deviceHostnames[k.DeviceID],
			ActionId:       k.ActionID,
			ActionName:     actionNames[k.ActionID],
			DevicePath:     k.DevicePath,
			Passphrase:     decPassphrase,
			RotationReason: rotationReasonFromString(k.RotationReason),
		}
		entry.RotatedAt = timestamppb.New(k.RotatedAt)
		if k.RevocationStatus != nil {
			entry.RevocationStatus = luksRevocationStatusFromString(*k.RevocationStatus)
		}
		if k.RevocationError != nil {
			entry.RevocationError = *k.RevocationError
		}
		if k.RevocationAt != nil {
			entry.RevocationAt = timestamppb.New(*k.RevocationAt)
		}
		resp.Current = append(resp.Current, entry)
	}

	for _, k := range history {
		decPassphrase, err := h.encryptor.DecryptWithContext(k.Passphrase, crypto.SecretAAD(k.DeviceID, k.ActionID, "luks"))
		if err != nil {
			h.logger.Error("failed to decrypt LUKS passphrase (history)",
				"device_id", k.DeviceID, "action_id", k.ActionID, "device_path", k.DevicePath, "error", err)
			h.auditSecretRead(ctx, req.Msg.DeviceId, eventtypes.LuksKeysViewDenied,
				payloads.LuksKeysViewDenied{DeviceID: req.Msg.DeviceId, Reason: "decrypt failure on stored material"})
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to decrypt LUKS passphrase")
		}
		entry := &pm.LuksKey{
			DeviceId:       k.DeviceID,
			ActionId:       k.ActionID,
			ActionName:     actionNames[k.ActionID],
			DevicePath:     k.DevicePath,
			Passphrase:     decPassphrase,
			RotationReason: rotationReasonFromString(k.RotationReason),
		}
		entry.RotatedAt = timestamppb.New(k.RotatedAt)
		resp.History = append(resp.History, entry)
	}

	// Spec 24 AC 2/5: exactly one view event per successful call, listing
	// the returned key identifiers — best-effort, before the response.
	viewedEntries := make([]payloads.LuksViewedEntry, 0, len(current)+len(history))
	for _, k := range current {
		viewedEntries = append(viewedEntries, payloads.LuksViewedEntry{RotationID: k.ID, DevicePath: k.DevicePath, Current: true})
	}
	for _, k := range history {
		viewedEntries = append(viewedEntries, payloads.LuksViewedEntry{RotationID: k.ID, DevicePath: k.DevicePath})
	}
	h.auditSecretRead(ctx, req.Msg.DeviceId, eventtypes.LuksKeysViewed,
		payloads.LuksKeysViewed{DeviceID: req.Msg.DeviceId, Entries: viewedEntries})

	return connect.NewResponse(resp), nil
}

// hashLuksToken returns the hex SHA-256 of a one-time LUKS token — the
// form stored at rest and matched on validation (WS10 #3), so the
// plaintext token never persists. Single source for the create and
// validate (ProxyValidateLuksToken) sides.
func hashLuksToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateLuksToken creates a one-time token for setting a user-defined LUKS passphrase.
// Only the device's assigned owner can create a token (admins cannot).
func (h *DeviceHandler) CreateLuksToken(ctx context.Context, req *connect.Request[pm.CreateLuksTokenRequest]) (*connect.Response[pm.CreateLuksTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify device exists
	_, err = h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	// Only an assigned owner can create a LUKS token
	assignedUserIDs, err := h.store.Repos().Assignment.ListAssignedUserIDsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check device assignments")
	}
	isAssigned := false
	for _, uid := range assignedUserIDs {
		if uid == userCtx.ID {
			isAssigned = true
			break
		}
	}
	if !isAssigned {
		return nil, apiErrorCtx(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "only the assigned device owner can create a LUKS passphrase token")
	}

	// Verify the action exists and is a LUKS action
	action, err := h.store.Repos().Action.Get(ctx, req.Msg.ActionId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrActionNotFound, "action not found")
	}
	if pm.ActionType(action.ActionType) != pm.ActionType_ACTION_TYPE_ENCRYPTION {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "action is not an encryption action")
	}

	// Parse LUKS params to get complexity requirements. WS16 #10: a decode
	// failure must fail closed — silently falling back to the floor policy
	// (min 16, complexity 0) would weaken a security-gating token whenever the
	// stored params are corrupt.
	var luksParams pm.EncryptionParams
	if len(action.Params) > 0 {
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(action.Params, &luksParams); err != nil {
			h.logger.Error("encryption action params decode failed",
				"action_id", req.Msg.ActionId, "error", err)
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "encryption action params are corrupt")
		}
	}

	minLength := luksParams.UserPassphraseMinLength
	if minLength < 16 {
		minLength = 16
	}
	complexity := int32(luksParams.UserPassphraseComplexity)

	// Generate one-time token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate token")
	}
	token := hex.EncodeToString(tokenBytes)

	// WS10 #3: store only the SHA-256 hash of the token, never the
	// plaintext (consistent with registration/terminal tokens). The
	// plaintext is returned to the caller exactly once below; an attacker
	// who reads the DB cannot replay it to set a LUKS passphrase.
	_, err = h.store.Repos().Luks.CreateToken(ctx, store.CreateLuksTokenParams{DeviceID: req.Msg.DeviceId, ActionID: req.Msg.ActionId, Token: hashLuksToken(token), MinLength: minLength, Complexity: complexity})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create token")
	}

	uri := fmt.Sprintf("power-manage://luks/set-passphrase?token=%s", token)
	cliCmd := fmt.Sprintf("sudo power-manage-agent luks set-passphrase --token %s", token)

	// Audit (#496): record who issued the LUKS key-storage token for which
	// device+action. NO token material — not even its hash — is recorded; the
	// audit interest is the grant, not the secret. Best-effort: the token is
	// already persisted, so a failed append must not undo it.
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   req.Msg.DeviceId,
		EventType:  string(eventtypes.LuksTokenCreated),
		Data: payloads.LuksTokenCreated{
			DeviceID: req.Msg.DeviceId,
			ActionID: req.Msg.ActionId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}); err != nil {
		h.logger.Error("AUDIT GAP: failed to append LuksTokenCreated; token already issued",
			"device_id", req.Msg.DeviceId, "action_id", req.Msg.ActionId, "error", err)
	}

	return connect.NewResponse(&pm.CreateLuksTokenResponse{
		Token:      token,
		Uri:        uri,
		CliCommand: cliCmd,
	}), nil
}

// RevokeLuksDeviceKey sends a revocation request to the agent via the task queue.
func (h *DeviceHandler) RevokeLuksDeviceKey(ctx context.Context, req *connect.Request[pm.RevokeLuksDeviceKeyRequest]) (*connect.Response[pm.RevokeLuksDeviceKeyResponse], error) {
	// Explicit auth check: a missing user in ctx is a configuration
	// bug (interceptor not wired), not a legitimate anonymous call.
	// Surfacing it as CodeUnauthenticated rather than silently
	// recording actor_id="" keeps the "every event has a valid
	// actor" invariant intact.
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Verify device exists
	_, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	// Fail fast when no task queue is configured. Without this the
	// handler used to append LuksDeviceKeyRevocationDispatched and
	// return success — the UI would show "dispatched" but the agent
	// would never get the revocation task, leaving the LUKS key
	// live when the operator thinks they've revoked it.
	if h.aqClient == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeFailedPrecondition, "LUKS key revocation unavailable: task queue not configured")
	}

	// Three-phase audit model:
	//
	//   Phase 1: append LuksDeviceKeyRevocationRequested (durable
	//            operator-intent record) BEFORE touching the queue.
	//   Phase 2: enqueue to Asynq.
	//   Phase 3: append Dispatched on enqueue success, or Failed on
	//            enqueue error.
	//
	// All three events share the SAME stream_id so the event stream
	// tells a single correlated story per revocation attempt:
	// Requested → (Dispatched|Failed) → Revoked|Failed. Using fresh
	// ULIDs per event would split the history and force downstream
	// readers to correlate via (device_id, action_id) instead — the
	// projector already does that, but the audit log loses the
	// "these three rows are one revocation attempt" invariant.
	luksStreamID := newULID()
	reqAt := h.now().UTC().Format(time.RFC3339Nano)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   luksStreamID,
		EventType:  string(eventtypes.LuksDeviceKeyRevocationRequested),
		Data: payloads.LuksDeviceKeyRevocationRequested{
			DeviceID:    req.Msg.DeviceId,
			ActionID:    req.Msg.ActionId,
			RequestedAt: reqAt,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to record revocation request")
	}

	// Phase 2: sign + enqueue. The agent verifies the CA signature binding
	// action_id before performing the destructive, irreversible slot-7 wipe
	// (WS4), so a compromised gateway cannot forge or replay a revocation. A
	// signing failure transitions the projection requested → failed.
	revokePayload := taskqueue.RevokeLuksDeviceKeyPayload{ActionID: req.Msg.ActionId}
	if signErr := signRevokeLuksDeviceKey(h.signer, &revokePayload); signErr != nil {
		h.logger.Error("luks revocation signing failed; emitting LuksDeviceKeyRevocationFailed",
			"device_id", req.Msg.DeviceId, "action_id", req.Msg.ActionId, "error", signErr)
		if failErr := h.store.AppendEvent(ctx, store.Event{
			StreamType: "luks_key",
			StreamID:   luksStreamID,
			EventType:  string(eventtypes.LuksDeviceKeyRevocationFailed),
			Data: payloads.LuksDeviceKeyRevocationFailed{
				DeviceID: req.Msg.DeviceId,
				ActionID: req.Msg.ActionId,
				Error:    "failed to sign revocation dispatch",
				FailedAt: h.now().UTC().Format(time.RFC3339Nano),
			},
			ActorType: "system",
			ActorID:   "system",
		}); failErr != nil {
			h.logger.Error("failed to append LuksDeviceKeyRevocationFailed; projection stays at 'requested'",
				"device_id", req.Msg.DeviceId, "action_id", req.Msg.ActionId, "error", failErr)
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to sign LUKS revocation dispatch")
	}
	if enqErr := h.aqClient.EnqueueToDevice(req.Msg.DeviceId, taskqueue.TypeRevokeLuksDeviceKey, revokePayload, asynq.MaxRetry(5)); enqErr != nil {
		// Phase 3b: append Failed so the projection transitions
		// requested → failed. Best-effort; if this append also
		// fails the projection stays at 'requested', which is
		// still a truthful audit state (the revocation did NOT
		// happen).
		h.logger.Error("luks revocation enqueue failed; emitting LuksDeviceKeyRevocationFailed",
			"device_id", req.Msg.DeviceId, "action_id", req.Msg.ActionId, "error", enqErr)
		if failErr := h.store.AppendEvent(ctx, store.Event{
			StreamType: "luks_key",
			StreamID:   luksStreamID,
			EventType:  string(eventtypes.LuksDeviceKeyRevocationFailed),
			Data: payloads.LuksDeviceKeyRevocationFailed{
				DeviceID: req.Msg.DeviceId,
				ActionID: req.Msg.ActionId,
				Error:    fmt.Sprintf("dispatch enqueue failed: %v", enqErr),
				FailedAt: h.now().UTC().Format(time.RFC3339Nano),
			},
			ActorType: "system",
			ActorID:   "system",
		}); failErr != nil {
			h.logger.Error("failed to append LuksDeviceKeyRevocationFailed; projection stays at 'requested'",
				"device_id", req.Msg.DeviceId, "action_id", req.Msg.ActionId, "error", failErr)
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to dispatch LUKS revocation")
	}

	// Phase 3a: append Dispatched. Task is already in the queue; a
	// failure here leaves the projection at 'requested' while the
	// agent proceeds with revocation. Log loudly and return error
	// so the caller knows the UI-visible state will lag. The agent
	// will still emit LuksDeviceKeyRevoked on success, which fully
	// transitions the row — so the lag is bounded, not permanent.
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   luksStreamID,
		EventType:  string(eventtypes.LuksDeviceKeyRevocationDispatched),
		Data: payloads.LuksDeviceKeyRevocationDispatched{
			DeviceID:     req.Msg.DeviceId,
			ActionID:     req.Msg.ActionId,
			DispatchedAt: h.now().UTC().Format(time.RFC3339Nano),
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}); err != nil {
		h.logger.Error("luks revocation dispatched but Dispatched event append failed; projection stays at 'requested' until agent emits LuksDeviceKeyRevoked",
			"device_id", req.Msg.DeviceId, "action_id", req.Msg.ActionId, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to record revocation dispatched event")
	}
	h.logger.Debug("luks revocation full flow appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "luks_key",
		"stream_id", luksStreamID,
	)

	return connect.NewResponse(&pm.RevokeLuksDeviceKeyResponse{}), nil
}

// ListDeviceAssignees returns the users and user groups assigned to a device.
func (h *DeviceHandler) ListDeviceAssignees(ctx context.Context, req *connect.Request[pm.ListDeviceAssigneesRequest]) (*connect.Response[pm.ListDeviceAssigneesResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	q := h.store.Queries()

	// Verify device exists
	_, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	var assignees []*pm.DeviceAssignee

	// Get assigned users
	users, err := q.ListDeviceAssignedUsers(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list assigned users")
	}
	for _, u := range users {
		assignees = append(assignees, &pm.DeviceAssignee{
			Id:   u.UserID,
			Type: pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER,
			Name: u.UserEmail,
		})
	}

	// Get assigned groups
	groups, err := q.ListDeviceAssignedGroups(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list assigned groups")
	}
	for _, g := range groups {
		assignees = append(assignees, &pm.DeviceAssignee{
			Id:   g.GroupID,
			Type: pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER_GROUP,
			Name: g.GroupName,
		})
	}

	return connect.NewResponse(&pm.ListDeviceAssigneesResponse{
		Assignees: assignees,
	}), nil
}
