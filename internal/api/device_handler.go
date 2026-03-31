package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// DeviceHandler handles device management RPCs.
type DeviceHandler struct {
	store     *store.Store
	logger    *slog.Logger
	encryptor *crypto.Encryptor
	aqClient  *taskqueue.Client
	searchIdx *search.Index
}

// NewDeviceHandler creates a new device handler.
func NewDeviceHandler(st *store.Store, enc *crypto.Encryptor, logger *slog.Logger) *DeviceHandler {
	return &DeviceHandler{store: st, encryptor: enc, logger: logger}
}

// SetTaskQueueClient sets the Asynq client for dual-write dispatch.
func (h *DeviceHandler) SetTaskQueueClient(c *taskqueue.Client) {
	h.aqClient = c
}

// SetSearchIndex sets the search index for enqueuing index updates.
func (h *DeviceHandler) SetSearchIndex(idx *search.Index) {
	h.searchIdx = idx
}

// enqueueDeviceReindex enqueues a search index update for a device.
func (h *DeviceHandler) enqueueDeviceReindex(ctx context.Context, d db.DevicesProjection) {
	if h.searchIdx == nil {
		return
	}
	labels := search.FlattenLabels(d.Labels)
	var registeredAt, lastSeenAt int64
	if d.RegisteredAt != nil {
		registeredAt = d.RegisteredAt.Unix()
	}
	if d.LastSeenAt != nil {
		lastSeenAt = d.LastSeenAt.Unix()
	}
	data := &taskqueue.SearchEntityData{
		Hostname:         d.Hostname,
		AgentVersion:     d.AgentVersion,
		Labels:           labels,
		ComplianceStatus: d.ComplianceStatus,
		RegisteredAt:     registeredAt,
		LastSeenAt:       lastSeenAt,
	}
	// Enrich with inventory data (best-effort).
	inv, err := h.store.Queries().GetDeviceInventoryByTables(ctx, db.GetDeviceInventoryByTablesParams{
		DeviceID: d.ID,
		Column2:  []string{"os_version", "kernel_info"},
	})
	if err == nil {
		for _, t := range inv {
			search.EnrichDeviceInventory(data, t.TableName, t.Rows)
		}
	}
	if err := h.searchIdx.EnqueueReindex(ctx, search.ScopeDevice, d.ID, data); err != nil {
		h.logger.Warn("failed to enqueue search reindex", "scope", "device", "error", err)
	}
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
			return nil, apiErrorCtx(ctx, ErrInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
		offset = int32(offset64)
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list devices")
	}

	// Use the matching count query for the active status filter
	var count int64
	switch req.Msg.StatusFilter {
	case "online":
		count, err = q.CountDevicesOnline(ctx, filterUID)
	case "offline":
		count, err = q.CountDevicesOffline(ctx, filterUID)
	default:
		count, err = q.CountDevices(ctx, filterUID)
	}
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count devices")
	}

	var nextPageToken string
	if int32(len(devices)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

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

	for i, d := range devices {
		protoDevices[i] = h.deviceToProtoWithAssignments(d, userAssignMap[d.ID], groupAssignMap[d.ID])
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

	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{
		ID:           req.Msg.Id,
		FilterUserID: userFilterID(ctx, "GetDevice"),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to set label")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "device",
		"stream_id", req.Msg.Id,
		"event_type", "DeviceLabelSet",
	)

	// Read back updated device
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get updated device")
	}

	h.enqueueDeviceReindex(ctx, device)

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// RemoveDeviceLabel removes a label from a device.
func (h *DeviceHandler) RemoveDeviceLabel(ctx context.Context, req *connect.Request[pm.RemoveDeviceLabelRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to remove label")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "device",
		"stream_id", req.Msg.Id,
		"event_type", "DeviceLabelRemoved",
	)

	// Read back updated device
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get updated device")
	}

	h.enqueueDeviceReindex(ctx, device)

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// DeleteDevice deletes a device.
func (h *DeviceHandler) DeleteDevice(ctx context.Context, req *connect.Request[pm.DeleteDeviceRequest]) (*connect.Response[pm.DeleteDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to delete device")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "device",
		"stream_id", req.Msg.Id,
		"event_type", "DeviceDeleted",
	)

	if h.searchIdx != nil {
		if err := h.searchIdx.EnqueueRemove(ctx, search.ScopeDevice, req.Msg.Id, nil); err != nil {
			h.logger.Warn("failed to enqueue search index remove", "scope", "device", "error", err)
		}
	}

	return connect.NewResponse(&pm.DeleteDeviceResponse{}), nil
}

// AssignDevice assigns a device to one or more users and/or user groups.
func (h *DeviceHandler) AssignDevice(ctx context.Context, req *connect.Request[pm.AssignDeviceRequest]) (*connect.Response[pm.AssignDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
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
	_, err := q.GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
	}

	// Build sets of already-assigned user/group IDs to prevent duplicate events
	existingUserIDs, _ := q.ListDeviceAssignedUserIDs(ctx, req.Msg.DeviceId)
	existingUserSet := make(map[string]bool, len(existingUserIDs))
	for _, id := range existingUserIDs {
		existingUserSet[id] = true
	}
	existingGroupIDs, _ := q.ListDeviceAssignedGroupIDs(ctx, req.Msg.DeviceId)
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
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
		}

		err = h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   req.Msg.DeviceId,
			EventType:  "DeviceAssigned",
			Data: map[string]any{
				"user_id": userID,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		})
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to assign device")
		}
		h.logger.Debug("event appended",
			"request_id", middleware.RequestIDFromContext(ctx),
			"stream_type", "device",
			"stream_id", req.Msg.DeviceId,
			"event_type", "DeviceAssigned",
		)
	}

	for _, groupID := range groupIDs {
		if existingGroupSet[groupID] {
			continue // already assigned, skip
		}

		// Verify user group exists
		_, err = q.GetUserGroupByID(ctx, groupID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, apiErrorCtx(ctx, ErrUserGroupNotFound, connect.CodeNotFound, "user group not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user group")
		}

		err = h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   req.Msg.DeviceId,
			EventType:  "DeviceGroupAssigned",
			Data: map[string]any{
				"group_id": groupID,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		})
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to assign device to group")
		}
		h.logger.Debug("event appended",
			"request_id", middleware.RequestIDFromContext(ctx),
			"stream_type", "device",
			"stream_id", req.Msg.DeviceId,
			"event_type", "DeviceGroupAssigned",
		)
	}

	// Read back updated device
	device, err := q.GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Exactly one of user_id or group_id must be set
	if (req.Msg.UserId == "") == (req.Msg.GroupId == "") {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "exactly one of user_id or group_id must be set")
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
	}

	if req.Msg.UserId != "" {
		// Emit DeviceUnassigned event
		err = h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   req.Msg.DeviceId,
			EventType:  "DeviceUnassigned",
			Data: map[string]any{
				"user_id": req.Msg.UserId,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		})
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to unassign device")
		}
		h.logger.Debug("event appended",
			"request_id", middleware.RequestIDFromContext(ctx),
			"stream_type", "device",
			"stream_id", req.Msg.DeviceId,
			"event_type", "DeviceUnassigned",
		)
	} else {
		// Emit DeviceGroupUnassigned event
		err = h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   req.Msg.DeviceId,
			EventType:  "DeviceGroupUnassigned",
			Data: map[string]any{
				"group_id": req.Msg.GroupId,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		})
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to unassign device from group")
		}
		h.logger.Debug("event appended",
			"request_id", middleware.RequestIDFromContext(ctx),
			"stream_type", "device",
			"stream_id", req.Msg.DeviceId,
			"event_type", "DeviceGroupUnassigned",
		)
	}

	// Read back updated device
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
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

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to set sync interval")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "device",
		"stream_id", req.Msg.Id,
		"event_type", "DeviceSyncIntervalSet",
	)

	// Read back updated device
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.Id})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get updated device")
	}

	return connect.NewResponse(&pm.UpdateDeviceResponse{
		Device: h.deviceToProtoCtx(ctx, device),
	}), nil
}

// deviceToProtoCtx converts a database device projection to a protobuf device,
// populating assigned user/group IDs from junction tables.
func (h *DeviceHandler) deviceToProtoCtx(ctx context.Context, d db.DevicesProjection) *pm.Device {
	q := h.store.Queries()
	var userIDs, groupIDs []string
	if rows, err := q.ListDeviceAssignedUserIDs(ctx, d.ID); err == nil {
		userIDs = rows
	}
	if rows, err := q.ListDeviceAssignedGroupIDs(ctx, d.ID); err == nil {
		groupIDs = rows
	}
	return h.deviceToProtoWithAssignments(d, userIDs, groupIDs)
}

// deviceToProtoWithAssignments converts a database device projection to a protobuf
// device using pre-fetched assignment data. Used by list endpoints with batch queries.
func (h *DeviceHandler) deviceToProtoWithAssignments(d db.DevicesProjection, assignedUserIDs, assignedGroupIDs []string) *pm.Device {
	device := &pm.Device{
		Id:                  d.ID,
		Hostname:            d.Hostname,
		AgentVersion:        d.AgentVersion,
		Labels:              make(map[string]string),
		SyncIntervalMinutes: d.SyncIntervalMinutes,
		AssignedUserIds:     assignedUserIDs,
		AssignedGroupIds:    assignedGroupIDs,
	}

	// Determine status based on last_seen
	if d.LastSeenAt != nil {
		device.LastSeenAt = timestamppb.New(*d.LastSeenAt)
		if time.Since(*d.LastSeenAt) < 5*time.Minute {
			device.Status = "online"
		} else {
			device.Status = "offline"
		}
	} else {
		device.Status = "offline"
	}

	if d.RegisteredAt != nil {
		device.RegisteredAt = timestamppb.New(*d.RegisteredAt)
	}

	if d.CertNotAfter != nil {
		device.CertExpiresAt = timestamppb.New(*d.CertNotAfter)
	}

	// Parse labels from JSONB
	if len(d.Labels) > 0 {
		var labels map[string]string
		if err := json.Unmarshal(d.Labels, &labels); err == nil {
			device.Labels = labels
		}
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

// GetDeviceLpsPasswords returns current and historical LPS passwords for a device.
func (h *DeviceHandler) GetDeviceLpsPasswords(ctx context.Context, req *connect.Request[pm.GetDeviceLpsPasswordsRequest]) (*connect.Response[pm.GetDeviceLpsPasswordsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
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
		entry.RotatedAt = timestamppb.New(p.RotatedAt)
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
		entry.RotatedAt = timestamppb.New(p.RotatedAt)
		resp.History = append(resp.History, entry)
	}

	return connect.NewResponse(resp), nil
}

// GetDeviceLuksKeys returns current and historical LUKS keys for a device.
func (h *DeviceHandler) GetDeviceLuksKeys(ctx context.Context, req *connect.Request[pm.GetDeviceLuksKeysRequest]) (*connect.Response[pm.GetDeviceLuksKeysResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
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
		entry.RotatedAt = timestamppb.New(k.RotatedAt)
		if k.RevocationStatus != nil {
			entry.RevocationStatus = *k.RevocationStatus
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
		entry.RotatedAt = timestamppb.New(k.RotatedAt)
		resp.History = append(resp.History, entry)
	}

	return connect.NewResponse(resp), nil
}

// CreateLuksToken creates a one-time token for setting a user-defined LUKS passphrase.
// Only the device's assigned owner can create a token (admins cannot).
func (h *DeviceHandler) CreateLuksToken(ctx context.Context, req *connect.Request[pm.CreateLuksTokenRequest]) (*connect.Response[pm.CreateLuksTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
	}

	// Only an assigned owner can create a LUKS token
	assignedUserIDs, err := h.store.Queries().ListDeviceAssignedUserIDs(ctx, req.Msg.DeviceId)
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
	action, err := h.store.Queries().GetActionByID(ctx, req.Msg.ActionId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
	}
	if pm.ActionType(action.ActionType) != pm.ActionType_ACTION_TYPE_LUKS {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "action is not a LUKS action")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate token")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create token")
	}

	uri := fmt.Sprintf("power-manage://luks/set-passphrase?token=%s", token)
	cliCmd := fmt.Sprintf("sudo power-manage-agent luks set-passphrase --token %s", token)

	return connect.NewResponse(&pm.CreateLuksTokenResponse{
		Token:      token,
		Uri:        uri,
		CliCommand: cliCmd,
	}), nil
}

// RevokeLuksDeviceKey sends a revocation request to the agent via the task queue.
func (h *DeviceHandler) RevokeLuksDeviceKey(ctx context.Context, req *connect.Request[pm.RevokeLuksDeviceKeyRequest]) (*connect.Response[pm.RevokeLuksDeviceKeyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to record revocation event")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "luks_key",
		"stream_id", luksStreamID,
		"event_type", "LuksDeviceKeyRevocationDispatched",
	)

	// Dispatch LUKS device key revocation to device via Asynq task queue
	if h.aqClient != nil {
		if err := h.aqClient.EnqueueToDevice(req.Msg.DeviceId, taskqueue.TypeRevokeLuksDeviceKey, taskqueue.RevokeLuksDeviceKeyPayload{
			ActionID: req.Msg.ActionId,
		}, asynq.MaxRetry(5)); err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to dispatch LUKS revocation")
		}
	}

	return connect.NewResponse(&pm.RevokeLuksDeviceKeyResponse{}), nil
}

// ListDeviceAssignees returns the users and user groups assigned to a device.
func (h *DeviceHandler) ListDeviceAssignees(ctx context.Context, req *connect.Request[pm.ListDeviceAssigneesRequest]) (*connect.Response[pm.ListDeviceAssigneesResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	q := h.store.Queries()

	// Verify device exists
	_, err := q.GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: req.Msg.DeviceId})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
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
			Type: "user",
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
			Type: "user_group",
			Name: g.GroupName,
		})
	}

	return connect.NewResponse(&pm.ListDeviceAssigneesResponse{
		Assignees: assignees,
	}), nil
}

// TriggerAgentUpdate pushes auto-update info to the given devices via the gateway.
func (h *DeviceHandler) TriggerAgentUpdate(ctx context.Context, req *connect.Request[pm.TriggerAgentUpdateRequest]) (*connect.Response[pm.TriggerAgentUpdateResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if h.aqClient == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "task queue not available")
	}

	var triggered int32
	for _, deviceID := range req.Msg.DeviceIds {
		if err := h.aqClient.EnqueueToDevice(deviceID, taskqueue.TypeTriggerUpdate, struct{}{}, asynq.MaxRetry(1)); err != nil {
			h.logger.Warn("failed to enqueue agent update trigger", "device_id", deviceID, "error", err)
			continue
		}
		triggered++
	}

	return connect.NewResponse(&pm.TriggerAgentUpdateResponse{
		TriggeredCount: triggered,
	}), nil
}
