package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// DeviceGroupHandler handles device group RPCs.
type DeviceGroupHandler struct {
	store *store.Store
}

// NewDeviceGroupHandler creates a new device group handler.
func NewDeviceGroupHandler(st *store.Store) *DeviceGroupHandler {
	return &DeviceGroupHandler{
		store: st,
	}
}

// CreateDeviceGroup creates a new device group.
func (h *DeviceGroupHandler) CreateDeviceGroup(ctx context.Context, req *connect.Request[pm.CreateDeviceGroupRequest]) (*connect.Response[pm.CreateDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	id := ulid.Make().String()

	// Validate dynamic query if provided
	if req.Msg.IsDynamic && req.Msg.DynamicQuery != "" {
		validationErr, err := h.store.Queries().ValidateDynamicQuery(ctx, req.Msg.DynamicQuery)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to validate query")
		}
		if validationErr != "" {
			return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, validationErr)
		}
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   id,
		EventType:  "DeviceGroupCreated",
		Data: map[string]any{
			"name":          req.Msg.Name,
			"description":   req.Msg.Description,
			"is_dynamic":    req.Msg.IsDynamic,
			"dynamic_query": req.Msg.DynamicQuery,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create device group")
	}

	group, err := h.store.Queries().GetDeviceGroupByID(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.CreateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// GetDeviceGroup returns a device group by ID.
func (h *DeviceGroupHandler) GetDeviceGroup(ctx context.Context, req *connect.Request[pm.GetDeviceGroupRequest]) (*connect.Response[pm.GetDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	group, err := h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "device group not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	members, err := h.store.Queries().ListDeviceGroupMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group members")
	}

	deviceIDs := make([]string, len(members))
	devices := make([]*pm.DeviceGroupMember, len(members))
	for i, m := range members {
		deviceIDs[i] = m.DeviceID
		devices[i] = &pm.DeviceGroupMember{
			DeviceId:     m.DeviceID,
			Hostname:     m.Hostname,
			AgentVersion: m.AgentVersion,
		}
		if m.LastSeenAt.Valid {
			devices[i].LastSeenAt = timestamppb.New(m.LastSeenAt.Time)
		}
	}

	return connect.NewResponse(&pm.GetDeviceGroupResponse{
		Group:     h.deviceGroupToProto(group),
		DeviceIds: deviceIDs,
		Devices:   devices,
	}), nil
}

// ListDeviceGroups returns a paginated list of device groups.
func (h *DeviceGroupHandler) ListDeviceGroups(ctx context.Context, req *connect.Request[pm.ListDeviceGroupsRequest]) (*connect.Response[pm.ListDeviceGroupsResponse], error) {
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

	groups, err := h.store.Queries().ListDeviceGroups(ctx, db.ListDeviceGroupsParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list device groups")
	}

	count, err := h.store.Queries().CountDeviceGroups(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count device groups")
	}

	var nextPageToken string
	if int32(len(groups)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoGroups := make([]*pm.DeviceGroup, len(groups))
	for i, g := range groups {
		protoGroups[i] = h.deviceGroupToProto(g)
	}

	return connect.NewResponse(&pm.ListDeviceGroupsResponse{
		Groups:        protoGroups,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// ListDeviceGroupsForDevice returns all device groups that a specific device belongs to.
func (h *DeviceGroupHandler) ListDeviceGroupsForDevice(ctx context.Context, req *connect.Request[pm.ListDeviceGroupsForDeviceRequest]) (*connect.Response[pm.ListDeviceGroupsForDeviceResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	groups, err := h.store.Queries().ListGroupsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list groups for device")
	}

	protoGroups := make([]*pm.DeviceGroup, len(groups))
	for i, g := range groups {
		protoGroups[i] = h.deviceGroupToProto(g)
	}

	return connect.NewResponse(&pm.ListDeviceGroupsForDeviceResponse{
		Groups: protoGroups,
	}), nil
}

// RenameDeviceGroup renames a device group.
func (h *DeviceGroupHandler) RenameDeviceGroup(ctx context.Context, req *connect.Request[pm.RenameDeviceGroupRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  "DeviceGroupRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to rename device group")
	}

	group, err := h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "device group not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// UpdateDeviceGroupDescription updates a device group's description.
func (h *DeviceGroupHandler) UpdateDeviceGroupDescription(ctx context.Context, req *connect.Request[pm.UpdateDeviceGroupDescriptionRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  "DeviceGroupDescriptionUpdated",
		Data: map[string]any{
			"description": req.Msg.Description,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update description")
	}

	group, err := h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "device group not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// DeleteDeviceGroup deletes a device group.
func (h *DeviceGroupHandler) DeleteDeviceGroup(ctx context.Context, req *connect.Request[pm.DeleteDeviceGroupRequest]) (*connect.Response[pm.DeleteDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  "DeviceGroupDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to delete device group")
	}

	return connect.NewResponse(&pm.DeleteDeviceGroupResponse{}), nil
}

// AddDeviceToGroup adds a device to a group.
func (h *DeviceGroupHandler) AddDeviceToGroup(ctx context.Context, req *connect.Request[pm.AddDeviceToGroupRequest]) (*connect.Response[pm.AddDeviceToGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Collect device IDs from single + repeated fields
	deviceIDs := append([]string{}, req.Msg.DeviceIds...)
	if req.Msg.DeviceId != "" {
		deviceIDs = append(deviceIDs, req.Msg.DeviceId)
	}
	if len(deviceIDs) == 0 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one device_id or device_ids must be set")
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	q := h.store.Queries()

	// Verify group exists and is not dynamic
	group, err := q.GetDeviceGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "device group not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	// Cannot manually add members to dynamic groups
	if group.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrDynamicGroupManualModify, connect.CodeFailedPrecondition, "cannot manually add members to dynamic groups")
	}

	for _, deviceID := range deviceIDs {
		// Verify device exists
		_, err = q.GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: deviceID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device")
		}

		err = h.store.AppendEvent(ctx, store.Event{
			StreamType: "device_group",
			StreamID:   req.Msg.GroupId,
			EventType:  "DeviceGroupMemberAdded",
			Data: map[string]any{
				"device_id": deviceID,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		})
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to add device to group")
		}
	}

	group, err = q.GetDeviceGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.AddDeviceToGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// RemoveDeviceFromGroup removes a device from a group.
func (h *DeviceGroupHandler) RemoveDeviceFromGroup(ctx context.Context, req *connect.Request[pm.RemoveDeviceFromGroupRequest]) (*connect.Response[pm.RemoveDeviceFromGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Verify group exists and is not dynamic
	group, err := h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "device group not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	// Cannot manually remove members from dynamic groups
	if group.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrDynamicGroupManualModify, connect.CodeFailedPrecondition, "cannot manually remove members from dynamic groups")
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.GroupId,
		EventType:  "DeviceGroupMemberRemoved",
		Data: map[string]any{
			"device_id": req.Msg.DeviceId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to remove device from group")
	}

	group, err = h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.RemoveDeviceFromGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// UpdateDeviceGroupQuery updates a device group's dynamic query.
func (h *DeviceGroupHandler) UpdateDeviceGroupQuery(ctx context.Context, req *connect.Request[pm.UpdateDeviceGroupQueryRequest]) (*connect.Response[pm.UpdateDeviceGroupQueryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Validate dynamic query if provided
	if req.Msg.IsDynamic && req.Msg.DynamicQuery != "" {
		validationErr, err := h.store.Queries().ValidateDynamicQuery(ctx, req.Msg.DynamicQuery)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to validate query")
		}
		if validationErr != "" {
			return nil, apiErrorCtx(ctx, ErrInvalidQuery, connect.CodeInvalidArgument, validationErr)
		}
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  "DeviceGroupQueryUpdated",
		Data: map[string]any{
			"is_dynamic":    req.Msg.IsDynamic,
			"dynamic_query": req.Msg.DynamicQuery,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update query")
	}

	group, err := h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "device group not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupQueryResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// ValidateDynamicQuery validates a dynamic query without creating a group.
func (h *DeviceGroupHandler) ValidateDynamicQuery(ctx context.Context, req *connect.Request[pm.ValidateDynamicQueryRequest]) (*connect.Response[pm.ValidateDynamicQueryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	validationErr, err := h.store.Queries().ValidateDynamicQuery(ctx, req.Msg.Query)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to validate query")
	}

	if validationErr != "" {
		return connect.NewResponse(&pm.ValidateDynamicQueryResponse{
			Valid: false,
			Error: validationErr,
		}), nil
	}

	// Count matching devices
	matchingCount, err := h.store.Queries().CountMatchingDevicesForQuery(ctx, req.Msg.Query)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count matching devices")
	}

	return connect.NewResponse(&pm.ValidateDynamicQueryResponse{
		Valid:               true,
		MatchingDeviceCount: int32(matchingCount),
	}), nil
}

// EvaluateDynamicGroup triggers re-evaluation of a dynamic group.
func (h *DeviceGroupHandler) EvaluateDynamicGroup(ctx context.Context, req *connect.Request[pm.EvaluateDynamicGroupRequest]) (*connect.Response[pm.EvaluateDynamicGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	// Verify group exists and is dynamic
	group, err := h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "device group not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	if !group.IsDynamic {
		return nil, apiErrorCtx(ctx, ErrGroupNotDynamic, connect.CodeFailedPrecondition, "group is not dynamic")
	}

	// Get current member count before evaluation
	membersBefore := group.MemberCount

	// Trigger evaluation
	err = h.store.Queries().EvaluateDynamicGroup(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to evaluate dynamic group")
	}

	// Get updated group
	group, err = h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	// Calculate added/removed (simplified - actual counts would need more tracking)
	devicesAdded := int32(0)
	devicesRemoved := int32(0)
	if group.MemberCount > membersBefore {
		devicesAdded = group.MemberCount - membersBefore
	} else if group.MemberCount < membersBefore {
		devicesRemoved = membersBefore - group.MemberCount
	}

	return connect.NewResponse(&pm.EvaluateDynamicGroupResponse{
		Group:          h.deviceGroupToProto(group),
		DevicesAdded:   devicesAdded,
		DevicesRemoved: devicesRemoved,
	}), nil
}

// SetDeviceGroupSyncInterval sets the sync interval for a device group.
func (h *DeviceGroupHandler) SetDeviceGroupSyncInterval(ctx context.Context, req *connect.Request[pm.SetDeviceGroupSyncIntervalRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Validate interval (0 = default, max 1440 = 24 hours)
	if req.Msg.SyncIntervalMinutes < 0 || req.Msg.SyncIntervalMinutes > 1440 {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "sync interval must be between 0 and 1440 minutes")
	}

	// Verify group exists
	_, err := h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrDeviceGroupNotFound, connect.CodeNotFound, "device group not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.Id,
		EventType:  "DeviceGroupSyncIntervalSet",
		Data: map[string]any{
			"sync_interval_minutes": req.Msg.SyncIntervalMinutes,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to set sync interval")
	}

	group, err := h.store.Queries().GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get device group")
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

func (h *DeviceGroupHandler) deviceGroupToProto(g db.DeviceGroupsProjection) *pm.DeviceGroup {
	group := &pm.DeviceGroup{
		Id:                  g.ID,
		Name:                g.Name,
		Description:         g.Description,
		MemberCount:         g.MemberCount,
		CreatedBy:           g.CreatedBy,
		IsDynamic:           g.IsDynamic,
		SyncIntervalMinutes: g.SyncIntervalMinutes,
	}

	if g.DynamicQuery != nil {
		group.DynamicQuery = *g.DynamicQuery
	}

	if g.CreatedAt.Valid {
		group.CreatedAt = timestamppb.New(g.CreatedAt.Time)
	}

	return group
}
