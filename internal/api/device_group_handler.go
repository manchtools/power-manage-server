package api

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

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
	store   *store.Store
	entropy *ulid.MonotonicEntropy
}

// NewDeviceGroupHandler creates a new device group handler.
func NewDeviceGroupHandler(st *store.Store) *DeviceGroupHandler {
	return &DeviceGroupHandler{
		store:   st,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// CreateDeviceGroup creates a new device group.
func (h *DeviceGroupHandler) CreateDeviceGroup(ctx context.Context, req *connect.Request[pm.CreateDeviceGroupRequest]) (*connect.Response[pm.CreateDeviceGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	// Validate dynamic query if provided
	if req.Msg.IsDynamic && req.Msg.DynamicQuery != "" {
		validationErr, err := h.store.QueriesFromContext(ctx).ValidateDynamicQuery(ctx, req.Msg.DynamicQuery)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to validate query"))
		}
		if validationErr != "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(validationErr))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create device group"))
	}

	group, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	return connect.NewResponse(&pm.CreateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// GetDeviceGroup returns a device group by ID.
func (h *DeviceGroupHandler) GetDeviceGroup(ctx context.Context, req *connect.Request[pm.GetDeviceGroupRequest]) (*connect.Response[pm.GetDeviceGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	group, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	members, err := h.store.QueriesFromContext(ctx).ListDeviceGroupMembers(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group members"))
	}

	deviceIDs := make([]string, len(members))
	for i, m := range members {
		deviceIDs[i] = m.DeviceID
	}

	return connect.NewResponse(&pm.GetDeviceGroupResponse{
		Group:     h.deviceGroupToProto(group),
		DeviceIds: deviceIDs,
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
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page token"))
		}
		offset = int32(offset64)
	}

	groups, err := h.store.QueriesFromContext(ctx).ListDeviceGroups(ctx, db.ListDeviceGroupsParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list device groups"))
	}

	count, err := h.store.QueriesFromContext(ctx).CountDeviceGroups(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count device groups"))
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

// RenameDeviceGroup renames a device group.
func (h *DeviceGroupHandler) RenameDeviceGroup(ctx context.Context, req *connect.Request[pm.RenameDeviceGroupRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to rename device group"))
	}

	group, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// UpdateDeviceGroupDescription updates a device group's description.
func (h *DeviceGroupHandler) UpdateDeviceGroupDescription(ctx context.Context, req *connect.Request[pm.UpdateDeviceGroupDescriptionRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update description"))
	}

	group, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// DeleteDeviceGroup deletes a device group.
func (h *DeviceGroupHandler) DeleteDeviceGroup(ctx context.Context, req *connect.Request[pm.DeleteDeviceGroupRequest]) (*connect.Response[pm.DeleteDeviceGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete device group"))
	}

	return connect.NewResponse(&pm.DeleteDeviceGroupResponse{}), nil
}

// AddDeviceToGroup adds a device to a group.
func (h *DeviceGroupHandler) AddDeviceToGroup(ctx context.Context, req *connect.Request[pm.AddDeviceToGroupRequest]) (*connect.Response[pm.AddDeviceToGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify group exists and is not dynamic
	group, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	// Cannot manually add members to dynamic groups
	if group.IsDynamic {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("cannot manually add members to dynamic groups"))
	}

	// Verify device exists
	_, err = h.store.QueriesFromContext(ctx).GetDeviceByID(ctx, req.Msg.DeviceId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device"))
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   req.Msg.GroupId,
		EventType:  "DeviceGroupMemberAdded",
		Data: map[string]any{
			"device_id": req.Msg.DeviceId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to add device to group"))
	}

	group, err = h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	return connect.NewResponse(&pm.AddDeviceToGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// RemoveDeviceFromGroup removes a device from a group.
func (h *DeviceGroupHandler) RemoveDeviceFromGroup(ctx context.Context, req *connect.Request[pm.RemoveDeviceFromGroupRequest]) (*connect.Response[pm.RemoveDeviceFromGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify group exists and is not dynamic
	group, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	// Cannot manually remove members from dynamic groups
	if group.IsDynamic {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("cannot manually remove members from dynamic groups"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to remove device from group"))
	}

	group, err = h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	return connect.NewResponse(&pm.RemoveDeviceFromGroupResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// UpdateDeviceGroupQuery updates a device group's dynamic query.
func (h *DeviceGroupHandler) UpdateDeviceGroupQuery(ctx context.Context, req *connect.Request[pm.UpdateDeviceGroupQueryRequest]) (*connect.Response[pm.UpdateDeviceGroupQueryResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Validate dynamic query if provided
	if req.Msg.IsDynamic && req.Msg.DynamicQuery != "" {
		validationErr, err := h.store.QueriesFromContext(ctx).ValidateDynamicQuery(ctx, req.Msg.DynamicQuery)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to validate query"))
		}
		if validationErr != "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(validationErr))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update query"))
	}

	group, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	return connect.NewResponse(&pm.UpdateDeviceGroupQueryResponse{
		Group: h.deviceGroupToProto(group),
	}), nil
}

// ValidateDynamicQuery validates a dynamic query without creating a group.
func (h *DeviceGroupHandler) ValidateDynamicQuery(ctx context.Context, req *connect.Request[pm.ValidateDynamicQueryRequest]) (*connect.Response[pm.ValidateDynamicQueryResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	validationErr, err := h.store.QueriesFromContext(ctx).ValidateDynamicQuery(ctx, req.Msg.Query)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to validate query"))
	}

	if validationErr != "" {
		return connect.NewResponse(&pm.ValidateDynamicQueryResponse{
			Valid: false,
			Error: validationErr,
		}), nil
	}

	// Count matching devices
	matchingCount, err := h.store.QueriesFromContext(ctx).CountMatchingDevicesForQuery(ctx, req.Msg.Query)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count matching devices"))
	}

	return connect.NewResponse(&pm.ValidateDynamicQueryResponse{
		Valid:               true,
		MatchingDeviceCount: int32(matchingCount),
	}), nil
}

// EvaluateDynamicGroup triggers re-evaluation of a dynamic group.
func (h *DeviceGroupHandler) EvaluateDynamicGroup(ctx context.Context, req *connect.Request[pm.EvaluateDynamicGroupRequest]) (*connect.Response[pm.EvaluateDynamicGroupResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify group exists and is dynamic
	group, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
	}

	if !group.IsDynamic {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("group is not dynamic"))
	}

	// Get current member count before evaluation
	membersBefore := group.MemberCount

	// Trigger evaluation
	err = h.store.QueriesFromContext(ctx).EvaluateDynamicGroup(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to evaluate dynamic group"))
	}

	// Get updated group
	group, err = h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
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
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Validate interval (0 = default, max 1440 = 24 hours)
	if req.Msg.SyncIntervalMinutes < 0 || req.Msg.SyncIntervalMinutes > 1440 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("sync interval must be between 0 and 1440 minutes"))
	}

	// Verify group exists
	_, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device group not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
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
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to set sync interval"))
	}

	group, err := h.store.QueriesFromContext(ctx).GetDeviceGroupByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get device group"))
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
