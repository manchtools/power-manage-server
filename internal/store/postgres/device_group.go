package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// DeviceGroup implements store.DeviceGroupRepo against
// device_groups_projection + device_group_members_projection.
type DeviceGroup struct {
	q *generated.Queries
}

// NewDeviceGroup returns a DeviceGroup repo bound to the given sqlc
// handle.
func NewDeviceGroup(q *generated.Queries) *DeviceGroup {
	return &DeviceGroup{q: q}
}

func (g *DeviceGroup) Get(ctx context.Context, id string) (store.DeviceGroup, error) {
	row, err := g.q.GetDeviceGroupByID(ctx, id)
	if err != nil {
		return store.DeviceGroup{}, fmt.Errorf("device_group: get: %w", translateNotFound(err))
	}
	return deviceGroupFromRow(row), nil
}

func (g *DeviceGroup) GetByName(ctx context.Context, name string) (store.DeviceGroup, error) {
	row, err := g.q.GetDeviceGroupByName(ctx, name)
	if err != nil {
		return store.DeviceGroup{}, fmt.Errorf("device_group: get by name: %w", translateNotFound(err))
	}
	return deviceGroupFromRow(row), nil
}

func (g *DeviceGroup) List(ctx context.Context, filter store.ListDeviceGroupsFilter) ([]store.DeviceGroup, error) {
	rows, err := g.q.ListDeviceGroups(ctx, generated.ListDeviceGroupsParams{
		Limit:           filter.Limit,
		Offset:          filter.Offset,
		ScopeRestricted: filter.Scope.Restricted,
		ScopeGroupIds:   filter.Scope.GroupIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("device_group: list: %w", err)
	}
	out := make([]store.DeviceGroup, len(rows))
	for i, r := range rows {
		out[i] = deviceGroupFromRow(r)
	}
	return out, nil
}

func (g *DeviceGroup) Count(ctx context.Context, scope store.ScopeGroupFilter) (int64, error) {
	n, err := g.q.CountDeviceGroups(ctx, generated.CountDeviceGroupsParams{
		ScopeRestricted: scope.Restricted,
		ScopeGroupIds:   scope.GroupIDs,
	})
	if err != nil {
		return 0, fmt.Errorf("device_group: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (g *DeviceGroup) ListForDevice(ctx context.Context, deviceID string) ([]store.DeviceGroup, error) {
	rows, err := g.q.ListGroupsForDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device_group: list for device: %w", err)
	}
	out := make([]store.DeviceGroup, len(rows))
	for i, r := range rows {
		out[i] = deviceGroupFromRow(r)
	}
	return out, nil
}

func (g *DeviceGroup) ListMembers(ctx context.Context, groupID string) ([]store.DeviceGroupMember, error) {
	rows, err := g.q.ListDeviceGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("device_group: list members: %w", err)
	}
	out := make([]store.DeviceGroupMember, len(rows))
	for i, r := range rows {
		out[i] = store.DeviceGroupMember{
			GroupID:      r.GroupID,
			DeviceID:     r.DeviceID,
			AddedAt:      r.AddedAt,
			Hostname:     r.Hostname,
			AgentVersion: r.AgentVersion,
			LastSeenAt:   r.LastSeenAt,
		}
	}
	return out, nil
}

func deviceGroupFromRow(r generated.DeviceGroupsProjection) store.DeviceGroup {
	return store.DeviceGroup{
		ID:                  r.ID,
		Name:                r.Name,
		Description:         r.Description,
		MemberCount:         r.MemberCount,
		CreatedAt:           r.CreatedAt,
		CreatedBy:           r.CreatedBy,
		IsDynamic:           r.IsDynamic,
		DynamicQuery:        r.DynamicQuery,
		SyncIntervalMinutes: r.SyncIntervalMinutes,
		MaintenanceWindow:   json.RawMessage(r.MaintenanceWindow),
	}
}
