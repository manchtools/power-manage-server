package store

import (
	"context"
	"encoding/json"
	"time"
)

// DeviceGroup is the device-group projection row. SyncIntervalMinutes
// drives the per-group dynamic-group re-evaluation cadence;
// MaintenanceWindow stays as json.RawMessage at the boundary per the
// JSONB normalize plan.
type DeviceGroup struct {
	ID                  string
	Name                string
	Description         string
	MemberCount         int32
	CreatedAt           *time.Time
	CreatedBy           string
	IsDynamic           bool
	DynamicQuery        *string
	SyncIntervalMinutes int32
	// InventoryIntervalMinutes is the per-group inventory-collection
	// interval (spec 22); 0 = no group contribution to a member's
	// resolved interval.
	InventoryIntervalMinutes int32
	MaintenanceWindow        json.RawMessage
}

// DeviceGroupMember is one row in the device-group membership join,
// hydrated with the device hostname + agent_version + last_seen_at
// for the UI's member listing.
type DeviceGroupMember struct {
	GroupID      string
	DeviceID     string
	AddedAt      *time.Time
	Hostname     string
	AgentVersion string
	LastSeenAt   *time.Time
}

// ListDeviceGroupsFilter is the pagination shape for the device-group
// list endpoint.
type ListDeviceGroupsFilter struct {
	Limit  int32
	Offset int32
	// Scope is the #3 device-group restriction: a direct id-match —
	// when Restricted, only groups whose id is in GroupIDs are listed.
	Scope ScopeGroupFilter
}

// DeviceGroupRepo reads device-group state from the projection.
// Writes flow through events; dynamic-group re-evaluation lives in
// internal/dyngroupeval (the PL/pgSQL evaluator was dropped under
// Wave C of tracker #242).
type DeviceGroupRepo interface {
	// Get returns the group by ID. Returns ErrNotFound when no
	// group with that ID exists.
	Get(ctx context.Context, id string) (DeviceGroup, error)

	// GetByName returns the group by display name. Used by the
	// CreateDeviceGroup duplicate-name pre-check.
	GetByName(ctx context.Context, name string) (DeviceGroup, error)

	// List returns a page of groups.
	List(ctx context.Context, filter ListDeviceGroupsFilter) ([]DeviceGroup, error)

	// Count returns the total non-deleted group count, scoped to the
	// caller's device-group scope when restricted.
	Count(ctx context.Context, scope ScopeGroupFilter) (int64, error)

	// ListForDevice returns every group the device belongs to
	// (direct + dynamic-materialized membership).
	ListForDevice(ctx context.Context, deviceID string) ([]DeviceGroup, error)

	// ListMembers returns the member rows hydrated with the
	// device hostname.
	ListMembers(ctx context.Context, groupID string) ([]DeviceGroupMember, error)
}
