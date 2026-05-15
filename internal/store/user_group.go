package store

import (
	"context"
	"encoding/json"
	"time"
)

// UserGroup is the user-group projection row.
// MaintenanceWindow stays as json.RawMessage at the boundary so each
// backend chooses how to materialize the column.
type UserGroup struct {
	ID                string
	Name              string
	Description       string
	MemberCount       int32
	CreatedAt         time.Time
	CreatedBy         string
	UpdatedAt         time.Time
	IsDynamic         bool
	DynamicQuery      *string
	MaintenanceWindow json.RawMessage
}

// UserGroupWithMembers wraps UserGroup with the JOIN-computed
// ActualMemberCount returned by GetWithMembers. The projection's
// stored member_count can lag the user_group_members table when a
// projector replay is in flight, so this row pairs both numbers and
// lets the SCIM handler reconcile against the live join count.
type UserGroupWithMembers struct {
	UserGroup
	ActualMemberCount int64
}

// UserGroupMember is one row in the user-group membership join,
// hydrated with the user's email for display.
type UserGroupMember struct {
	UserID  string
	Email   string
	AddedAt time.Time
}

// ListUserGroupsFilter is the pagination shape for the user-group
// list endpoint.
type ListUserGroupsFilter struct {
	Limit  int32
	Offset int32
}

// UserGroupRepo reads user-group state from the projection. Writes
// (UserGroupCreated / Updated / Deleted / MemberAdded / MemberRemoved
// etc.) flow through the event store + projector.
//
// Dynamic-group evaluator queries (EvaluateDynamicUserGroup,
// EvaluateQueuedDynamicUserGroups, ValidateUserGroupQuery) are NOT
// surfaced here — they call PL/pgSQL functions today and will move
// to a Go interpreter under Wave C of the storage-abstraction
// tracker. Until then, those call sites continue to use
// Store.Queries() directly.
type UserGroupRepo interface {
	// Get returns the group by ID. Returns ErrNotFound when no
	// group with that ID exists.
	Get(ctx context.Context, id string) (UserGroup, error)

	// GetByName returns the group by display name. Used by the
	// CreateUserGroup duplicate-name pre-check.
	GetByName(ctx context.Context, name string) (UserGroup, error)

	// GetWithMembers returns the group row plus the JOIN-computed
	// actual member count. SCIM handlers use this to detect
	// projection lag.
	GetWithMembers(ctx context.Context, id string) (UserGroupWithMembers, error)

	// List returns a page of groups.
	List(ctx context.Context, filter ListUserGroupsFilter) ([]UserGroup, error)

	// Count returns the total non-deleted group count.
	Count(ctx context.Context) (int64, error)

	// ListForUser returns every group the user belongs to (direct
	// membership only — dynamic-group membership is materialized
	// into user_group_members during evaluation).
	ListForUser(ctx context.Context, userID string) ([]UserGroup, error)

	// ListMemberIDs returns just the user IDs in the group.
	ListMemberIDs(ctx context.Context, groupID string) ([]string, error)

	// ListMembers returns the member rows hydrated with the
	// member's email.
	ListMembers(ctx context.Context, groupID string) ([]UserGroupMember, error)
}
