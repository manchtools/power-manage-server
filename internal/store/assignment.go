package store

import (
	"context"
	"time"
)

// Assignment is the basic assignment-projection row. Mode is the
// pm.AssignmentMode enum value (Required / Available); SortOrder
// drives the dispatch ordering on the agent.
type Assignment struct {
	ID         string
	SourceType string
	SourceID   string
	TargetType string
	TargetID   string
	SortOrder  int32
	Mode       int32
	CreatedAt  *time.Time
	CreatedBy  string
}

// AssignmentWithNames is the List-side shape — wraps Assignment with
// the joined SourceName + TargetName so the list UI can render without
// per-row lookups for display.
type AssignmentWithNames struct {
	Assignment
	SourceName string
	TargetName string
}

// AssignmentKey is the composite (source, target) lookup used by
// GetAssignment and the duplicate-pre-check path. The projection's
// unique index on this tuple guarantees at most one active row.
type AssignmentKey struct {
	SourceType string
	SourceID   string
	TargetType string
	TargetID   string
}

// ListAssignmentsFilter pairs pagination with the four optional
// filter axes the UI exposes. Empty strings disable each axis
// independently — the projection treats "" as "no filter".
type ListAssignmentsFilter struct {
	SourceType string
	SourceID   string
	TargetType string
	TargetID   string
	Limit      int32
	Offset     int32
}

// CountAssignmentsFilter mirrors ListAssignmentsFilter's filter
// fields for the matching count side.
type CountAssignmentsFilter struct {
	SourceType string
	SourceID   string
	TargetType string
	TargetID   string
}

// AssignmentRepo reads assignment state. Writes flow through events
// (AssignmentCreated / AssignmentDeleted / AssignmentModeChanged /
// AssignmentSortOrderChanged) and the projector listener.
//
// Per-device join queries that hydrate action / source-type details
// (ListAssignedActionsForDevice, ListDirectAssignmentsForDevice,
// ListGroupAssignmentsForDevice, ListAssignmentsForUser) stay on
// Store.Queries() — they return join-shaped rows that migrate with
// their respective domain consumers.
type AssignmentRepo interface {
	// Get returns the assignment for a (source, target) tuple.
	// Returns ErrNotFound when no active assignment matches.
	Get(ctx context.Context, key AssignmentKey) (Assignment, error)

	// GetByID returns the assignment by its ID.
	GetByID(ctx context.Context, id string) (Assignment, error)

	// List returns a page of assignments hydrated with source +
	// target display names, ordered by created_at descending.
	List(ctx context.Context, filter ListAssignmentsFilter) ([]AssignmentWithNames, error)

	// Count returns the total matching the filter.
	Count(ctx context.Context, filter CountAssignmentsFilter) (int64, error)

	// ListAvailableForDevice returns every "Available"-mode
	// assignment whose effective target reaches the given device
	// (directly, via device-group, via user assigned to the device,
	// or via that user's user-groups). Used to build the per-device
	// "what can the user opt into" catalog.
	ListAvailableForDevice(ctx context.Context, deviceID string) ([]Assignment, error)

	// ListAssignedUserIDsForDevice returns the user IDs with at
	// least one assignment that resolves to the given device.
	// Returns an empty slice when the device has no user
	// assignments.
	ListAssignedUserIDsForDevice(ctx context.Context, deviceID string) ([]string, error)
}
