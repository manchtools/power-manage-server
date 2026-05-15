package store

import (
	"context"
	"encoding/json"
	"time"
)

// ActionSet is the action-set projection row — a named, ordered
// collection of actions. Schedule stays as json.RawMessage at the
// boundary per the JSONB normalize plan.
type ActionSet struct {
	ID          string
	Name        string
	Description string
	MemberCount int32
	CreatedAt   *time.Time
	CreatedBy   string
	UpdatedAt   *time.Time
	Schedule    json.RawMessage
}

// ActionSetMember is one row in the action-set membership join,
// hydrated with the action's name + type for display.
type ActionSetMember struct {
	SetID      string
	ActionID   string
	SortOrder  int32
	AddedAt    *time.Time
	ActionName string
	ActionType int32
}

// ListActionSetsFilter pairs pagination with the "unassigned only"
// flag (sets with no assignment targeting them).
type ListActionSetsFilter struct {
	UnassignedOnly bool
	Limit          int32
	Offset         int32
}

// ActionSetRepo reads action-set state. Writes flow through events.
type ActionSetRepo interface {
	// Get returns a set by ID. Returns ErrNotFound when no set
	// with that ID exists.
	Get(ctx context.Context, id string) (ActionSet, error)

	// List returns a page of sets.
	List(ctx context.Context, filter ListActionSetsFilter) ([]ActionSet, error)

	// Count returns the total non-deleted set count, honouring
	// UnassignedOnly so pagination totals stay aligned.
	Count(ctx context.Context, unassignedOnly bool) (int64, error)

	// ListMembers returns the action members of a set in their
	// configured sort order, hydrated with the action's display
	// name + type.
	ListMembers(ctx context.Context, setID string) ([]ActionSetMember, error)

	// ListInDefinition returns every action set that belongs to a
	// given definition. Used by definition-detail handlers and the
	// definition reindex sweep.
	ListInDefinition(ctx context.Context, definitionID string) ([]ActionSet, error)
}
