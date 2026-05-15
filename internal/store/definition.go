package store

import (
	"context"
	"encoding/json"
	"time"
)

// Definition is the definition-projection row — the top of the
// action-chain hierarchy (definition → action_sets → actions).
// Schedule stays as json.RawMessage at the boundary per the JSONB
// normalize plan.
type Definition struct {
	ID          string
	Name        string
	Description string
	MemberCount int32
	CreatedAt   *time.Time
	CreatedBy   string
	UpdatedAt   *time.Time
	Schedule    json.RawMessage
}

// DefinitionMember is one row in the definition-members join,
// hydrated with the action_set's display name.
type DefinitionMember struct {
	DefinitionID  string
	ActionSetID   string
	SortOrder     int32
	AddedAt       *time.Time
	ActionSetName string
}

// ListDefinitionsFilter is the pagination shape.
type ListDefinitionsFilter struct {
	Limit  int32
	Offset int32
}

// DefinitionRepo reads definition state. Writes flow through events.
// Lookups for "what action sets does this definition contain" live
// on ActionSetRepo.ListInDefinition (already migrated in #273).
type DefinitionRepo interface {
	// Get returns a definition by ID. Returns ErrNotFound when no
	// definition with that ID exists.
	Get(ctx context.Context, id string) (Definition, error)

	// List returns a page of definitions.
	List(ctx context.Context, filter ListDefinitionsFilter) ([]Definition, error)

	// Count returns the total non-deleted definition count.
	Count(ctx context.Context) (int64, error)

	// ListMembers returns the action_set members of a definition in
	// their configured sort order, hydrated with action_set_name.
	ListMembers(ctx context.Context, definitionID string) ([]DefinitionMember, error)
}
