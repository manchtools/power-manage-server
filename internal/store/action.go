package store

import (
	"context"
	"encoding/json"
	"time"
)

// Action is the action-projection row. Params + ParamsCanonical +
// Schedule + Signature stay as opaque bytes/json.RawMessage at the
// boundary — they're verified / signed / executed by code that
// already operates on the raw shapes.
type Action struct {
	ID              string
	Name            string
	Description     *string
	ActionType      int32
	Params          json.RawMessage
	TimeoutSeconds  int32
	CreatedAt       *time.Time
	CreatedBy       string
	Signature       []byte
	ParamsCanonical json.RawMessage
	DesiredState    int32
	IsSystem        bool
	UpdatedAt       *time.Time
	Schedule        json.RawMessage
}

// ActionNamePair is the narrow (id, name) shape returned by the
// bulk-name lookup. Used by response builders.
type ActionNamePair struct {
	ID   string
	Name string
}

// ListActionsFilter pairs pagination with the optional
// action-type filter and "unassigned only" flag. ActionTypeFilter == 0
// disables the type filter (returns all types).
type ListActionsFilter struct {
	ActionTypeFilter int32
	UnassignedOnly   bool
	Limit            int32
	Offset           int32
}

// CountActionsFilter mirrors ListActionsFilter's filter fields for
// the matching count side. Both shapes must stay in sync so
// pagination totals line up with the rows actually returned.
type CountActionsFilter struct {
	ActionTypeFilter int32
	UnassignedOnly   bool
}

// UpdateActionSignatureParams carries the fields a re-signing pass
// writes back to the action row. Used after the CA rotates the
// signing key — every action's signature + canonical-params blob is
// recomputed.
type UpdateActionSignatureParams struct {
	ID              string
	Signature       []byte
	ParamsCanonical json.RawMessage
}

// ActionRepo reads + maintains the action catalog. Writes other
// than the signature-rewrite flow through events.
type ActionRepo interface {
	// Get returns an action by ID. Returns ErrNotFound when no
	// action with that ID exists.
	Get(ctx context.Context, id string) (Action, error)

	// List returns a page of actions matching the filter. Empty
	// slice past the end.
	List(ctx context.Context, filter ListActionsFilter) ([]Action, error)

	// Count returns the total matching the filter. Pair with List.
	Count(ctx context.Context, filter CountActionsFilter) (int64, error)

	// NamesByIDs returns the (id, name) pairs for the given action
	// IDs in a single round-trip. Used by response builders that
	// need to hydrate action names without re-loading each row.
	NamesByIDs(ctx context.Context, ids []string) ([]ActionNamePair, error)

	// UpdateSignature rewrites the signature + canonical-params
	// pair on an action. The CA key-rotation pathway is the only
	// expected caller; everything else routes signature changes
	// through events.
	UpdateSignature(ctx context.Context, p UpdateActionSignatureParams) error
}
