package payloads

// AssignmentCreated is the wire shape for AssignmentCreated. The four
// tuple fields are required (NOT NULL columns); they stay non-pointer
// strings so the handler emit site can't omit them. The projector
// validates that none are empty.
type AssignmentCreated struct {
	SourceType string `json:"source_type"`
	SourceID   string `json:"source_id"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	SortOrder  *int32 `json:"sort_order,omitempty"`
	Mode       *int32 `json:"mode,omitempty"`
}

// AssignmentModeChanged is the wire shape for AssignmentModeChanged.
// Currently unused (assignments are immutable; mutate by
// delete-and-recreate) but the projector preserves replay parity.
type AssignmentModeChanged struct {
	Mode *int32 `json:"mode,omitempty"`
}

// AssignmentSortOrderChanged is the wire shape for
// AssignmentSortOrderChanged. Currently unused; preserved for replay.
type AssignmentSortOrderChanged struct {
	SortOrder *int32 `json:"sort_order,omitempty"`
}
