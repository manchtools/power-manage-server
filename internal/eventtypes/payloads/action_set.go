package payloads

// ActionSetRenamed is the wire shape for ActionSetRenamed.
type ActionSetRenamed struct {
	Name string `json:"name"`
}

// ActionSetDescriptionUpdated is the wire shape for
// ActionSetDescriptionUpdated.
type ActionSetDescriptionUpdated struct {
	Description string `json:"description"`
}

// ActionSetMemberAdded is the wire shape for ActionSetMemberAdded.
type ActionSetMemberAdded struct {
	ActionID  string `json:"action_id"`
	SortOrder int32  `json:"sort_order"`
}

// ActionSetMemberRemoved is the wire shape for ActionSetMemberRemoved.
type ActionSetMemberRemoved struct {
	ActionID string `json:"action_id"`
}

// ActionSetMemberReordered is the wire shape for
// ActionSetMemberReordered.
type ActionSetMemberReordered struct {
	ActionID  string `json:"action_id"`
	SortOrder int32  `json:"sort_order"`
}
