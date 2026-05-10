package payloads

// DefinitionRenamed is the wire shape for DefinitionRenamed.
type DefinitionRenamed struct {
	Name string `json:"name"`
}

// DefinitionDescriptionUpdated is the wire shape for
// DefinitionDescriptionUpdated.
type DefinitionDescriptionUpdated struct {
	Description string `json:"description"`
}

// DefinitionMemberAdded is the wire shape for DefinitionMemberAdded.
type DefinitionMemberAdded struct {
	ActionSetID string `json:"action_set_id"`
	SortOrder   int32  `json:"sort_order"`
}

// DefinitionMemberRemoved is the wire shape for
// DefinitionMemberRemoved.
type DefinitionMemberRemoved struct {
	ActionSetID string `json:"action_set_id"`
}

// DefinitionMemberReordered is the wire shape for
// DefinitionMemberReordered.
type DefinitionMemberReordered struct {
	ActionSetID string `json:"action_set_id"`
	SortOrder   int32  `json:"sort_order"`
}
