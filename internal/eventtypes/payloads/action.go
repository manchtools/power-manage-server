package payloads

import "encoding/json"

// ActionCreated is the wire shape for ActionCreated. Name is required
// (NOT NULL column on actions_projection); it stays a non-pointer
// string so the handler can't accidentally omit it. The projector
// validates that it is non-empty.
type ActionCreated struct {
	Name           string          `json:"name"`
	Description    *string         `json:"description,omitempty"`
	ActionType     *int32          `json:"action_type,omitempty"`
	DesiredState   *int32          `json:"desired_state,omitempty"`
	Params         json.RawMessage `json:"params,omitempty"`
	TimeoutSeconds *int32          `json:"timeout_seconds,omitempty"`
	IsSystem       *bool           `json:"is_system,omitempty"`
	Schedule       json.RawMessage `json:"schedule,omitempty"`
}

// ActionRenamed is the wire shape for ActionRenamed.
type ActionRenamed struct {
	Name string `json:"name"`
}

// ActionDescriptionUpdated is the wire shape for
// ActionDescriptionUpdated. The PL/pgSQL projector wrote
// `event.data->>'description'` directly; *string preserves the
// nullable-vs-empty distinction.
type ActionDescriptionUpdated struct {
	Description *string `json:"description,omitempty"`
}

// ActionParamsUpdated is the wire shape for ActionParamsUpdated.
type ActionParamsUpdated struct {
	Params         json.RawMessage `json:"params,omitempty"`
	TimeoutSeconds *int32          `json:"timeout_seconds,omitempty"`
	DesiredState   *int32          `json:"desired_state,omitempty"`
	Schedule       json.RawMessage `json:"schedule,omitempty"`
}
