package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// defaultActionParams mirrors the column default on actions_projection
// (`'{}'::JSONB`) and the PL/pgSQL projector's
// `COALESCE(event.data->'params', '{}')` fallback. Stored as a byte
// slice so the listener can pass it straight to the JSONB column
// without a marshal step.
var defaultActionParams = []byte(`{}`)

// defaultActionTimeoutSeconds mirrors the PL/pgSQL projector's
// `COALESCE((event.data->>'timeout_seconds')::INTEGER, 300)` fallback.
const defaultActionTimeoutSeconds int32 = 300

// ActionCreatedPayload mirrors the fields the deleted PL/pgSQL
// project_action_event() read out of an ActionCreated event.
//
//   - name (required)
//   - description (defaults to "" — column is nullable but the
//     PL/pgSQL projector wrote `event.data->>'description'` directly,
//     which yields NULL on absence; we surface that as the empty
//     pointer)
//   - action_type (required, integer; PL/pgSQL COALESCEd to 0 — we
//     surface a missing key as 0 to match)
//   - desired_state (defaults to 0)
//   - params (defaults to `{}` JSONB)
//   - timeout_seconds (defaults to 300)
//   - is_system (defaults to false)
//   - schedule (no PL/pgSQL default — column is nullable; absent key
//     stays nil bytes which sqlc maps to NULL)
type ActionCreatedPayload struct {
	ID             string
	Name           string
	Description    *string
	ActionType     int32
	DesiredState   int32
	Params         []byte
	TimeoutSeconds int32
	IsSystem       bool
	Schedule       []byte
	CreatedBy      string
}

// ActionCreatedFromEvent decodes ActionCreated. Returns ErrIgnoredEvent
// for any other (stream, event_type) so the listener wrapper can
// silently no-op.
func ActionCreatedFromEvent(e store.PersistedEvent) (ActionCreatedPayload, error) {
	raw, err := decodePayload[payloads.ActionCreated](e, "action", eventtypes.ActionCreated)
	if err != nil {
		return ActionCreatedPayload{}, err
	}
	if raw.Name == "" {
		return ActionCreatedPayload{}, fmt.Errorf("projector: ActionCreated requires name")
	}
	out := ActionCreatedPayload{
		ID:             e.StreamID,
		Name:           raw.Name,
		Description:    raw.Description,
		Params:         defaultActionParams,
		TimeoutSeconds: defaultActionTimeoutSeconds,
		CreatedBy:      e.ActorID,
	}
	if raw.ActionType != nil {
		out.ActionType = *raw.ActionType
	}
	if raw.DesiredState != nil {
		out.DesiredState = *raw.DesiredState
	}
	if len(raw.Params) > 0 {
		out.Params = []byte(raw.Params)
	}
	if raw.TimeoutSeconds != nil {
		out.TimeoutSeconds = *raw.TimeoutSeconds
	}
	if raw.IsSystem != nil {
		out.IsSystem = *raw.IsSystem
	}
	if len(raw.Schedule) > 0 {
		out.Schedule = []byte(raw.Schedule)
	}
	return out, nil
}

// ActionRenamedPayload covers the single mutable field the PL/pgSQL
// projector wrote on an ActionRenamed event. Empty Name is treated as
// a validation error rather than silently no-op'd — the PL/pgSQL
// projector would have written NULL and broken the NOT NULL column
// constraint, so emitters that drop the field hit the same error class
// either way.
type ActionRenamedPayload struct {
	ID   string
	Name string
}

// ActionRenamedFromEvent decodes ActionRenamed.
func ActionRenamedFromEvent(e store.PersistedEvent) (ActionRenamedPayload, error) {
	raw, err := decodePayload[payloads.ActionRenamed](e, "action", eventtypes.ActionRenamed)
	if err != nil {
		return ActionRenamedPayload{}, err
	}
	if raw.Name == "" {
		return ActionRenamedPayload{}, fmt.Errorf("projector: ActionRenamed requires name")
	}
	return ActionRenamedPayload{ID: e.StreamID, Name: raw.Name}, nil
}

// ActionDescriptionUpdatedPayload — the PL/pgSQL projector wrote
// `event.data->>'description'` directly, which can be NULL. We surface
// the same shape via *string so an absent key collapses to NULL and an
// explicit empty string round-trips as "".
type ActionDescriptionUpdatedPayload struct {
	ID          string
	Description *string
}

// ActionDescriptionUpdatedFromEvent decodes ActionDescriptionUpdated.
func ActionDescriptionUpdatedFromEvent(e store.PersistedEvent) (ActionDescriptionUpdatedPayload, error) {
	if e.StreamType != "action" || e.EventType != string(eventtypes.ActionDescriptionUpdated) {
		return ActionDescriptionUpdatedPayload{}, ErrIgnoredEvent
	}
	out := ActionDescriptionUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.ActionDescriptionUpdated
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ActionDescriptionUpdatedPayload{}, fmt.Errorf("projector: invalid ActionDescriptionUpdated payload: %w", err)
	}
	out.Description = raw.Description
	return out, nil
}

// ActionParamsUpdatedPayload — the PL/pgSQL projector used
// `COALESCE(event.data->'params', params)` for params/timeout/desired_state/
// schedule, meaning a missing key preserves the existing column value.
// We model that with pointer/raw-bytes presence: nil means "preserve",
// non-nil means "set to this".
type ActionParamsUpdatedPayload struct {
	ID             string
	Params         []byte
	TimeoutSeconds *int32
	DesiredState   *int32
	Schedule       []byte
}

// ActionParamsUpdatedFromEvent decodes ActionParamsUpdated.
func ActionParamsUpdatedFromEvent(e store.PersistedEvent) (ActionParamsUpdatedPayload, error) {
	if e.StreamType != "action" || e.EventType != string(eventtypes.ActionParamsUpdated) {
		return ActionParamsUpdatedPayload{}, ErrIgnoredEvent
	}
	out := ActionParamsUpdatedPayload{ID: e.StreamID}
	if len(e.Data) == 0 {
		return out, nil
	}
	var raw payloads.ActionParamsUpdated
	if err := json.Unmarshal(e.Data, &raw); err != nil {
		return ActionParamsUpdatedPayload{}, fmt.Errorf("projector: invalid ActionParamsUpdated payload: %w", err)
	}
	if len(raw.Params) > 0 {
		out.Params = []byte(raw.Params)
	}
	out.TimeoutSeconds = raw.TimeoutSeconds
	out.DesiredState = raw.DesiredState
	if len(raw.Schedule) > 0 {
		out.Schedule = []byte(raw.Schedule)
	}
	return out, nil
}

// ActionDeletedFromEvent decodes ActionDeleted. The PL/pgSQL projector
// did not read any payload fields — the cascade derives everything from
// the stream id and the projection's own state — so this is a stream/
// event-type validator only.
func ActionDeletedFromEvent(e store.PersistedEvent) (string, error) {
	if e.StreamType != "action" || e.EventType != string(eventtypes.ActionDeleted) {
		return "", ErrIgnoredEvent
	}
	return e.StreamID, nil
}
