package projectors

import (
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// UserSelectionChangedPayload mirrors the PL/pgSQL projector's
// `selected` handling for the omitted-field case (defaults to
// FALSE), but tightens the non-bool case: a non-bool `selected`
// (e.g. a string or number) makes json.Unmarshal fail and the whole
// event is rejected at the decoder, where the PL/pgSQL projector's
// `COALESCE((event.data->>'selected')::BOOLEAN, FALSE)` would have
// silently coerced it to NULL → FALSE. This is a deliberate
// hardening — malformed payloads should fail loudly, not produce
// silently-defaulted projection rows. Composite-key fields
// (device_id, source_type, source_id) remain required.
type UserSelectionChangedPayload struct {
	ID         string
	DeviceID   string
	SourceType string
	SourceID   string
	Selected   bool
	CreatedBy  string
}

// UserSelectionChangedFromEvent decodes UserSelectionChanged.
func UserSelectionChangedFromEvent(e store.PersistedEvent) (UserSelectionChangedPayload, error) {
	raw, err := decodePayload[struct {
		DeviceID   string `json:"device_id"`
		SourceType string `json:"source_type"`
		SourceID   string `json:"source_id"`
		Selected   *bool  `json:"selected,omitempty"`
	}](e, "user_selection", eventtypes.UserSelectionChanged)
	if err != nil {
		return UserSelectionChangedPayload{}, err
	}
	switch {
	case raw.DeviceID == "":
		return UserSelectionChangedPayload{}, fmt.Errorf("projector: UserSelectionChanged requires device_id")
	case raw.SourceType == "":
		return UserSelectionChangedPayload{}, fmt.Errorf("projector: UserSelectionChanged requires source_type")
	case raw.SourceID == "":
		return UserSelectionChangedPayload{}, fmt.Errorf("projector: UserSelectionChanged requires source_id")
	}
	out := UserSelectionChangedPayload{
		ID:         e.StreamID,
		DeviceID:   raw.DeviceID,
		SourceType: raw.SourceType,
		SourceID:   raw.SourceID,
		CreatedBy:  e.ActorID,
	}
	if raw.Selected != nil {
		out.Selected = *raw.Selected
	}
	return out, nil
}
