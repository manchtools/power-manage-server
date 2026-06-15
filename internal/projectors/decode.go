package projectors

import (
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// decodePayload is the single-source projector payload decoder (WS16b). Every
// `*FromEvent` decoder that JSON-decodes a non-empty event payload routes
// through it, replacing the ~100 hand-rolled copies of the same shape:
//
//   - verify the event's (stream_type, event_type); any other event returns
//     ErrIgnoredEvent so the listener wrapper silently no-ops;
//   - reject an empty payload with the canonical "empty <event> payload" error;
//   - json.Unmarshal e.Data into T with the canonical
//     "invalid <event> payload: <err>" wrap.
//
// Per-event field validation (required ids, scope pairing, etc.) stays in the
// caller — only the boilerplate decode is centralized. The
// TestDecodePayloadHelperUsedByAllProjectors guard fails the build if a
// projector decodes a JSON payload without going through this helper.
//
// Decoders whose payload is legitimately allowed to be empty (the event
// carries no body and the projection derives everything from the envelope) do
// NOT use this helper — they handle the empty case explicitly and are recorded
// in that guard's allowlist.
func decodePayload[T any](e store.PersistedEvent, streamType string, eventType eventtypes.EventType) (T, error) {
	var zero T
	if e.StreamType != streamType || e.EventType != string(eventType) {
		return zero, ErrIgnoredEvent
	}
	if len(e.Data) == 0 {
		return zero, fmt.Errorf("projector: empty %s payload", eventType)
	}
	var p T
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return zero, fmt.Errorf("projector: invalid %s payload: %w", eventType, err)
	}
	return p, nil
}
