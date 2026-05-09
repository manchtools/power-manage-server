// Package projectors hosts pure functions that derive projection-row
// shapes from PersistedEvents, plus the post-commit listeners that
// apply those shapes to the database.
//
// The split between "pure derivation" and "DB-side application" is
// deliberate: handlers building immediate API responses call the
// pure function on the freshly-appended event to produce the
// response in memory, while the post-commit listener calls the
// SAME pure function and writes the result to the projection. By
// construction the two cannot diverge — they're the same function
// applied to the same event — so the read-back gap (post-commit
// projection write hasn't landed yet) is invisible to the caller
// that wrote the event.
//
// First scope ported under this pattern is `security_alert` (#96).
// Subsequent ports (#97–#106) follow the same shape: one file per
// stream type with pure derivation funcs + a Listener registration.
//
// Refs tracker #107.
package projectors

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ErrIgnoredEvent signals that the projector saw an event it does
// not care about (wrong stream_type or wrong event_type combo). The
// listener wrapper uses it to silently no-op on every other event
// in the stream without polluting the warning log.
var ErrIgnoredEvent = errors.New("projector: event ignored")

// SecurityAlertProjectionFromEvent returns the projection row that
// `SecurityAlert` event implies. Returns ErrIgnoredEvent for any
// other event type so callers can use the same function for the
// dispatcher's "should I do anything?" check.
//
// Pure: no I/O, deterministic, depends only on the event's fields.
// Test it directly without a database. Reuse it from a handler that
// wants to render the alert immediately while the listener writes
// to the DB asynchronously.
func SecurityAlertProjectionFromEvent(e store.PersistedEvent) (db.InsertSecurityAlertProjectionParams, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.SecurityAlert) {
		return db.InsertSecurityAlertProjectionParams{}, ErrIgnoredEvent
	}

	var data struct {
		AlertType string          `json:"alert_type"`
		Message   string          `json:"message"`
		Details   json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return db.InsertSecurityAlertProjectionParams{},
			fmt.Errorf("projector: invalid SecurityAlert payload: %w", err)
	}

	// Details is a free-form JSONB blob; preserve whatever shape the
	// emitter sent. The deleted PL/pgSQL projector stored
	// `event.data->'details'` directly; json.RawMessage gives us the
	// same byte-preservation contract on the Go side.
	return db.InsertSecurityAlertProjectionParams{
		EventID:   e.ID,
		DeviceID:  e.StreamID,
		AlertType: data.AlertType,
		Message:   data.Message,
		Details:   []byte(data.Details),
		RaisedAt:  e.OccurredAt,
	}, nil
}

// SecurityAlertAckParamsFromEvent returns the parameters needed to
// apply a `SecurityAlertAcknowledged` event to the projection.
// Same purity contract as SecurityAlertProjectionFromEvent.
//
// alert_id arrives as a string in the event data and must round-trip
// to a UUID for the WHERE clause to hit the primary-key index. A
// malformed UUID is propagated as a validation error rather than
// silently full-scanning and matching nothing — matches the deleted
// PL/pgSQL projector's `(event.data->>'alert_id')::uuid` behaviour.
func SecurityAlertAckParamsFromEvent(e store.PersistedEvent) (db.AcknowledgeSecurityAlertProjectionParams, error) {
	if e.StreamType != "device" || e.EventType != string(eventtypes.SecurityAlertAcknowledged) {
		return db.AcknowledgeSecurityAlertProjectionParams{}, ErrIgnoredEvent
	}

	var data struct {
		AlertID        string `json:"alert_id"`
		AcknowledgedBy string `json:"acknowledged_by"`
	}
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return db.AcknowledgeSecurityAlertProjectionParams{},
			fmt.Errorf("projector: invalid SecurityAlertAcknowledged payload: %w", err)
	}

	alertID, err := uuid.Parse(data.AlertID)
	if err != nil {
		return db.AcknowledgeSecurityAlertProjectionParams{},
			fmt.Errorf("projector: invalid alert_id %q in SecurityAlertAcknowledged: %w", data.AlertID, err)
	}

	occurredAt := e.OccurredAt
	ackBy := data.AcknowledgedBy
	return db.AcknowledgeSecurityAlertProjectionParams{
		Column1:        alertID,
		AcknowledgedAt: &occurredAt,
		AcknowledgedBy: &ackBy,
	}, nil
}
