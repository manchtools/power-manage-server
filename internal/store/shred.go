package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// AppendUserDeletionWithShred is the shared delete-with-shred flow
// (spec 19 AC 7/8/14). It appends the caller's UserDeleted event AND
// destroys the subject's DEK in ONE transaction — all-or-nothing:
//
//   - AC 7: deletion always crypto-shreds; there is no separate erase.
//   - AC 8: both the API DeleteUser and the SCIM delete path call this,
//     so the shred is identical across packages.
//   - AC 14: if the DEK delete fails, the transaction rolls back — no
//     UserDeleted event, no projection change, no half-erased state.
//
// event.StreamID is the user being deleted (and whose DEK is shredded).
// Post-commit listeners fire AFTER the tx commits, exactly as
// AppendEvent does, so the UserDeleted projector (soft-delete +
// PII-column redaction) runs on the durable event.
//
// Idempotent (AC 13): re-running for an already-deleted user still
// appends a UserDeleted event (harmless — the projector's
// projection_version guard no-ops the stale replay) and the DEK delete
// reports zero rows without error, so the DEK stays absent.
func (s *Store) AppendUserDeletionWithShred(ctx context.Context, event Event) error {
	if event.StreamType != "user" {
		return fmt.Errorf("shred flow: event must be on the user stream, got %q", event.StreamType)
	}
	if event.StreamID == "" {
		return fmt.Errorf("shred flow: event requires a stream_id (the user to shred)")
	}
	if event.ActorType == "" || event.ActorID == "" {
		return fmt.Errorf("shred flow: event actor_type and actor_id are required")
	}

	// UserDeleted carries no PII, but seal for generality (no-op when
	// the payload has no tagged fields).
	event, err := s.sealPII(ctx, event)
	if err != nil {
		return fmt.Errorf("shred flow: seal PII: %w", err)
	}
	data, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("shred flow: marshal event data: %w", err)
	}
	metadata := []byte("{}")
	if event.Metadata != nil {
		if metadata, err = json.Marshal(event.Metadata); err != nil {
			return fmt.Errorf("shred flow: marshal event metadata: %w", err)
		}
	}

	const maxRetries = 5
	for i := 0; i < maxRetries; i++ {
		var appended PersistedEvent
		conflict := false
		err := s.WithTx(ctx, func(q *Queries) error {
			version, verr := q.GetStreamVersion(ctx, generated.GetStreamVersionParams{
				StreamType: event.StreamType,
				StreamID:   event.StreamID,
			})
			if verr != nil {
				return fmt.Errorf("get stream version: %w", verr)
			}
			row, aerr := q.AppendEvent(ctx, generated.AppendEventParams{
				ID:            ulid.Make().String(),
				StreamType:    event.StreamType,
				StreamID:      event.StreamID,
				StreamVersion: version + 1,
				EventType:     event.EventType,
				Data:          data,
				Metadata:      metadata,
				ActorType:     event.ActorType,
				ActorID:       event.ActorID,
			})
			if aerr != nil {
				if IsVersionConflict(aerr) {
					conflict = true
				}
				return fmt.Errorf("append UserDeleted: %w", aerr)
			}
			// THE crypto-shred, in the SAME transaction (AC 7/14). A
			// failure here rolls the UserDeleted append back too.
			if _, derr := q.DeleteUserEncryptionKey(ctx, event.StreamID); derr != nil {
				return fmt.Errorf("shred DEK: %w", derr)
			}
			appended = row
			return nil
		})
		if err == nil {
			// Post-commit listeners (projector redaction, search index)
			// run only after the event is durable — same contract as
			// AppendEvent.
			s.fireListeners(ctx, appended)
			return nil
		}
		if conflict && i < maxRetries-1 {
			continue // OCC retry; the DEK delete is idempotent
		}
		return err
	}
	return fmt.Errorf("shred flow: exhausted retries appending UserDeleted for %s", event.StreamID)
}
