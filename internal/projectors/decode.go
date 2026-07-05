package projectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/pii"
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

// PIIOpener decrypts sealed pii:"true" fields on a decoded wire
// payload, in place. Implemented by internal/pii.Opener; wired at boot
// via SetPIIOpener alongside WireAll (the interface lives here to keep
// projectors free of a pii-package dependency).
type PIIOpener interface {
	OpenDecoded(ctx context.Context, streamType, streamID string, payload any) error
}

// piiOpener is boot-once wiring state, same posture as the store's
// listener registry. Nil is tolerated ONLY while no sealed PII exists
// (fresh boot paths, tests that never mint DEKs) — decodePayloadPII
// fails loudly if ciphertext shows up with no opener wired, so a
// mis-wired deployment can never silently project ciphertext.
var piiOpener PIIOpener

// SetPIIOpener wires the PII opener (spec 19). Call at boot, before
// any projection traffic.
func SetPIIOpener(o PIIOpener) { piiOpener = o }

// decodePayloadPII is decodePayload for PII-bearing payload types:
// after the JSON decode it opens sealed fields under the subject's
// DEK (spec 19 AC 4). Needs the caller's ctx for the key lookup —
// which is why the PII-bearing *FromEvent decoders take a ctx while
// the rest of the projector surface stays context-free.
//
// The AC 9/10 split is handled HERE, not bubbled to callers:
//   - subject's DEK gone (pii.ErrErased) → the tagged fields collapse
//     to the redaction sentinel and decode SUCCEEDS (the graceful
//     erased state — replaying a PII event for a shredded user must
//     project the sentinel, never abort);
//   - any other open failure (unwrappable DEK, tampered ciphertext) →
//     a hard error that aborts the projection/rebuild.
func decodePayloadPII[T any](ctx context.Context, e store.PersistedEvent, streamType string, eventType eventtypes.EventType) (T, error) {
	p, err := decodePayload[T](e, streamType, eventType)
	if err != nil {
		return p, err
	}
	if err := openSealedPII(ctx, e, &p); err != nil {
		var zero T
		return zero, err
	}
	return p, nil
}

// openSealedPII opens sealed fields on an already-decoded wire payload
// (pointer). Shared by decodePayloadPII and the empty-tolerant custom
// decoders that cannot route through it. On pii.ErrErased it redacts
// in place and returns nil (AC 9); any other failure propagates.
func openSealedPII(ctx context.Context, e store.PersistedEvent, payload any) error {
	if !crypto.HasSealedPII(payload) {
		return nil // legacy plaintext / factory-seeded events need no DEK
	}
	if piiOpener == nil {
		return fmt.Errorf("projector: %s carries sealed PII but no PII opener is wired (SetPIIOpener at boot) — refusing to project ciphertext", e.EventType)
	}
	if err := piiOpener.OpenDecoded(ctx, e.StreamType, e.StreamID, payload); err != nil {
		if errors.Is(err, pii.ErrErased) {
			// Subject crypto-shredded: the sealed value is
			// unrecoverable BY DESIGN. Project the sentinel and
			// complete (AC 9) rather than abort a live projection or
			// a full rebuild.
			if rerr := crypto.RedactPayloadPII(payload); rerr != nil {
				return fmt.Errorf("projector: %s: redact erased PII: %w", e.EventType, rerr)
			}
			return nil
		}
		return fmt.Errorf("projector: %s: %w", e.EventType, err)
	}
	return nil
}
