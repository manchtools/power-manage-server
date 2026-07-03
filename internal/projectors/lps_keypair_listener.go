package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// LpsKeypairListener returns a store.EventListener that materialises the
// singleton lps_keypair row from LpsKeypairGenerated (#495). Before #495 the
// row was written directly by api.EnsureLpsKeypair (advisory lock + INSERT ON
// CONFLICT DO NOTHING) — the only Postgres state bypassing the event store.
// Now the table is a real projection: the OCC append in EnsureLpsKeypair is
// the sole write path, this listener (and the rebuild target) derive the row.
//
// Single event type, single idempotent upsert — no transaction wrap needed.
//
// Wired in projectors.WireAll; rebuild target "lps_keypair" registers
// ApplyLpsKeypair via RegisterRebuildApply.
func LpsKeypairListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if err := ApplyLpsKeypair(ctx, st.Queries(), e); err != nil {
			logger.Warn("lps_keypair projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "error", err)
		}
	}
}

// ApplyLpsKeypair is the transactional core of the lps_keypair projector.
// The listener wraps it for live-event dispatch; the rebuild path registers
// it via RegisterRebuildApply so RebuildAll re-derives the projection from
// the event store (replay guarantee: 1:1 row reproduction, #495 AC1).
func ApplyLpsKeypair(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "lps_keypair" || e.EventType != string(eventtypes.LpsKeypairGenerated) {
		return nil
	}
	payload, err := LpsKeypairGeneratedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	// created_at: the #495 backfill preserves the pre-event row's timestamp
	// in the payload; a freshly generated keypair omits it and the event's
	// occurred_at is the generation time.
	createdAt := e.OccurredAt
	if payload.CreatedAt != nil {
		createdAt = *payload.CreatedAt
	}
	return q.UpsertLpsKeypair(ctx, db.UpsertLpsKeypairParams{
		PublicKey:     payload.PublicKey,
		PrivateKeyEnc: payload.PrivateKeyEnc,
		CreatedAt:     pgtype.Timestamptz{Time: createdAt, Valid: true},
	})
}
