package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// pruneStreamType / pruneStreamID name the singleton retention stream
// the EventLogPruned chain lives on. A dedicated stream keeps prune
// bookkeeping off the domain streams and gives the OCC version a stable
// home.
const (
	pruneStreamType = "retention"
	pruneStreamID   = "global"
)

// EventLogPrunedType is the event-type string appended by PruneEventsUpTo.
// Declared here (not imported from eventtypes) so the store package
// stays free of the eventtypes dependency, matching the rest of the
// append path; the value is pinned to eventtypes.EventLogPruned by a
// guard test.
const EventLogPrunedType = "EventLogPruned"

// PruneEventsUpTo is the ONE sanctioned mutation of the append-only
// event log (spec 19 AC 19). In a single transaction it:
//
//  1. appends the EventLogPruned marker FIRST (so its sequence_num is
//     > upToSeq and it therefore survives this prune and every later
//     one — AC 24);
//  2. sets the transaction-scoped guards the append-only trigger
//     requires (pm.prune_active + pm.prune_up_to_seq);
//  3. DELETEs events with sequence_num <= upToSeq, EXCEPT EventLogPruned
//     markers (the prune chain stays visible in the live log — AC 24).
//
// The trigger (013) independently enforces the FULL double condition:
// the SET LOCAL guard, the range bound (OLD.sequence_num <=
// pm.prune_up_to_seq), the marker exemption, AND an EventLogPruned row
// appended in the same transaction for the same range — so even a raw
// SQL session with the guards set cannot delete history without leaving
// the tamper-evident marker. This method's append-first ordering is what
// satisfies that trigger check. Callers must have durably written the
// sealed archive for upToSeq BEFORE calling this (archive-then-delete
// ordering — AC 28); this method only performs the delete leg.
//
// Returns the number of events deleted.
func (s *Store) PruneEventsUpTo(ctx context.Context, upToSeq int64, archiveRef, archiveSHA256 string) (int64, error) {
	if upToSeq <= 0 {
		return 0, fmt.Errorf("prune: upToSeq must be positive, got %d", upToSeq)
	}
	if archiveRef == "" || archiveSHA256 == "" {
		return 0, fmt.Errorf("prune: archive ref and sha256 are required (archive must land before delete)")
	}

	marker, err := json.Marshal(payloads.EventLogPruned{
		UpToSeq:       upToSeq,
		ArchiveRef:    archiveRef,
		ArchiveSHA256: archiveSHA256,
	})
	if err != nil {
		return 0, fmt.Errorf("prune: marshal EventLogPruned: %w", err)
	}

	var deleted int64
	var appended PersistedEvent
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := s.queries.WithTx(tx)

		// (1) Append the EventLogPruned marker first — it lands with a
		// sequence_num strictly greater than every existing event, so
		// the DELETE below (and any future prune) leaves it in place.
		version, verr := q.GetStreamVersion(ctx, generated.GetStreamVersionParams{
			StreamType: pruneStreamType, StreamID: pruneStreamID,
		})
		if verr != nil {
			return fmt.Errorf("prune: get retention stream version: %w", verr)
		}
		row, aerr := q.AppendEvent(ctx, generated.AppendEventParams{
			ID:            ulid.Make().String(),
			StreamType:    pruneStreamType,
			StreamID:      pruneStreamID,
			StreamVersion: version + 1,
			EventType:     EventLogPrunedType,
			Data:          marker,
			Metadata:      []byte("{}"),
			ActorType:     "system",
			ActorID:       "retention",
		})
		if aerr != nil {
			return fmt.Errorf("prune: append EventLogPruned: %w", aerr)
		}
		appended = row

		// (2) Set the transaction-scoped guards the append-only trigger
		// checks. SET LOCAL is auto-cleared at COMMIT/ROLLBACK, so it
		// never leaks to the next pooled checkout.
		if _, err := tx.Exec(ctx, `SELECT set_config('pm.prune_active', 'on', true)`); err != nil {
			return fmt.Errorf("prune: set guard: %w", err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('pm.prune_up_to_seq', $1, true)`, strconv.FormatInt(upToSeq, 10)); err != nil {
			return fmt.Errorf("prune: set range guard: %w", err)
		}

		// (3) Delete history ≤ N, EXCEPT the EventLogPruned chain.
		tag, derr := tx.Exec(ctx,
			`DELETE FROM events WHERE sequence_num <= $1 AND event_type <> $2`,
			upToSeq, EventLogPrunedType)
		if derr != nil {
			return fmt.Errorf("prune: delete events ≤ %d: %w", upToSeq, derr)
		}
		deleted = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, err
	}
	s.fireListeners(ctx, appended)
	return deleted, nil
}

// PruneCheckpointBefore returns the highest sequence_num whose event
// occurred before cutoff — the prune checkpoint N (spec 19). Returns 0
// when no event is older than the cutoff (the no-op case, AC 25).
// EventLogPruned markers are excluded: they are retention bookkeeping,
// never themselves a prune boundary, and are exempt from pruning.
//
// Commit-visibility contract: sequence_num is a plain nextval() sequence
// (assigned pre-commit, NOT commit-order-safe), so a not-yet-committed
// append can hold a lower, invisible sequence_num. The caller MUST pass a
// cutoff old enough that every event before it has certainly committed —
// the retention worker enforces this with pruneSafetyMargin (occurred_at,
// ≈ transaction start, must be older than max(window, 1h); no append
// transaction stays open that long). Without that floor the returned N
// could straddle an in-flight lower sequence_num, and the downstream
// DELETE (which filters on sequence_num alone) could remove an event that
// StreamEventsUpTo never archived.
func (s *Store) PruneCheckpointBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(sequence_num), 0) FROM events
		  WHERE occurred_at < $1 AND event_type <> $2`,
		cutoff, EventLogPrunedType).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("prune: choose checkpoint before %s: %w", cutoff, err)
	}
	return n, nil
}

// ListPruneMarkers returns every EventLogPruned marker in the live log in
// sequence order — the authoritative ledger of what was pruned when,
// where each range's sealed archive lives, and the hash it must match.
// Markers are exempt from pruning (AC 24), so the chain is always
// complete; the archive-restore path walks it to load the FULL pruned
// history (a single later archive no longer contains earlier ranges).
func (s *Store) ListPruneMarkers(ctx context.Context) ([]payloads.EventLogPruned, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT data FROM events WHERE event_type = $1 ORDER BY sequence_num`,
		EventLogPrunedType)
	if err != nil {
		return nil, fmt.Errorf("prune: list markers: %w", err)
	}
	defer rows.Close()
	var out []payloads.EventLogPruned
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("prune: scan marker: %w", err)
		}
		var m payloads.EventLogPruned
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("prune: decode marker: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// StreamEventsUpTo calls fn with every event (sequence_num <= upToSeq)
// as a to_jsonb row, in sequence order — the archive payload. Streams
// row-by-row so a large history is never fully buffered.
func (s *Store) StreamEventsUpTo(ctx context.Context, upToSeq int64, fn func(json.RawMessage) error) error {
	rows, err := s.pool.Query(ctx,
		`SELECT to_jsonb(e) FROM events e WHERE sequence_num <= $1 ORDER BY sequence_num`,
		upToSeq)
	if err != nil {
		return fmt.Errorf("prune: stream events ≤ %d: %w", upToSeq, err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return fmt.Errorf("prune: scan archived event: %w", err)
		}
		if err := fn(json.RawMessage(raw)); err != nil {
			return err
		}
	}
	return rows.Err()
}
