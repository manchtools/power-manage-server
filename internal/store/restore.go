package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RebuildAllFromArchive rebuilds every projection from a retention
// archive plus the live log: it replays the archived events ≤ N (the
// pruned history, handed in as a sequence-ordered slice) and then the
// live events > N, through the same appliers, in one transaction (spec 19
// AC 21). N is the archive's checkpoint — the highest sequence_num among
// the archived events.
//
// This is the recovery path after a retention prune has deleted events
// ≤ N from the live `events` table: the pruned history survives only in
// the cold archive as CIPHERTEXT events, so restore replays it rather
// than loading a materialized projection. Because the appliers decrypt
// PII through the per-user DEK on the way in, a user whose DEK has been
// crypto-shredded reproduces as the redaction sentinel — erasure is
// honored across restore, and the archive never holds plaintext PII
// (spec 19 AC 21a; "cold archives hold only ciphertext PII").
//
// Full-fidelity contract (AC 17): restore(archived ≤ N) + replay(> N)
// reproduces byte-identical projection state to a RebuildAll run before
// the prune — proven by the full-row round-trip test.
//
// Memory: the archived slice is held in full for the duration of the
// rebuild. ponytail: whole-archive-in-memory; stream per-target from the
// ArchiveStore if a single prune's history ever outgrows RAM (restore is
// a rare, operator-invoked recovery, so one load is acceptable for v1).
func (s *Store) RebuildAllFromArchive(ctx context.Context, archived []PersistedEvent) (RebuildResult, error) {
	var upToSeq int64
	for _, e := range archived {
		if e.SequenceNum > upToSeq {
			upToSeq = e.SequenceNum
		}
	}

	start := s.now()
	result := RebuildResult{Targets: make([]TargetResult, 0, len(AllRebuildTargets))}

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Completeness (spec 19 AC 21): the live marker chain is the
		// authoritative ledger of what was pruned. The archived slice must
		// reach at least the LATEST recorded checkpoint — a later archive
		// alone no longer contains events ≤ an earlier N (they were
		// already deleted when it was written), and a stale earlier
		// archive misses (N_old, N_latest]. Refuse rather than restore
		// with a silent hole. Checked in-tx, before any TRUNCATE.
		var latestMarker int64
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX((data->>'up_to_seq')::bigint), 0) FROM events WHERE event_type = $1`,
			EventLogPrunedType).Scan(&latestMarker); err != nil {
			return fmt.Errorf("restore: read prune marker chain: %w", err)
		}
		if latestMarker > upToSeq {
			return fmt.Errorf("restore: archived history (≤ %d) does not cover the latest prune checkpoint %d — chain ALL retention archives per the EventLogPruned markers, not a single artifact", upToSeq, latestMarker)
		}

		for _, t := range AllRebuildTargets {
			tStart := s.now()
			applied, skipped, runErr := s.restoreOneTarget(ctx, tx, t, archived, upToSeq)
			if runErr != nil {
				return fmt.Errorf("restore target %q: %w", t.Name, runErr)
			}
			result.Targets = append(result.Targets, TargetResult{
				Name:          t.Name,
				EventsApplied: applied,
				Skipped:       skipped,
				Duration:      s.now().Sub(tStart),
			})
		}
		return nil
	})
	if err != nil {
		return RebuildResult{}, err
	}

	result.TotalDuration = s.now().Sub(start)
	return result, nil
}

// restoreOneTarget truncates + re-seeds a target then replays, in strict
// sequence order, the archived events ≤ N (from the slice) followed by
// the live events > N (from the events table). archived ≤ N < live > N,
// so concatenation preserves global sequence order for the applier.
//
// Boundary: applyEvents replays the whole archived slice, INCLUDING the
// event at sequence_num == N (upToSeq is the archive checkpoint, the max
// archived seq). dispatchViaGoApplier's fromSeq is EXCLUSIVE — its query
// filters `sequence_num > fromSeq` — so passing upToSeq replays strictly
// > N and event N is applied exactly once. An inclusive lower bound would
// double-apply N; the byte-identical fidelity test (AC 17) is the standing
// guard that this boundary stays exclusive.
func (s *Store) restoreOneTarget(ctx context.Context, tx pgx.Tx, t rebuildTarget, archived []PersistedEvent, upToSeq int64) (applied, skipped int64, err error) {
	apply := s.rebuildApplyFor(t.Name)
	if apply == nil {
		return 0, 0, fmt.Errorf("rebuild target %q has no Go applier registered (projectors.WireAll wiring may have drifted)", t.Name)
	}
	if err := s.truncateAndSeed(ctx, tx, t); err != nil {
		return 0, 0, err
	}
	a1, s1, err := s.applyEvents(ctx, tx, t, apply, archived) // archived ≤ N, includes N
	if err != nil {
		return 0, 0, err
	}
	a2, s2, err := s.dispatchViaGoApplier(ctx, tx, t, apply, upToSeq, 0) // live, sequence_num > N (fromSeq exclusive)
	if err != nil {
		return 0, 0, err
	}
	return a1 + a2, s1 + s2, nil
}

// DecodeArchivedEvents turns the archived event rows produced by
// StreamEventsUpTo / the retention artifact (each a to_jsonb(events) row)
// back into PersistedEvents ready to replay. The jsonb `data`/`metadata`
// columns arrive as inline JSON objects, so they are decoded as raw JSON
// (a plain []byte target would expect base64) and carried through
// verbatim.
func DecodeArchivedEvents(rows []json.RawMessage) ([]PersistedEvent, error) {
	out := make([]PersistedEvent, 0, len(rows))
	for i, raw := range rows {
		var r archivedEventRow
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("restore: decode archived event %d: %w", i, err)
		}
		out = append(out, PersistedEvent{
			ID:            r.ID,
			SequenceNum:   r.SequenceNum,
			StreamType:    r.StreamType,
			StreamID:      r.StreamID,
			StreamVersion: r.StreamVersion,
			EventType:     r.EventType,
			Data:          []byte(r.Data),
			Metadata:      []byte(r.Metadata),
			ActorType:     r.ActorType,
			ActorID:       r.ActorID,
			OccurredAt:    r.OccurredAt,
		})
	}
	return out, nil
}

// archivedEventRow mirrors the events table columns for decoding a
// to_jsonb(events) row. data/metadata are jsonb, serialized inline as
// JSON objects (not base64), so they must decode as RawMessage.
type archivedEventRow struct {
	ID            string          `json:"id"`
	SequenceNum   int64           `json:"sequence_num"`
	StreamType    string          `json:"stream_type"`
	StreamID      string          `json:"stream_id"`
	StreamVersion int32           `json:"stream_version"`
	EventType     string          `json:"event_type"`
	Data          json.RawMessage `json:"data"`
	Metadata      json.RawMessage `json:"metadata"`
	ActorType     string          `json:"actor_type"`
	ActorID       string          `json:"actor_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
}
