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

	// REPEATABLE READ for the same reason as RebuildAll: the completeness
	// check and the per-target live-event reads (> N) must share one
	// snapshot, or a prune committing mid-restore could delete live events
	// after the check passed and leave a silent gap.
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		// Completeness (spec 19 AC 21): the live marker chain is the
		// authoritative ledger of what was pruned, and the slice must be
		// the FULL chain, not one artifact. Two checks, in-tx, before any
		// TRUNCATE:
		//
		//  1. The slice reaches the LATEST checkpoint — a stale earlier
		//     archive misses (N_old, N_latest].
		//  2. The slice contains EVERY marker's checkpoint event (the
		//     event with sequence_num == up_to_seq). That event exists in
		//     exactly ONE archive — its own: it is non-marker (checkpoint
		//     selection excludes markers), it was deleted by its own prune,
		//     so every LATER archive was written after it left the live
		//     log. A latest-archive-only slice reaches N_latest (passes
		//     check 1) yet misses every earlier range — check 2 refuses it.
		rows, err := tx.Query(ctx,
			`SELECT (data->>'up_to_seq')::bigint FROM events WHERE event_type = $1 ORDER BY sequence_num`,
			EventLogPrunedType)
		if err != nil {
			return fmt.Errorf("restore: read prune marker chain: %w", err)
		}
		var checkpoints []int64
		for rows.Next() {
			var n int64
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return fmt.Errorf("restore: scan marker checkpoint: %w", err)
			}
			checkpoints = append(checkpoints, n)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("restore: iterate marker chain: %w", err)
		}

		haveSeq := make(map[int64]bool, len(archived))
		for _, e := range archived {
			haveSeq[e.SequenceNum] = true
		}
		for _, cp := range checkpoints {
			if cp > upToSeq {
				return fmt.Errorf("restore: archived history (≤ %d) does not cover the latest prune checkpoint %d — chain ALL retention archives per the EventLogPruned markers, not a single artifact", upToSeq, cp)
			}
			if !haveSeq[cp] {
				return fmt.Errorf("restore: archived history is missing the checkpoint event for prune marker %d — that event exists only in that range's own archive, so the slice is not the full marker chain (a latest archive alone does not contain earlier pruned ranges)", cp)
			}
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
