// Package retention runs the spec-19 rolling snapshot + prune of the
// event log: it chooses a checkpoint N older than the configured
// window, captures the projection state @ N, seals {snapshot,
// events ≤ N} into a cold archive through an ArchiveStore, and then —
// only after the archive durably lands — deletes events ≤ N via the
// store's privileged prune path (which records an EventLogPruned
// marker in the same transaction).
//
// The worker is advisory-lock single-flighted (one replica prunes, the
// others skip), non-re-entrant, and crash-resume idempotent: a crash
// after the archive lands but before the delete re-runs cleanly at the
// same checkpoint.
package retention

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/store"
)

// advisoryKeyPrune is the cross-replica single-flight key for the prune
// worker ("prune" in hex). Distinct from the admin-mutation and
// dynamic-group keys.
const advisoryKeyPrune int64 = 0x7072756e65

// pruneSafetyMargin is a hard floor on how recent the prune checkpoint may
// be, independent of the configured Window. It closes a sequence-visibility
// race: events.sequence_num is a plain nextval() sequence (assigned before
// commit, so NOT commit-order-safe) and occurred_at defaults to now() (the
// transaction's START time). An append transaction that called nextval()
// but has not yet committed holds a lower, still-invisible sequence_num; if
// the checkpoint could reach it, StreamEventsUpTo would not archive it yet
// PruneEventsUpTo's later DELETE (which filters on sequence_num alone) could
// remove it once it commits — deleting an un-archived event and breaking the
// archive-before-delete guarantee.
//
// The checkpoint only includes events whose occurred_at (≈ transaction
// start) is older than max(Window, this margin) ago. No append transaction
// stays open for an hour (appends are sub-second), so every event at or
// below the checkpoint has long committed and is visible — the race is
// unreachable regardless of how small Window is configured. Days/months
// windows dominate this floor, so it is invisible in normal operation.
const pruneSafetyMargin = time.Hour

// Config parameterizes a prune run.
type Config struct {
	// Window is the retention window: events OLDER than now-Window are
	// eligible to prune. The checkpoint N is the highest sequence_num
	// whose occurred_at is before the cutoff.
	Window time.Duration
}

// Worker prunes the event log on demand (called on a schedule by the
// caller). It holds no goroutine itself — Prune is invoked per tick.
type Worker struct {
	store   *store.Store
	archive archive.ArchiveStore
	cfg     Config
	logger  *slog.Logger
	now     func() time.Time
}

// NewWorker builds a prune worker. archive is the sealed cold-storage
// backend; a nil archive is refused (an unarchived prune would be data
// loss).
func NewWorker(st *store.Store, arch archive.ArchiveStore, cfg Config, logger *slog.Logger) (*Worker, error) {
	if st == nil {
		return nil, fmt.Errorf("retention: store is required")
	}
	if arch == nil {
		return nil, fmt.Errorf("retention: archive store is required (an unarchived prune is data loss)")
	}
	if cfg.Window <= 0 {
		return nil, fmt.Errorf("retention: window must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{store: st, archive: arch, cfg: cfg, logger: logger, now: time.Now}, nil
}

// SetNowForTest overrides the worker's clock so a test can make seeded
// events prune-eligible under a positive retention window (advancing
// "now" past the events' occurred_at) without a negative window, which
// production config validation rightly forbids.
func (w *Worker) SetNowForTest(now func() time.Time) { w.now = now }

// PruneResult reports one prune run.
type PruneResult struct {
	Ran           bool   // false if another replica held the lock (single-flight skip)
	Pruned        bool   // false on a no-op run (nothing older than the window)
	Checkpoint    int64  // the chosen sequence_num N (0 if no-op)
	EventsDeleted int64  // events removed from the live log
	ArchiveRef    string // the sealed artifact's ref (empty on no-op)
}

// Prune runs one prune cycle under the single-flight lock. AC 25 (no-op
// when nothing is older than the window), AC 27 (single-flight —
// another replica's concurrent call returns Ran=false), AC 28
// (archive-then-delete: the archive is sealed and durable BEFORE any
// event is deleted). Returns Ran=false with no error when another
// replica holds the lock.
func (w *Worker) Prune(ctx context.Context) (PruneResult, error) {
	var res PruneResult
	ran, err := w.store.TryWithAdvisoryLock(ctx, advisoryKeyPrune, func() error {
		var perr error
		res, perr = w.pruneLocked(ctx)
		return perr
	})
	if err != nil {
		return PruneResult{}, err
	}
	res.Ran = ran
	if !ran {
		w.logger.Debug("retention: prune already running on another replica; skipping")
	}
	return res, nil
}

// pruneLocked is the prune cycle body, run under the advisory lock.
func (w *Worker) pruneLocked(ctx context.Context) (PruneResult, error) {
	// Never let the checkpoint reach events younger than the safety margin,
	// even if Window is configured smaller — see pruneSafetyMargin for the
	// sequence-visibility race this closes.
	cutoff := w.now().Add(-w.cfg.Window)
	if floor := w.now().Add(-pruneSafetyMargin); cutoff.After(floor) {
		cutoff = floor
	}
	checkpoint, err := w.store.PruneCheckpointBefore(ctx, cutoff)
	if err != nil {
		return PruneResult{}, fmt.Errorf("retention: choose checkpoint: %w", err)
	}
	if checkpoint == 0 {
		// AC 25 — nothing older than the window: no archive, no delete,
		// no EventLogPruned.
		w.logger.Debug("retention: no events older than the window; nothing to prune")
		return PruneResult{Pruned: false}, nil
	}

	// AC 16/18/21a — the snapshot IS the archived ciphertext events ≤ N:
	// serialize {events ≤ N} into one artifact and seal it in the archive.
	// Replaying them reproduces state @ N deterministically (proven by the
	// full-fidelity round-trip, AC 17), and because they carry PII as
	// DEK-sealed ciphertext the archive never holds plaintext PII and a
	// crypto-shredded user restores as the redaction sentinel. Crash-resume
	// idempotent (AC 26): the ref is deterministic in N, so re-running at
	// the same checkpoint overwrites the same artifact rather than orphaning
	// a duplicate.
	ref := fmt.Sprintf("prune-%020d", checkpoint)
	// Stream the artifact straight into the archive through a pipe: the
	// events are gzip-encoded and written as they are read from the DB,
	// never materializing the whole (potentially hundreds-of-MB) blob in
	// RAM — the ArchiveStore.Put streaming contract the spec is built on.
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(w.writeArtifact(ctx, pw, checkpoint)) }()
	info, err := w.archive.Put(ctx, ref, pr)
	// If Put stopped reading early (its own error), unblock the writer
	// goroutine's next Write so it cannot leak; a no-op once pr is at EOF.
	_ = pr.CloseWithError(err)
	if err != nil {
		return PruneResult{}, fmt.Errorf("retention: seal archive %s: %w", ref, err)
	}

	// AC 28 — only now, after the sealed archive has durably landed,
	// delete events ≤ N (the store appends EventLogPruned in the same tx).
	deleted, err := w.store.PruneEventsUpTo(ctx, checkpoint, info.Ref, info.SHA256)
	if err != nil {
		return PruneResult{}, fmt.Errorf("retention: prune events ≤ %d: %w", checkpoint, err)
	}
	w.logger.Info("retention: pruned event log",
		"checkpoint", checkpoint, "events_deleted", deleted, "archive_ref", info.Ref)
	return PruneResult{
		Pruned:        true,
		Checkpoint:    checkpoint,
		EventsDeleted: deleted,
		ArchiveRef:    info.Ref,
	}, nil
}

// writeArtifact streams the archived events ≤ N to dst as a gzip'd
// JSON-lines blob: a header line ({version, up_to_seq}) then one raw
// event row (to_jsonb) per line. Events are encoded as StreamEventsUpTo
// yields them, so memory stays bounded regardless of backlog size (the
// spec's streaming ArchiveStore contract). The events carry PII as
// DEK-sealed ciphertext, so the artifact holds no plaintext PII (spec 19).
// Independently replayable offline for out-of-band audit or restore
// (AC 21/22) — no live system, no projection dump.
func (w *Worker) writeArtifact(ctx context.Context, dst io.Writer, upToSeq int64) error {
	gz := gzip.NewWriter(dst)
	enc := json.NewEncoder(gz)

	if err := enc.Encode(artifactHeader{Version: 1, UpToSeq: upToSeq}); err != nil {
		return fmt.Errorf("retention: encode artifact header: %w", err)
	}
	if err := w.store.StreamEventsUpTo(ctx, upToSeq, func(raw json.RawMessage) error {
		return enc.Encode(archivedEvent{Event: raw})
	}); err != nil {
		return fmt.Errorf("retention: encode archived events: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("retention: finalize artifact: %w", err)
	}
	return nil
}

type artifactHeader struct {
	Version int   `json:"version"`
	UpToSeq int64 `json:"up_to_seq"`
}

type archivedEvent struct {
	Event json.RawMessage `json:"event"`
}

// ReadArtifact deserializes an artifact produced by buildArtifact,
// returning the checkpoint N and the archived events (each a to_jsonb
// event row) in sequence order. It needs nothing but the artifact bytes
// — the archive is independently replayable for out-of-band audit
// without the live system (spec 19 AC 22), and it is the read leg of the
// restore path: after a prune, restore fetches the latest archive, passes
// these rows through store.DecodeArchivedEvents, and replays them ahead
// of the live events > N via store.RebuildAllFromArchive.
func ReadArtifact(r io.Reader) (upToSeq int64, events []json.RawMessage, err error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, nil, fmt.Errorf("retention: open artifact: %w", err)
	}
	defer gz.Close()
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<26) // tolerate large event rows

	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return 0, nil, fmt.Errorf("retention: read header: %w", err)
		}
		return 0, nil, fmt.Errorf("retention: artifact missing header")
	}
	var hdr artifactHeader
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
		return 0, nil, fmt.Errorf("retention: decode header: %w", err)
	}
	for sc.Scan() {
		var ev archivedEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return 0, nil, fmt.Errorf("retention: decode archived event: %w", err)
		}
		events = append(events, ev.Event)
	}
	if err := sc.Err(); err != nil {
		return 0, nil, fmt.Errorf("retention: scan artifact: %w", err)
	}
	return hdr.UpToSeq, events, nil
}
