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
	"bytes"
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
	cutoff := w.now().Add(-w.cfg.Window)
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

	// AC 16/17 — capture state @ N (deterministic replay of events ≤ N,
	// live projection untouched).
	snap, err := w.store.CaptureProjectionSnapshot(ctx, checkpoint)
	if err != nil {
		return PruneResult{}, fmt.Errorf("retention: capture snapshot @ %d: %w", checkpoint, err)
	}

	// Serialize {snapshot, events ≤ N} into one artifact and seal it in
	// the archive. Crash-resume idempotent (AC 26): the ref is
	// deterministic in N, so re-running at the same checkpoint overwrites
	// the same artifact rather than orphaning a duplicate.
	ref := fmt.Sprintf("prune-%020d", checkpoint)
	artifact, err := w.buildArtifact(ctx, snap, checkpoint)
	if err != nil {
		return PruneResult{}, err
	}
	info, err := w.archive.Put(ctx, ref, bytes.NewReader(artifact))
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

// buildArtifact serializes {snapshot, events ≤ N} as a gzip'd
// JSON-lines blob: a header line with the snapshot, then one line per
// archived event. Independently replayable offline (AC 22).
func (w *Worker) buildArtifact(ctx context.Context, snap store.Snapshot, upToSeq int64) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)

	if err := enc.Encode(artifactHeader{Version: 1, UpToSeq: upToSeq, Snapshot: snap}); err != nil {
		return nil, fmt.Errorf("retention: encode snapshot header: %w", err)
	}
	if err := w.store.StreamEventsUpTo(ctx, upToSeq, func(raw json.RawMessage) error {
		return enc.Encode(archivedEvent{Event: raw})
	}); err != nil {
		return nil, fmt.Errorf("retention: encode archived events: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("retention: finalize artifact: %w", err)
	}
	return buf.Bytes(), nil
}

type artifactHeader struct {
	Version  int            `json:"version"`
	UpToSeq  int64          `json:"up_to_seq"`
	Snapshot store.Snapshot `json:"snapshot"`
}

type archivedEvent struct {
	Event json.RawMessage `json:"event"`
}

// ReadArtifact deserializes an artifact produced by buildArtifact,
// returning the snapshot header and the archived events in sequence
// order. It needs nothing but the artifact bytes — the archive is
// independently replayable for out-of-band audit without the live
// system (spec 19 AC 22). It is also the read leg of the restore path:
// after a prune, RebuildAll restores the latest snapshot by fetching its
// archive and handing the parsed snapshot to Store.RebuildAllFromSnapshot.
func ReadArtifact(r io.Reader) (store.Snapshot, []json.RawMessage, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return store.Snapshot{}, nil, fmt.Errorf("retention: open artifact: %w", err)
	}
	defer gz.Close()
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<26) // allow large snapshot header lines

	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return store.Snapshot{}, nil, fmt.Errorf("retention: read header: %w", err)
		}
		return store.Snapshot{}, nil, fmt.Errorf("retention: artifact missing header")
	}
	var hdr artifactHeader
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
		return store.Snapshot{}, nil, fmt.Errorf("retention: decode header: %w", err)
	}
	var events []json.RawMessage
	for sc.Scan() {
		var ev archivedEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return store.Snapshot{}, nil, fmt.Errorf("retention: decode archived event: %w", err)
		}
		events = append(events, ev.Event)
	}
	if err := sc.Err(); err != nil {
		return store.Snapshot{}, nil, fmt.Errorf("retention: scan artifact: %w", err)
	}
	return hdr.Snapshot, events, nil
}
