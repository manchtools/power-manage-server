package retention

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/store"
)

// LoadArchivedHistory loads the FULL pruned history by walking the
// EventLogPruned marker chain (spec 19 AC 21): each marker records the
// range's archive ref and the sha256 the sealed artifact must match.
// A single later archive is NOT sufficient — events ≤ an earlier
// checkpoint were already deleted when it was written — so every
// marker's archive is fetched, integrity-checked against the
// tamper-evident marker hash (stronger than the archive's own sidecar:
// the marker lives in the append-only log), parsed, and concatenated in
// sequence order.
//
// The result feeds store.RebuildAllFromArchive, whose own completeness
// check independently verifies the slice covers the latest checkpoint.
//
// ponytail: whole artifacts are buffered in memory (hash-then-parse);
// stream in two passes if a recovery ever outgrows RAM — this is a rare,
// operator-invoked path.
func LoadArchivedHistory(ctx context.Context, st *store.Store, arch archive.ArchiveStore) ([]store.PersistedEvent, error) {
	markers, err := st.ListPruneMarkers(ctx)
	if err != nil {
		return nil, err
	}
	if len(markers) == 0 {
		return nil, fmt.Errorf("retention: no EventLogPruned markers in the log — nothing was pruned, use a plain rebuild")
	}

	seen := map[string]bool{}
	var out []store.PersistedEvent
	for _, m := range markers {
		rc, err := arch.Get(ctx, m.ArchiveRef)
		if err != nil {
			return nil, fmt.Errorf("retention: fetch archive %s (checkpoint %d): %w", m.ArchiveRef, m.UpToSeq, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("retention: read archive %s: %w", m.ArchiveRef, err)
		}

		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != m.ArchiveSHA256 {
			return nil, fmt.Errorf("retention: archive %s does not match its tamper-evident marker hash (marker %s, artifact %s) — the artifact was modified or replaced; refusing to restore", m.ArchiveRef, m.ArchiveSHA256, got)
		}

		upTo, rows, err := ReadArtifact(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("retention: parse archive %s: %w", m.ArchiveRef, err)
		}
		if upTo != m.UpToSeq {
			return nil, fmt.Errorf("retention: archive %s header checkpoint %d does not match its marker checkpoint %d", m.ArchiveRef, upTo, m.UpToSeq)
		}
		evs, err := store.DecodeArchivedEvents(rows)
		if err != nil {
			return nil, fmt.Errorf("retention: decode archive %s: %w", m.ArchiveRef, err)
		}
		// Later archives re-contain earlier EventLogPruned markers (they
		// survive pruning, so they are ≤ the later checkpoint); dedupe by
		// event id so the concatenation is each event exactly once. A row
		// BEYOND its own archive's checkpoint cannot legitimately exist
		// (writeArtifact bounds ≤ N) — refuse it rather than let it skew
		// the restore's live-replay cutoff (max archived seq) past events
		// that were never archived.
		for _, ev := range evs {
			if ev.SequenceNum > m.UpToSeq {
				return nil, fmt.Errorf("retention: archive %s contains event %s (seq %d) beyond its checkpoint %d — malformed artifact; refusing to restore", m.ArchiveRef, ev.ID, ev.SequenceNum, m.UpToSeq)
			}
			if !seen[ev.ID] {
				seen[ev.ID] = true
				out = append(out, ev)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SequenceNum < out[j].SequenceNum })
	return out, nil
}
