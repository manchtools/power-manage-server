package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	auditArchiveVersion  = 1
	auditArchivePageSize = int64(1000)
)

// AuditArchiveSummary identifies the exact chain prefix written by
// WriteAuditPrefix.
type AuditArchiveSummary struct {
	Rows         int64
	BoundaryHash []byte
}

type auditArchiveHeader struct {
	Type            string           `json:"type"`
	Version         int              `json:"version"`
	Stream          string           `json:"stream"`
	BoundarySeq     int64            `json:"boundary_seq"`
	BoundaryHash    string           `json:"boundary_hash"`
	PriorCheckpoint *AuditCheckpoint `json:"prior_checkpoint,omitempty"`
}

type auditArchiveRow struct {
	Type      string                    `json:"type"`
	Operation *generated.AuditOperation `json:"operation,omitempty"`
	Effect    *generated.AuditEffect    `json:"effect,omitempty"`
}

// FindAuditRetentionBoundary returns the newest closed chain position older
// than cutoff, or zero when no retained row is old enough.
func (s *Store) FindAuditRetentionBoundary(ctx context.Context, stream string, cutoff time.Time) (int64, error) {
	if ctx == nil || s == nil || cutoff.IsZero() {
		return 0, errors.New("audit retention boundary requires a store, context, and cutoff")
	}
	if stream == "" {
		stream = DefaultAuditStream
	}
	boundary, err := s.queries.FindClosedAuditRetentionBoundary(ctx, generated.FindClosedAuditRetentionBoundaryParams{
		Stream: stream, Cutoff: cutoff.UTC(),
	})
	if err != nil {
		return 0, fmt.Errorf("audit: find retention boundary: %w", err)
	}
	return boundary, nil
}

// WriteAuditPrefix writes a deterministic JSON-lines archive of every retained
// operation and effect through boundarySeq. It performs no database mutation.
func (s *Store) WriteAuditPrefix(ctx context.Context, stream string, boundarySeq int64, dst io.Writer) (AuditArchiveSummary, error) {
	if ctx == nil || s == nil || dst == nil || boundarySeq <= 0 {
		return AuditArchiveSummary{}, errors.New("audit archive requires a store, context, boundary, and writer")
	}
	if stream == "" {
		stream = DefaultAuditStream
	}
	boundaryHash, err := s.rowHashAt(ctx, s.queries, stream, boundarySeq)
	if err != nil {
		return AuditArchiveSummary{}, fmt.Errorf("audit archive: read boundary: %w", err)
	}
	operationCount, err := s.queries.CountAuditOperationsAtOrBelow(ctx, generated.CountAuditOperationsAtOrBelowParams{
		Stream: stream, ChainSeq: boundarySeq,
	})
	if err != nil {
		return AuditArchiveSummary{}, fmt.Errorf("audit archive: count operations: %w", err)
	}
	effectCount, err := s.queries.CountAuditEffectsAtOrBelow(ctx, generated.CountAuditEffectsAtOrBelowParams{
		Stream: stream, ChainSeq: boundarySeq,
	})
	if err != nil {
		return AuditArchiveSummary{}, fmt.Errorf("audit archive: count effects: %w", err)
	}
	firstSeq, err := s.firstSeqAbove(ctx, s.queries, stream, 0)
	if err != nil {
		return AuditArchiveSummary{}, err
	}
	if firstSeq == 0 || firstSeq > boundarySeq {
		return AuditArchiveSummary{}, fmt.Errorf("audit archive: boundary position %d is not retained", boundarySeq)
	}
	checkpoints, err := s.ListAuditCheckpoints(ctx, stream)
	if err != nil {
		return AuditArchiveSummary{}, err
	}
	var prior *AuditCheckpoint
	if len(checkpoints) > 0 {
		copy := checkpoints[len(checkpoints)-1]
		prior = &copy
	}
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(auditArchiveHeader{
		Type: "header", Version: auditArchiveVersion, Stream: stream,
		BoundarySeq: boundarySeq, BoundaryHash: hex.EncodeToString(boundaryHash), PriorCheckpoint: prior,
	}); err != nil {
		return AuditArchiveSummary{}, fmt.Errorf("audit archive: write header: %w", err)
	}
	type orderedRow struct {
		seq int64
		row auditArchiveRow
	}
	rowsWritten := int64(0)
	expectedSeq := firstSeq
	for from := firstSeq; from <= boundarySeq; from += auditArchivePageSize {
		to := min(from+auditArchivePageSize-1, boundarySeq)
		ops, err := s.queries.ListAuditChainOperations(ctx, generated.ListAuditChainOperationsParams{
			Stream: stream, ChainSeq: from, ChainSeq_2: to,
		})
		if err != nil {
			return AuditArchiveSummary{}, fmt.Errorf("audit archive: list operations: %w", err)
		}
		effects, err := s.queries.ListAuditChainEffects(ctx, generated.ListAuditChainEffectsParams{
			Stream: stream, ChainSeq: from, ChainSeq_2: to,
		})
		if err != nil {
			return AuditArchiveSummary{}, fmt.Errorf("audit archive: list effects: %w", err)
		}
		rows := make([]orderedRow, 0, len(ops)+len(effects))
		for i := range ops {
			rows = append(rows, orderedRow{seq: ops[i].ChainSeq, row: auditArchiveRow{Type: "operation", Operation: &ops[i]}})
		}
		for i := range effects {
			rows = append(rows, orderedRow{seq: effects[i].ChainSeq, row: auditArchiveRow{Type: "effect", Effect: &effects[i]}})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].seq < rows[j].seq })
		for _, row := range rows {
			if row.seq != expectedSeq {
				return AuditArchiveSummary{}, fmt.Errorf("audit archive: chain jumps from %d to %d", expectedSeq-1, row.seq)
			}
			if err := encoder.Encode(row.row); err != nil {
				return AuditArchiveSummary{}, fmt.Errorf("audit archive: write row: %w", err)
			}
			expectedSeq++
			rowsWritten++
		}
	}
	if rowsWritten != operationCount+effectCount || expectedSeq != boundarySeq+1 {
		return AuditArchiveSummary{}, errors.New("audit archive: retained row count changed during export")
	}
	return AuditArchiveSummary{Rows: rowsWritten, BoundaryHash: append([]byte(nil), boundaryHash...)}, nil
}
