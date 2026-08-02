package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// AuditChainRow is one position in the unified chain, whichever table
// the row lives in.
type AuditChainRow struct {
	Stream   string
	ChainSeq int64
	// Kind is "operation" or "effect".
	Kind     string
	ID       string
	PrevHash []byte
	RowHash  []byte
	// canonical is the byte string the row's hash covers, recomputed
	// from the stored columns.
	canonical []byte
}

// AuditAnchor is a chain position published off-host.
type AuditAnchor struct {
	AnchorID    string
	Stream      string
	ChainSeq    int64
	RowHash     []byte
	CapturedAt  time.Time
	ExternalRef string
}

// AuditCheckpoint records a deleted chain prefix and the boundary
// verification resumes from.
type AuditCheckpoint struct {
	CheckpointID  string
	Stream        string
	BoundarySeq   int64
	BoundaryHash  []byte
	ResumeSeq     int64
	DeletedRows   int64
	ArchiveDigest string
	ArchiveRef    string
	ArchivedAt    time.Time
	CreatedAt     time.Time
}

// AuditVerifyOptions selects what a verification pass proves.
type AuditVerifyOptions struct {
	// Stream defaults to DefaultAuditStream.
	Stream string
	// ExpectedAnchor, when set, must be reproduced by the local chain.
	// This is the check a local attacker cannot pass: rewriting rows
	// and recomputing every hash after them still cannot produce a
	// value that was published elsewhere.
	ExpectedAnchor *AuditAnchor
	// CheckStoredAnchors additionally verifies every anchor recorded
	// in this database whose position is still present locally.
	CheckStoredAnchors bool
}

// AuditVerification is what a verification pass found.
type AuditVerification struct {
	Stream string
	// Rows is the number of chain rows walked.
	Rows int64
	// FirstSeq and LastSeq bound the walked range; zero when empty.
	FirstSeq int64
	LastSeq  int64
	// HeadHash is the row_hash of the last row walked.
	HeadHash []byte
	// ResumedFromCheckpoint is set when the walk started at a
	// retention boundary rather than at genesis.
	ResumedFromCheckpoint string
	// AnchorsChecked counts the anchors reproduced by this pass.
	AnchorsChecked int
}

// VerifyAuditChain walks the stream's chain, recomputes every row's
// hash from its stored content and its predecessor's hash, and checks
// the result against the recorded chain head.
//
// It detects any edit: a changed field, a changed timestamp, a
// reordered or inserted row, a removed interior row, a gap that no
// retention checkpoint explains, and — because the walk's end is
// compared against the stored head — rows removed from the TAIL, which
// leave a shorter chain that is internally consistent and would
// otherwise pass. It cannot detect a rewrite by someone who also
// recomputed every subsequent hash AND the head; that is what the
// anchors are for, which is why ExpectedAnchor exists.
func (s *Store) VerifyAuditChain(ctx context.Context, opts AuditVerifyOptions) (AuditVerification, error) {
	stream := opts.Stream
	if stream == "" {
		stream = DefaultAuditStream
	}

	rows, err := s.loadChain(ctx, stream)
	if err != nil {
		return AuditVerification{}, err
	}

	checkpoints, err := s.ListAuditCheckpoints(ctx, stream)
	if err != nil {
		return AuditVerification{}, err
	}

	head, err := s.AuditChainTipOf(ctx, stream)
	if err != nil {
		return AuditVerification{}, err
	}

	out := AuditVerification{Stream: stream, Rows: int64(len(rows))}
	if len(rows) == 0 {
		// An empty chain is verifiable in exactly two situations:
		// nothing was ever appended, or everything was archived under
		// a checkpoint. Anything else is a chain whose rows are gone.
		wantSeq, wantHash := int64(0), genesisHash
		if len(checkpoints) > 0 {
			last := checkpoints[len(checkpoints)-1]
			out.ResumedFromCheckpoint = last.CheckpointID
			wantSeq, wantHash = last.BoundarySeq, last.BoundaryHash
		}
		if head.Height != wantSeq || !bytes.Equal(head.HeadHash, wantHash) {
			return out, fmt.Errorf("%w: stream %s holds no rows but its head stands at position %d",
				ErrAuditChainBroken, stream, head.Height)
		}
		out.HeadHash = wantHash
		if opts.ExpectedAnchor != nil {
			if err := verifyExternalAnchor(nil, checkpoints, *opts.ExpectedAnchor); err != nil {
				return out, err
			}
			out.AnchorsChecked++
		}
		return out, nil
	}

	out.FirstSeq = rows[0].ChainSeq
	out.LastSeq = rows[len(rows)-1].ChainSeq

	// Where the walk starts. A chain that begins above position 1 must
	// be explained by a checkpoint whose resume position matches, or
	// the missing prefix is an unexplained deletion.
	expectPrev := genesisHash
	if rows[0].ChainSeq != 1 {
		cp, ok := checkpointResumingAt(checkpoints, rows[0].ChainSeq)
		if !ok {
			return out, fmt.Errorf("%w: stream %s starts at position %d with no retention checkpoint explaining the gap",
				ErrAuditChainBroken, stream, rows[0].ChainSeq)
		}
		expectPrev = cp.BoundaryHash
		out.ResumedFromCheckpoint = cp.CheckpointID
	}

	expectSeq := rows[0].ChainSeq
	for _, r := range rows {
		if r.ChainSeq != expectSeq {
			return out, fmt.Errorf("%w: stream %s jumps from position %d to %d",
				ErrAuditChainBroken, stream, expectSeq-1, r.ChainSeq)
		}
		if !bytes.Equal(r.PrevHash, expectPrev) {
			return out, fmt.Errorf("%w: %s row %s at position %d does not link to its predecessor",
				ErrAuditChainBroken, r.Kind, r.ID, r.ChainSeq)
		}
		want := chainHash(r.PrevHash, r.canonical)
		if !bytes.Equal(r.RowHash, want) {
			return out, fmt.Errorf("%w: %s row %s at position %d has been altered",
				ErrAuditChainBroken, r.Kind, r.ID, r.ChainSeq)
		}
		expectPrev = r.RowHash
		expectSeq++
	}
	out.HeadHash = expectPrev

	// The walk must end exactly where the recorded head says it does.
	// Without this, deleting the newest rows leaves a shorter chain
	// that is internally perfect, and a stale or edited head row goes
	// unnoticed.
	if head.Height != out.LastSeq {
		return out, fmt.Errorf("%w: stream %s ends at position %d but its head stands at %d",
			ErrAuditChainBroken, stream, out.LastSeq, head.Height)
	}
	if !bytes.Equal(head.HeadHash, out.HeadHash) {
		return out, fmt.Errorf("%w: stream %s head hash does not match the row at position %d",
			ErrAuditChainBroken, stream, out.LastSeq)
	}

	if opts.ExpectedAnchor != nil {
		if err := verifyExternalAnchor(rows, checkpoints, *opts.ExpectedAnchor); err != nil {
			return out, err
		}
		out.AnchorsChecked++
	}
	if opts.CheckStoredAnchors {
		stored, err := s.ListAuditAnchors(ctx, stream)
		if err != nil {
			return out, err
		}
		for _, a := range stored {
			if a.ChainSeq < rows[0].ChainSeq || a.ChainSeq > rows[len(rows)-1].ChainSeq {
				// Archived away; the local chain cannot speak to it.
				continue
			}
			if err := verifyAnchor(rows, a); err != nil {
				return out, err
			}
			out.AnchorsChecked++
		}
	}

	return out, nil
}

func verifyExternalAnchor(rows []AuditChainRow, checkpoints []AuditCheckpoint, anchor AuditAnchor) error {
	if len(rows) > 0 && anchor.ChainSeq >= rows[0].ChainSeq {
		return verifyAnchor(rows, anchor)
	}
	for _, checkpoint := range checkpoints {
		if checkpoint.BoundarySeq == anchor.ChainSeq && bytes.Equal(checkpoint.BoundaryHash, anchor.RowHash) {
			return nil
		}
	}
	return fmt.Errorf("%w: external anchor at position %d is neither retained nor authenticated by a checkpoint",
		ErrAuditAnchorMismatch, anchor.ChainSeq)
}

// verifyAnchor checks that the local chain reproduces the value the
// anchor pinned. An anchor authenticates the PREFIX up to its
// position, so rows appended afterwards — including late effects of
// already-anchored operations — are irrelevant to it.
func verifyAnchor(rows []AuditChainRow, a AuditAnchor) error {
	for _, r := range rows {
		if r.ChainSeq != a.ChainSeq {
			continue
		}
		if !bytes.Equal(r.RowHash, a.RowHash) {
			return fmt.Errorf("%w: position %d does not reproduce anchor %s",
				ErrAuditAnchorMismatch, a.ChainSeq, a.AnchorID)
		}
		return nil
	}
	return fmt.Errorf("%w: anchor %s pins position %d, which is not present locally",
		ErrAuditAnchorMismatch, a.AnchorID, a.ChainSeq)
}

func checkpointResumingAt(checkpoints []AuditCheckpoint, seq int64) (AuditCheckpoint, bool) {
	for _, cp := range checkpoints {
		if cp.ResumeSeq == seq {
			return cp, true
		}
	}
	return AuditCheckpoint{}, false
}

// loadChain reads both row kinds and merges them into chain order.
func (s *Store) loadChain(ctx context.Context, stream string) ([]AuditChainRow, error) {
	const (
		fromStart = int64(1)
		toEnd     = int64(1) << 62
	)

	ops, err := s.queries.ListAuditChainOperations(ctx, generated.ListAuditChainOperationsParams{
		Stream:     stream,
		ChainSeq:   fromStart,
		ChainSeq_2: toEnd,
	})
	if err != nil {
		return nil, fmt.Errorf("audit: list chain operations: %w", err)
	}
	effs, err := s.queries.ListAuditChainEffects(ctx, generated.ListAuditChainEffectsParams{
		Stream:     stream,
		ChainSeq:   fromStart,
		ChainSeq_2: toEnd,
	})
	if err != nil {
		return nil, fmt.Errorf("audit: list chain effects: %w", err)
	}

	rows := make([]AuditChainRow, 0, len(ops)+len(effs))
	for _, o := range ops {
		rows = append(rows, AuditChainRow{
			Stream:    o.Stream,
			ChainSeq:  o.ChainSeq,
			Kind:      "operation",
			ID:        o.OperationID,
			PrevHash:  o.PrevHash,
			RowHash:   o.RowHash,
			canonical: canonicalOfOperation(o),
		})
	}
	for _, e := range effs {
		rows = append(rows, AuditChainRow{
			Stream:    e.Stream,
			ChainSeq:  e.ChainSeq,
			Kind:      "effect",
			ID:        e.EffectID,
			PrevHash:  e.PrevHash,
			RowHash:   e.RowHash,
			canonical: canonicalOfEffect(e),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ChainSeq < rows[j].ChainSeq })
	return rows, nil
}

// ---------------------------------------------------------------------------
// Anchoring
// ---------------------------------------------------------------------------

// Anchoring is two steps, because an anchor row asserts something the
// database cannot check on its own: that a specific chain position was
// published somewhere this database does not control.
//
//  1. AuditChainTipOf reads the current tip — a (stream, position,
//     hash) tuple.
//  2. the publisher writes that exact tuple off-host and then calls
//     RecordPublishedAuditAnchor with it and a reference to where it
//     landed.
//
// Sampling the head inside the recording call instead would attest a
// position the caller never published: appends between the publish and
// the call would move the head, and the anchor would claim external
// evidence for a value that was never sent anywhere. Anchor rows are
// append-only, so there is no correcting it afterwards.

// RecordPublishedAuditAnchor records that a captured chain position was
// published off-host.
//
// The tuple is verified against the local chain first: the row at that
// position must still carry that hash. Appends after the capture are
// expected and irrelevant — an anchor authenticates the prefix up to
// its own position. A tuple the chain does not produce is refused and
// nothing is written, because an anchor that does not match the chain
// it anchors is worse than no anchor at all.
//
// externalRef must name where the value went. A hash that exists only
// in this database proves nothing to anyone who can write to this
// database, which is the entire threat an anchor addresses.
func (s *Store) RecordPublishedAuditAnchor(ctx context.Context, tip AuditChainTip, externalRef string) (AuditAnchor, error) {
	stream := tip.Stream
	if stream == "" {
		stream = DefaultAuditStream
	}
	if externalRef == "" {
		return AuditAnchor{}, fmt.Errorf("%w: an anchor with no off-host reference attests nothing", ErrAuditAnchorMismatch)
	}
	if tip.Height <= 0 {
		return AuditAnchor{}, fmt.Errorf("%w: chain position %d is not a position", ErrAuditAnchorMismatch, tip.Height)
	}
	if len(tip.HeadHash) != sha256.Size {
		return AuditAnchor{}, fmt.Errorf("%w: published hash is not a SHA-256 digest", ErrAuditAnchorMismatch)
	}

	var out AuditAnchor
	err := s.withTx(ctx, func(_ *sql.Tx, q *generated.Queries) error {
		local, err := s.rowHashAt(ctx, q, stream, tip.Height)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrAuditAnchorMismatch, err)
		}
		if !bytes.Equal(local, tip.HeadHash) {
			return fmt.Errorf("%w: position %d does not carry the published hash",
				ErrAuditAnchorMismatch, tip.Height)
		}

		row, err := q.InsertAuditChainAnchor(ctx, generated.InsertAuditChainAnchorParams{
			AnchorID:    ulid.Make().String(),
			Stream:      stream,
			ChainSeq:    tip.Height,
			RowHash:     tip.HeadHash,
			CapturedAt:  s.auditNow(),
			ExternalRef: externalRef,
		})
		if err != nil {
			return fmt.Errorf("audit: record anchor: %w", err)
		}
		out = anchorFromRow(row)
		return nil
	})
	if err != nil {
		return AuditAnchor{}, err
	}
	return out, nil
}

// LatestAuditAnchor returns the most recent anchor for a stream.
func (s *Store) LatestAuditAnchor(ctx context.Context, stream string) (AuditAnchor, error) {
	if stream == "" {
		stream = DefaultAuditStream
	}
	row, err := s.queries.GetLatestAuditChainAnchor(ctx, stream)
	if err != nil {
		return AuditAnchor{}, fmt.Errorf("audit: latest anchor: %w", translateNotFound(err))
	}
	return anchorFromRow(row), nil
}

// ListAuditAnchors returns every recorded anchor for a stream in chain
// order.
func (s *Store) ListAuditAnchors(ctx context.Context, stream string) ([]AuditAnchor, error) {
	if stream == "" {
		stream = DefaultAuditStream
	}
	rows, err := s.queries.ListAuditChainAnchors(ctx, stream)
	if err != nil {
		return nil, fmt.Errorf("audit: list anchors: %w", err)
	}
	out := make([]AuditAnchor, 0, len(rows))
	for _, r := range rows {
		out = append(out, anchorFromRow(r))
	}
	return out, nil
}

func anchorFromRow(r generated.AuditChainAnchor) AuditAnchor {
	return AuditAnchor{
		AnchorID:    r.AnchorID,
		Stream:      r.Stream,
		ChainSeq:    r.ChainSeq,
		RowHash:     r.RowHash,
		CapturedAt:  r.CapturedAt,
		ExternalRef: r.ExternalRef,
	}
}

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

// sha256HexPattern matches a lowercase SHA-256 digest and nothing else.
var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// AuditRetentionRequest asks for one chain prefix to be deleted.
//
// The archive fields are not bookkeeping: they are the precondition.
// Deleting evidence that was never archived destroys it, so the
// primitive refuses to run without a digest of the archived prefix and
// a reference to where it landed.
type AuditRetentionRequest struct {
	// Stream defaults to DefaultAuditStream.
	Stream string
	// BoundarySeq is the highest chain position to delete. Choosing a
	// boundary that only covers finished work is the caller's job;
	// this primitive enforces that the boundary is a CLOSED prefix.
	BoundarySeq int64

	// ArchiveDigest is the SHA-256 hex digest of the archived prefix,
	// so the archive can later be proven to be the thing that was
	// deleted.
	ArchiveDigest string
	// ArchiveRef names where the archive landed.
	ArchiveRef string
	// ArchivedAt is when the archive was confirmed durable.
	ArchivedAt time.Time
}

// PruneAuditPrefix deletes an archived chain prefix and writes the
// checkpoint that keeps the remainder verifiable, in one transaction.
//
// Four conditions must all hold, and any failure aborts the whole
// transaction, so a refused retention pass deletes nothing and leaves
// no checkpoint behind:
//
//  1. archive confirmation is present — checked before any database
//     work, so an unarchived prefix is never even opened;
//  2. the boundary is a CLOSED prefix: no surviving effect may
//     reference an operation inside it, or the chain would keep a
//     record of a consequence whose cause had been deleted;
//  3. the transaction-scoped guards the append-only trigger requires
//     are set, and bound the deletion to the archived range;
//  4. the checkpoint row commits with the deletion.
func (s *Store) PruneAuditPrefix(ctx context.Context, req AuditRetentionRequest) (AuditCheckpoint, error) {
	stream := req.Stream
	if stream == "" {
		stream = DefaultAuditStream
	}
	switch {
	case req.BoundarySeq <= 0:
		return AuditCheckpoint{}, fmt.Errorf("audit: retention boundary must be a positive chain position")
	case !sha256HexPattern.MatchString(req.ArchiveDigest):
		return AuditCheckpoint{}, fmt.Errorf("%w: archive digest must be a SHA-256 hex digest", ErrAuditArchiveRequired)
	case req.ArchiveRef == "":
		return AuditCheckpoint{}, fmt.Errorf("%w: archive reference is unset", ErrAuditArchiveRequired)
	case req.ArchivedAt.IsZero():
		return AuditCheckpoint{}, fmt.Errorf("%w: archive timestamp is unset", ErrAuditArchiveRequired)
	}

	var out AuditCheckpoint
	err := s.withTx(ctx, func(_ *sql.Tx, q *generated.Queries) error {
		// The append-only trigger permits the archived prefix only while this
		// transaction's guard row exists. Rollback removes it automatically;
		// the success path removes it explicitly before commit.
		if err := q.ArmAuditRetentionGuard(ctx, generated.ArmAuditRetentionGuardParams{
			Stream: stream, BoundarySeq: req.BoundarySeq,
		}); err != nil {
			if strings.Contains(err.Error(), "audit retention boundary is not a closed prefix") {
				return fmt.Errorf("%w: boundary position %d", ErrAuditBoundaryNotClosed, req.BoundarySeq)
			}
			return fmt.Errorf("audit: arm retention guard: %w", err)
		}
		stranded, err := q.CountAuditEffectsStrandedByBoundary(ctx, generated.CountAuditEffectsStrandedByBoundaryParams{
			Stream:   stream,
			ChainSeq: req.BoundarySeq,
		})
		if err != nil {
			return fmt.Errorf("audit: check retention boundary: %w", err)
		}
		if stranded > 0 {
			return fmt.Errorf("%w: %d effect(s) beyond position %d still reference an operation inside it",
				ErrAuditBoundaryNotClosed, stranded, req.BoundarySeq)
		}

		boundaryHash, err := s.rowHashAt(ctx, q, stream, req.BoundarySeq)
		if err != nil {
			return err
		}

		opsBelow, err := q.CountAuditOperationsAtOrBelow(ctx, generated.CountAuditOperationsAtOrBelowParams{
			Stream:   stream,
			ChainSeq: req.BoundarySeq,
		})
		if err != nil {
			return fmt.Errorf("audit: count operations in prefix: %w", err)
		}
		effsBelow, err := q.CountAuditEffectsAtOrBelow(ctx, generated.CountAuditEffectsAtOrBelowParams{
			Stream:   stream,
			ChainSeq: req.BoundarySeq,
		})
		if err != nil {
			return fmt.Errorf("audit: count effects in prefix: %w", err)
		}

		resumeSeq, err := s.firstSeqAbove(ctx, q, stream, req.BoundarySeq)
		if err != nil {
			return err
		}
		if resumeSeq == 0 {
			// Nothing survives; the next append continues from here.
			resumeSeq = req.BoundarySeq + 1
		}

		if _, err := q.DeleteAuditEffectsAtOrBelow(ctx, generated.DeleteAuditEffectsAtOrBelowParams{
			Stream:   stream,
			ChainSeq: req.BoundarySeq,
		}); err != nil {
			return fmt.Errorf("audit: delete archived effects: %w", err)
		}
		if _, err := q.DeleteAuditOperationsAtOrBelow(ctx, generated.DeleteAuditOperationsAtOrBelowParams{
			Stream:   stream,
			ChainSeq: req.BoundarySeq,
		}); err != nil {
			return fmt.Errorf("audit: delete archived operations: %w", err)
		}

		row, err := q.InsertAuditChainCheckpoint(ctx, generated.InsertAuditChainCheckpointParams{
			CheckpointID:  ulid.Make().String(),
			Stream:        stream,
			BoundarySeq:   req.BoundarySeq,
			BoundaryHash:  boundaryHash,
			ResumeSeq:     resumeSeq,
			DeletedRows:   opsBelow + effsBelow,
			ArchiveDigest: req.ArchiveDigest,
			ArchiveRef:    req.ArchiveRef,
			ArchivedAt:    req.ArchivedAt.UTC().Truncate(time.Microsecond),
			CreatedAt:     s.auditNow(),
		})
		if err != nil {
			// The deletion is in this transaction, so it goes with it.
			return fmt.Errorf("audit: write retention checkpoint: %w", err)
		}
		if err := q.DisarmAuditRetentionGuard(ctx, stream); err != nil {
			return fmt.Errorf("audit: disarm retention guard: %w", err)
		}
		out = checkpointFromRow(row)
		return nil
	})
	if err != nil {
		return AuditCheckpoint{}, err
	}
	return out, nil
}

// rowHashAt resolves one chain position across both row kinds.
func (s *Store) rowHashAt(ctx context.Context, q *generated.Queries, stream string, seq int64) ([]byte, error) {
	h, err := q.GetAuditOperationRowHashAt(ctx, generated.GetAuditOperationRowHashAtParams{
		Stream:   stream,
		ChainSeq: seq,
	})
	if err == nil {
		return h, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("audit: read operation hash at position %d: %w", seq, err)
	}
	h, err = q.GetAuditEffectRowHashAt(ctx, generated.GetAuditEffectRowHashAtParams{
		Stream:   stream,
		ChainSeq: seq,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("audit: no chain row at position %d", seq)
		}
		return nil, fmt.Errorf("audit: read effect hash at position %d: %w", seq, err)
	}
	return h, nil
}

// firstSeqAbove returns the lowest surviving position above seq, or 0
// when nothing survives.
func (s *Store) firstSeqAbove(ctx context.Context, q *generated.Queries, stream string, seq int64) (int64, error) {
	opSeq, err := q.FirstAuditOperationSeqAbove(ctx, generated.FirstAuditOperationSeqAboveParams{
		Stream:   stream,
		ChainSeq: seq,
	})
	if err != nil {
		return 0, fmt.Errorf("audit: first operation above position %d: %w", seq, err)
	}
	efSeq, err := q.FirstAuditEffectSeqAbove(ctx, generated.FirstAuditEffectSeqAboveParams{
		Stream:   stream,
		ChainSeq: seq,
	})
	if err != nil {
		return 0, fmt.Errorf("audit: first effect above position %d: %w", seq, err)
	}
	switch {
	case opSeq == 0:
		return efSeq, nil
	case efSeq == 0:
		return opSeq, nil
	case opSeq < efSeq:
		return opSeq, nil
	default:
		return efSeq, nil
	}
}

// ListAuditCheckpoints returns every retention checkpoint for a
// stream, in boundary order.
func (s *Store) ListAuditCheckpoints(ctx context.Context, stream string) ([]AuditCheckpoint, error) {
	if stream == "" {
		stream = DefaultAuditStream
	}
	rows, err := s.queries.ListAuditChainCheckpoints(ctx, stream)
	if err != nil {
		return nil, fmt.Errorf("audit: list checkpoints: %w", err)
	}
	out := make([]AuditCheckpoint, 0, len(rows))
	for _, r := range rows {
		out = append(out, checkpointFromRow(r))
	}
	return out, nil
}

func checkpointFromRow(r generated.AuditChainCheckpoint) AuditCheckpoint {
	return AuditCheckpoint{
		CheckpointID:  r.CheckpointID,
		Stream:        r.Stream,
		BoundarySeq:   r.BoundarySeq,
		BoundaryHash:  r.BoundaryHash,
		ResumeSeq:     r.ResumeSeq,
		DeletedRows:   r.DeletedRows,
		ArchiveDigest: r.ArchiveDigest,
		ArchiveRef:    r.ArchiveRef,
		ArchivedAt:    r.ArchivedAt,
		CreatedAt:     r.CreatedAt,
	}
}
