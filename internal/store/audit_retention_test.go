package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
)

func archiveRequest(boundary int64) store.AuditRetentionRequest {
	return store.AuditRetentionRequest{
		Stream:        store.DefaultAuditStream,
		BoundarySeq:   boundary,
		ArchiveDigest: sha256hex("archived prefix bytes"),
		ArchiveRef:    "s3://audit-archive/2026-07-31.tar.zst",
		ArchivedAt:    time.Now().UTC().Add(-time.Minute),
	}
}

// Deleting evidence that was never archived destroys it. The primitive
// refuses before it opens a transaction, so an unarchived prefix is
// not even read, let alone deleted.
func TestPruneAuditPrefix_RefusesWithoutArchiveConfirmation(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()
	seedOperation(t, st)
	seedOperation(t, st)

	missing := map[string]func(*store.AuditRetentionRequest){
		"no digest":         func(r *store.AuditRetentionRequest) { r.ArchiveDigest = "" },
		"digest not sha256": func(r *store.AuditRetentionRequest) { r.ArchiveDigest = "archived-yesterday" },
		"no reference":      func(r *store.AuditRetentionRequest) { r.ArchiveRef = "" },
		"no timestamp":      func(r *store.AuditRetentionRequest) { r.ArchivedAt = time.Time{} },
	}
	require.NotEmpty(t, missing, "matches-zero guard: the archive-confirmation table is empty")

	for name, break_ := range missing {
		t.Run(name, func(t *testing.T) {
			req := archiveRequest(2)
			break_(&req)
			_, err := st.PruneAuditPrefix(ctx, req)
			require.Error(t, err)
			assert.ErrorIs(t, err, store.ErrAuditArchiveRequired)
		})
	}

	assert.Equal(t, int64(2), countRows(t, pool, "audit_operations"))
	assert.Equal(t, int64(2), countRows(t, pool, "audit_effects"))
	assert.Zero(t, countRows(t, pool, "audit_chain_checkpoints"))

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(4), v.Rows)
}

// A boundary that would leave a surviving effect pointing at a deleted
// operation is refused atomically. Archiving half an operation would
// keep a record of a consequence whose cause is gone.
func TestPruneAuditPrefix_RefusesABoundaryThatSplitsAnOperation(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()

	dispatch, err := st.RecordOperation(ctx, mutationOp(), store.AuditEffect{
		ResourceType: "delivery",
		ResourceID:   newID(),
		Action:       "DISPATCH",
		Outcome:      store.EffectApplied,
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), dispatch.HeadSeq)

	// Unrelated traffic, then a late effect of the FIRST operation.
	seedOperation(t, st)
	late, err := st.WithAuditEffects(ctx, dispatch.OperationID, func(_ context.Context, _ *store.Tx, r *store.AuditRecorder) error {
		r.Effect(store.AuditEffect{
			ResourceType: "delivery",
			ResourceID:   newID(),
			Action:       "RESULT",
			Outcome:      store.EffectApplied,
		})
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, int64(5), late.HeadSeq)

	before := chainSnapshot(t, pool)
	require.Len(t, before, 5)

	// Position 4 covers the dispatch operation but not its late
	// effect at position 5.
	_, err = st.PruneAuditPrefix(ctx, archiveRequest(4))
	require.Error(t, err)
	assert.ErrorIs(t, err, store.ErrAuditBoundaryNotClosed)

	assert.Equal(t, before, chainSnapshot(t, pool), "a refused retention pass must delete nothing")
	assert.Zero(t, countRows(t, pool, "audit_chain_checkpoints"), "a refused retention pass must write no checkpoint")

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(5), v.Rows)
	assert.Empty(t, v.ResumedFromCheckpoint)
}

// Move the boundary past the late effect and the same prefix becomes a
// closed one: operation and every effect that references it go
// together, the checkpoint commits with the deletion, and the
// remaining chain verifies from that boundary.
func TestPruneAuditPrefix_ArchivesAClosedPrefixAndTheChainVerifiesFromTheCheckpoint(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()

	dispatch, err := st.RecordOperation(ctx, mutationOp(), store.AuditEffect{
		ResourceType: "delivery",
		ResourceID:   newID(),
		Action:       "DISPATCH",
		Outcome:      store.EffectApplied,
	})
	require.NoError(t, err)
	seedOperation(t, st)
	late, err := st.WithAuditEffects(ctx, dispatch.OperationID, func(_ context.Context, _ *store.Tx, r *store.AuditRecorder) error {
		r.Effect(store.AuditEffect{
			ResourceType: "delivery",
			ResourceID:   newID(),
			Action:       "RESULT",
			Outcome:      store.EffectApplied,
		})
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, int64(5), late.HeadSeq)

	boundaryHash := chainSnapshot(t, pool)[5]
	require.NotEmpty(t, boundaryHash)

	// Work that arrives after the boundary and must survive.
	survivor := seedOperation(t, st)
	require.Equal(t, int64(7), survivor.HeadSeq)

	cp, err := st.PruneAuditPrefix(ctx, archiveRequest(5))
	require.NoError(t, err)
	assert.Equal(t, int64(5), cp.BoundarySeq)
	assert.Equal(t, int64(6), cp.ResumeSeq)
	assert.Equal(t, int64(5), cp.DeletedRows)
	assert.Equal(t, strings.ToLower(boundaryHash), hexOf(cp.BoundaryHash))
	assert.Equal(t, "s3://audit-archive/2026-07-31.tar.zst", cp.ArchiveRef)

	assert.Equal(t, int64(1), countRows(t, pool, "audit_operations"))
	assert.Equal(t, int64(1), countRows(t, pool, "audit_effects"))

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err, "the surviving suffix must verify from the checkpoint")
	assert.Equal(t, cp.CheckpointID, v.ResumedFromCheckpoint)
	assert.Equal(t, int64(6), v.FirstSeq)
	assert.Equal(t, int64(7), v.LastSeq)
	assert.Equal(t, int64(2), v.Rows)

	// The archived operation is genuinely gone, not hidden.
	_, err = st.GetAuditOperation(ctx, dispatch.OperationID)
	assert.True(t, store.IsNotFound(err), "the archived operation must be deleted, got %v", err)
}

// A failure writing the checkpoint takes the deletion with it. The
// failure is a real constraint violation: the archive reference
// exceeds the bounded length the schema allows, and the checkpoint
// insert is the statement that discovers it.
func TestPruneAuditPrefix_CheckpointFailureRollsBackTheDeletion(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()

	seedOperation(t, st)
	seedOperation(t, st)
	before := chainSnapshot(t, pool)
	require.Len(t, before, 4)

	req := archiveRequest(4)
	req.ArchiveRef = "s3://audit-archive/" + strings.Repeat("x", 300)

	_, err := st.PruneAuditPrefix(ctx, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "archive_ref")

	assert.Equal(t, before, chainSnapshot(t, pool),
		"the deletion and the checkpoint commit together; a failed checkpoint must restore every deleted row")
	assert.Zero(t, countRows(t, pool, "audit_chain_checkpoints"))

	v, err := st.VerifyAuditChain(ctx, store.AuditVerifyOptions{})
	require.NoError(t, err)
	assert.Equal(t, int64(4), v.Rows)
	assert.Equal(t, int64(1), v.FirstSeq)
}

// The retention guards are transaction-scoped. Once the pass commits
// or rolls back they are gone, so a later statement on the same pooled
// connection is refused exactly like any other.
func TestPruneAuditPrefix_RetentionExemptionDoesNotOutliveItsTransaction(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()

	seedOperation(t, st)
	seedOperation(t, st)
	_, err := st.PruneAuditPrefix(ctx, archiveRequest(2))
	require.NoError(t, err)

	// A plain delete afterwards must be refused again.
	_, err = pool.Exec(ctx, `DELETE FROM audit_operations`)
	require.Error(t, err)
	assert.True(t, store.IsAppendOnlyViolation(err),
		"the retention exemption must not survive its transaction: %v", err)
	assert.Equal(t, int64(1), countRows(t, pool, "audit_operations"))
}

// Retention cannot reach beyond the range it archived even while the
// guard is armed: the trigger bounds the delete by chain position.
func TestAuditRetentionGuard_BoundsDeletionToTheArchivedRange(t *testing.T) {
	st, pool := setupSQLite(t)
	ctx := context.Background()

	seedOperation(t, st)
	seedOperation(t, st)
	require.Equal(t, int64(2), countRows(t, pool, "audit_operations"))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `INSERT INTO audit_retention_guard (stream, boundary_seq) VALUES ('control', 2)`)
	require.NoError(t, err)

	// Position 2 is inside the armed range; position 3 is not.
	_, err = tx.Exec(ctx, `DELETE FROM audit_effects WHERE chain_seq = 2`)
	require.NoError(t, err, "a row inside the archived range is deletable")

	_, err = tx.Exec(ctx, `DELETE FROM audit_operations WHERE chain_seq = 3`)
	require.Error(t, err, "a row beyond the archived range must be refused even with the guard armed")
	assert.Contains(t, err.Error(), "append-only")
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
