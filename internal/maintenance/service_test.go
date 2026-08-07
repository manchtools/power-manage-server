package maintenance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/jobs"
	"github.com/manchtools/power-manage/server/internal/maintenance"
	"github.com/manchtools/power-manage/server/internal/store"
)

// evidenceFixture is one control deployment's durable evidence: the live
// database, the archive mount it publishes to, and the maintenance service
// that moves rows between them. Tests reach into archiveDir directly because
// the threat this package defends against is someone who can write there.
type evidenceFixture struct {
	service    *maintenance.Service
	store      *store.Store
	archive    archive.ArchiveStore
	archiveDir string
}

// newEvidenceFixture builds a service whose clock is far enough ahead of the
// seeded rows that retention considers them expired.
func newEvidenceFixture(t *testing.T) evidenceFixture {
	t.Helper()
	// context.Background: test lifecycle root, not a request path.
	ctx := context.Background()
	st, err := store.New(ctx, filepath.Join(t.TempDir(), "control.db"))
	require.NoError(t, err)
	t.Cleanup(st.Close)

	archiveDir := t.TempDir()
	archives, err := archive.New(archive.Config{
		Backend: archive.BackendFilesystem, FilesystemPath: archiveDir,
	})
	require.NoError(t, err)

	now := time.Now().UTC().Add(120 * 24 * time.Hour)
	return evidenceFixture{
		service: maintenance.New(maintenance.Config{
			Store: st, Archive: archives, Retention: 90 * 24 * time.Hour,
			Now:        func() time.Time { return now },
			BackupPath: t.TempDir(), BackupMaxLag: 26 * time.Hour,
		}),
		store: st, archive: archives, archiveDir: archiveDir,
	}
}

// seedAuditRow appends one audited background operation so the chain has
// something to anchor, archive and prune.
func seedAuditRow(t *testing.T, st *store.Store) {
	t.Helper()
	operationID := ulid.Make().String()
	_, err := st.RecordOperation(context.Background(), store.AuditOperation{
		OperationID: operationID, Class: store.ClassBackgroundWriter,
		ActorType: "control_worker", Origin: "in_process",
		RequestDescriptor:    "maintenance.test.seed",
		AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result:               store.ResultSuccess, ResultCode: "OK",
	}, store.AuditEffect{
		ResourceType: "security_posture", ResourceID: operationID,
		Action: "INSPECT", Outcome: store.EffectApplied,
	})
	require.NoError(t, err)
}

// archivedRef returns the single archived object whose ref starts with prefix.
func archivedRef(t *testing.T, archives archive.ArchiveStore, prefix string) string {
	t.Helper()
	infos, err := archives.List(context.Background())
	require.NoError(t, err)
	var found []string
	for _, info := range infos {
		if len(info.Ref) >= len(prefix) && info.Ref[:len(prefix)] == prefix {
			found = append(found, info.Ref)
		}
	}
	require.Len(t, found, 1, "matches-zero guard: exactly one %q object must be archived", prefix)
	return found[0]
}

// TestVerifyAudit_FailsClosedWhenThePublishedAnchorIsMissing holds F19. An
// anchor row asserts that a chain position was published where this database
// cannot reach. If the object it names is gone, the assertion is unverifiable
// — and a verification pass that returns success for it makes an intact chain
// indistinguishable from one whose off-host evidence has been destroyed.
func TestVerifyAudit_FailsClosedWhenThePublishedAnchorIsMissing(t *testing.T) {
	fixture := newEvidenceFixture(t)
	ctx := context.Background()
	seedAuditRow(t, fixture.store)
	require.NoError(t, fixture.service.AnchorAudit(ctx, jobs.Job{}))

	anchorRef := archivedRef(t, fixture.archive, "audit-anchor-")
	published, err := fixture.store.LatestAuditAnchor(ctx, store.DefaultAuditStream)
	require.NoError(t, err)
	require.Equal(t, anchorRef, published.ExternalRef)

	// Remove the anchor object and its sidecar, exactly as losing or
	// wiping the archive mount would.
	require.NoError(t, os.Remove(filepath.Join(fixture.archiveDir, anchorRef)))
	require.NoError(t, os.Remove(filepath.Join(fixture.archiveDir, anchorRef+".sha256")))

	err = fixture.service.VerifyAudit(ctx, jobs.Job{})
	require.Error(t, err, "a published anchor whose object is gone must fail verification")
	assert.ErrorContains(t, err, anchorRef, "the operator must be told which object is missing")
}

// TestVerifyAudit_FailsClosedWhenThePublishedAnchorWasRewritten covers the
// other half of the same trust boundary: the object is present but no longer
// says what this database recorded it saying. Nothing in the archive can
// settle that disagreement, because the archive is the side under suspicion.
func TestVerifyAudit_FailsClosedWhenThePublishedAnchorWasRewritten(t *testing.T) {
	fixture := newEvidenceFixture(t)
	ctx := context.Background()
	seedAuditRow(t, fixture.store)
	require.NoError(t, fixture.service.AnchorAudit(ctx, jobs.Job{}))

	published, err := fixture.store.LatestAuditAnchor(ctx, store.DefaultAuditStream)
	require.NoError(t, err)
	anchorPath := filepath.Join(fixture.archiveDir, published.ExternalRef)
	raw, err := os.ReadFile(anchorPath)
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, json.Unmarshal(raw, &document))
	forgedHash := hex.EncodeToString(bytes.Repeat([]byte{0xAB}, sha256.Size))
	require.NotEqual(t, document["row_hash"], forgedHash,
		"matches-zero guard: the forged head must actually differ from the published one")
	document["row_hash"] = forgedHash
	rewritten, err := json.Marshal(document)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(anchorPath, append(rewritten, '\n'), 0o600))

	err = fixture.service.VerifyAudit(ctx, jobs.Job{})
	require.Error(t, err, "an anchor object that contradicts its recorded row must fail verification")
	assert.ErrorContains(t, err, published.ExternalRef)
}

// TestVerifyAudit_SucceedsBeforeAnythingHasEverBeenAnchored is the positive
// control for the branch above: on a fresh deployment no anchor has been
// published, so there is no off-host object to be missing. Without this,
// "fails closed" could be satisfied by refusing every deployment.
func TestVerifyAudit_SucceedsBeforeAnythingHasEverBeenAnchored(t *testing.T) {
	fixture := newEvidenceFixture(t)
	ctx := context.Background()
	seedAuditRow(t, fixture.store)

	_, err := fixture.store.LatestAuditAnchor(ctx, store.DefaultAuditStream)
	require.True(t, store.IsNotFound(err), "the fixture must have no anchor row yet")
	infos, err := fixture.archive.List(ctx)
	require.NoError(t, err)
	require.Empty(t, infos, "the fixture must have an empty archive")

	assert.NoError(t, fixture.service.VerifyAudit(ctx, jobs.Job{}),
		"a never-anchored deployment is not a tampered one")
}

// TestVerifyAudit_FailsClosedWhenAnArchivedPrefixIsMissing extends the same
// property to retention: the live rows a checkpoint covers were deleted on the
// strength of the archived object, so its absence is destroyed evidence.
func TestVerifyAudit_FailsClosedWhenAnArchivedPrefixIsMissing(t *testing.T) {
	fixture := newEvidenceFixture(t)
	ctx := context.Background()
	seedAuditRow(t, fixture.store)
	seedAuditRow(t, fixture.store)
	require.NoError(t, fixture.service.RetainAudit(ctx, jobs.Job{}))

	prefixRef := archivedRef(t, fixture.archive, "audit-prefix-")
	checkpoints, err := fixture.store.ListAuditCheckpoints(ctx, store.DefaultAuditStream)
	require.NoError(t, err)
	require.Len(t, checkpoints, 1)
	require.Equal(t, prefixRef, checkpoints[0].ArchiveRef)

	require.NoError(t, os.Remove(filepath.Join(fixture.archiveDir, prefixRef)))
	require.NoError(t, os.Remove(filepath.Join(fixture.archiveDir, prefixRef+".sha256")))

	err = fixture.service.VerifyAudit(ctx, jobs.Job{})
	require.Error(t, err, "a checkpoint whose archived prefix is gone must fail verification")
	assert.ErrorContains(t, err, prefixRef)
}

// TestRetainAudit_RefusesToPruneWhenAnArchivedPrefixWasRewritten holds C2's
// other half: the checkpoint's archive_digest is the durable, append-only copy
// of what was archived, and it must be what verification compares against.
// Rewriting the artifact and its colocated sidecar together leaves the archive
// mount self-consistent, so any check that reads its expected value from the
// mount passes — and more live evidence is then deleted on the strength of an
// artifact nobody can vouch for.
func TestRetainAudit_RefusesToPruneWhenAnArchivedPrefixWasRewritten(t *testing.T) {
	fixture := newEvidenceFixture(t)
	ctx := context.Background()
	seedAuditRow(t, fixture.store)
	seedAuditRow(t, fixture.store)
	require.NoError(t, fixture.service.RetainAudit(ctx, jobs.Job{}))

	prefixRef := archivedRef(t, fixture.archive, "audit-prefix-")
	checkpoints, err := fixture.store.ListAuditCheckpoints(ctx, store.DefaultAuditStream)
	require.NoError(t, err)
	require.Len(t, checkpoints, 1)

	forged := []byte(`{"operation_id":"the record the auditor was never meant to see"}` + "\n")
	forgedSum := sha256.Sum256(forged)
	require.NotEqual(t, checkpoints[0].ArchiveDigest, hex.EncodeToString(forgedSum[:]),
		"matches-zero guard: the forged prefix must actually differ from the archived one")
	require.NoError(t, os.WriteFile(filepath.Join(fixture.archiveDir, prefixRef), forged, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fixture.archiveDir, prefixRef+".sha256"),
		[]byte(hex.EncodeToString(forgedSum[:])), 0o600))

	seedAuditRow(t, fixture.store)
	err = fixture.service.RetainAudit(ctx, jobs.Job{})
	require.Error(t, err, "retention must not delete more evidence while an archived prefix disagrees with its checkpoint")
	assert.ErrorContains(t, err, prefixRef)
}
