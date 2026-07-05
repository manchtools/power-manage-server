package store_test

// Spec 19 AC 17 / AC 21 / AC 21a: snapshot-restore rebuild. The archived
// "snapshot" is the CIPHERTEXT events ≤ N (never a plaintext projection
// dump). A rebuild replays those archived events plus the live events > N
// and must reproduce projection state BYTE-IDENTICAL to a full rebuild
// taken before the prune (AC 17), and — because PII decrypts through the
// per-user DEK on the way in — must reproduce erased users as the
// redaction sentinel when the key table is gone (AC 21a).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/retention"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestRebuildAll_ConsistentSnapshotUnderConcurrentPrune pins the
// guard-vs-replay TOCTOU: RebuildAll checks for pruned history once, then
// re-reads events per target. If a concurrent prune commits BETWEEN the
// guard check and a later target's read, a READ COMMITTED transaction
// (fresh snapshot per statement) silently loses the pruned events
// mid-replay — the exact data-loss class the guard exists to close. The
// rebuild transaction must run at REPEATABLE READ so the guard and every
// replay read share ONE snapshot; the concurrent prune then commits
// harmlessly after the fact.
//
// Deterministic race: the "users" applier (the FIRST rebuild target) is
// wrapped to commit a full prune on a separate connection before the
// first user event applies — so every later target's events are already
// deleted from the live table when that target reads them.
func TestRebuildAll_ConsistentSnapshotUnderConcurrentPrune(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	testutil.CreateTestUser(t, st, "race-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "race-host-"+testutil.NewID()[:6])
	checkpoint := maxSeq(t, st)
	baseline := dumpRebuildTables(t, st)

	pruned := false
	st.RegisterRebuildApply("users", func(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
		if !pruned {
			pruned = true
			// A concurrent prune (separate pool connection) commits while
			// the rebuild transaction is mid-flight.
			if _, err := st.PruneEventsUpTo(ctx, checkpoint, "prune-race", "sha-race"); err != nil {
				return fmt.Errorf("concurrent prune: %w", err)
			}
		}
		return projectors.ApplyUserWithRoles(ctx, q, e)
	})

	_, err := st.RebuildAll(ctx)
	require.NoError(t, err)
	require.True(t, pruned, "the race must actually have fired")

	after := dumpRebuildTables(t, st)
	for tbl, rows := range baseline {
		assert.Equalf(t, rows, after[tbl],
			"projection table %q lost rows to a prune that committed mid-rebuild — the rebuild transaction must hold one consistent snapshot (REPEATABLE READ) across the guard and every replay read", tbl)
	}
}

// collectArchivedEvents returns every event ≤ upToSeq as the raw
// to_jsonb rows the retention artifact would carry — the archived
// ciphertext history handed to a restore.
func collectArchivedEvents(t *testing.T, st *store.Store, upToSeq int64) []store.PersistedEvent {
	t.Helper()
	var raw []json.RawMessage
	require.NoError(t, st.StreamEventsUpTo(context.Background(), upToSeq, func(r json.RawMessage) error {
		raw = append(raw, append(json.RawMessage(nil), r...))
		return nil
	}))
	events, err := store.DecodeArchivedEvents(raw)
	require.NoError(t, err)
	return events
}

// TestRebuildAllFromArchive_FullFidelity pins AC 17: prune@N then
// restore (replay archived events ≤ N + live events > N) reproduces a
// pre-prune rebuild, byte for byte, over every AllRebuildTargets table.
func TestRebuildAllFromArchive_FullFidelity(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// Batch 1: the rich fixture across every stream type (≤ N).
	seedRichFixture(t, st)
	checkpoint := maxSeq(t, st)
	require.Positive(t, checkpoint)

	// Batch 2: a spread of further events (> N) so the live-replay leg is
	// non-trivial and touches multiple targets.
	adminID := testutil.CreateTestUser(t, st, "postN-admin-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	newUser := testutil.CreateTestUser(t, st, "postN-user-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	newRole := testutil.CreateTestRole(t, st, adminID, "postN-role-"+testutil.NewID()[:8], []string{"GetDevice"})
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user_role",
		StreamID:   newUser + ":" + newRole,
		EventType:  "UserRoleAssigned",
		Data:       map[string]any{"user_id": newUser, "role_id": newRole},
		ActorType:  "user",
		ActorID:    adminID,
	}))
	newDevice := testutil.CreateTestDevice(t, st, "postN-host-"+testutil.NewID()[:8])
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   newDevice,
		EventType:  "DeviceLabelSet",
		Data:       map[string]any{"key": "tier", "value": "gold"},
		ActorType:  "user",
		ActorID:    adminID,
	}))
	require.Greater(t, maxSeq(t, st), checkpoint, "batch 2 must add events beyond the checkpoint")

	// Reference: a full rebuild of ALL events, taken BEFORE any prune.
	_, err := st.RebuildAll(ctx)
	require.NoError(t, err)
	baseline := dumpRebuildTables(t, st)
	nonEmpty := 0
	for _, rows := range baseline {
		if rows != "" {
			nonEmpty++
		}
	}
	require.GreaterOrEqual(t, nonEmpty, 10,
		"fixture too thin (%d non-empty tables) — the byte-compare would prove little", nonEmpty)

	// Collect the archived events ≤ N (the cold history) BEFORE pruning
	// them, then prune: the ≤ N events now live only in the archive slice.
	archived := collectArchivedEvents(t, st, checkpoint)
	require.NotEmpty(t, archived)
	deleted, err := st.PruneEventsUpTo(ctx, checkpoint, "test-archive-ref", "0000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	require.Positive(t, deleted, "the prune must actually delete the ≤ N history")

	// Restore: replay archived ≤ N, then live > N.
	res, err := st.RebuildAllFromArchive(ctx, archived)
	require.NoError(t, err)
	require.NotEmpty(t, res.Targets)

	after := dumpRebuildTables(t, st)
	for tbl, rows := range baseline {
		assert.Equalf(t, rows, after[tbl],
			"projection table %q not byte-identical after prune@N + restore(archived ≤ N)+replay(> N) — snapshot/replay infidelity (spec 19 AC 17)", tbl)
	}
}

// TestRebuildAll_RefusesAfterPrune pins the AC 21 fail-closed leg: once
// history has been pruned, a plain RebuildAll (TRUNCATE + replay of the
// surviving live log) would silently reproduce projections MISSING all
// state ≤ N — the #497 data-loss class through the front door. It must
// refuse with ErrHistoryPruned and point the operator at the
// archive-restore path instead of destroying state.
func TestRebuildAll_RefusesAfterPrune(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	email := "refuse-" + testutil.NewID()[:8] + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	_, err := st.PruneEventsUpTo(ctx, maxSeq(t, st), "prune-refuse", "sha")
	require.NoError(t, err)

	_, err = st.RebuildAll(ctx)
	require.Error(t, err, "RebuildAll after a prune would destroy all state ≤ N — it must refuse")
	require.ErrorIs(t, err, store.ErrHistoryPruned)

	// Fail-closed means NOTHING was truncated: the live projection still
	// resolves the user.
	got, err := st.Repos().User.Get(ctx, userID)
	require.NoError(t, err, "the refusal must roll back before any TRUNCATE")
	assert.Equal(t, email, got.Email)

	// A partial rebuild is refused just the same.
	_, err = st.RebuildAll(ctx, "users")
	require.ErrorIs(t, err, store.ErrHistoryPruned)
}

// TestRebuildAllFromArchive_RefusesIncompleteArchive pins the restore
// completeness check: the archived slice must cover the LATEST prune
// checkpoint recorded in the live marker chain. Handing only a later
// archive (which, after a second prune, no longer contains events ≤ N1 —
// they were already deleted when it was written) or a stale earlier one
// must be refused, not silently restored with a hole.
func TestRebuildAllFromArchive_RefusesIncompleteArchive(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	testutil.CreateTestUser(t, st, "inc1-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	cp1 := maxSeq(t, st)
	archive1 := collectArchivedEvents(t, st, cp1)
	_, err := st.PruneEventsUpTo(ctx, cp1, "prune-inc-1", "sha1")
	require.NoError(t, err)

	testutil.CreateTestUser(t, st, "inc2-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	cp2 := maxSeq(t, st)
	_, err = st.PruneEventsUpTo(ctx, cp2, "prune-inc-2", "sha2")
	require.NoError(t, err)

	// archive1 stops at N1 < N2 (the latest marker): incomplete.
	_, err = st.RebuildAllFromArchive(ctx, archive1)
	require.Error(t, err, "an archive that does not cover the latest prune checkpoint must be refused")
	assert.Contains(t, err.Error(), "does not cover")
}

// TestRebuildAllFromArchive_RefusesLatestArchiveOnly pins the other half
// of the completeness check (CR): the LATEST archive alone reaches the
// latest checkpoint (max seq == N2), but after a second prune it no
// longer contains events ≤ N1 — they were already deleted when it was
// written. Every marker's checkpoint event (seq == up_to_seq) exists in
// exactly ONE archive (its own: later prunes deleted it from the live
// log before their archives were written), so a slice missing any
// marker's checkpoint event cannot be the full chain and must be
// refused.
func TestRebuildAllFromArchive_RefusesLatestArchiveOnly(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	testutil.CreateTestUser(t, st, "lat1-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	cp1 := maxSeq(t, st)
	_, err := st.PruneEventsUpTo(ctx, cp1, "prune-lat-1", "sha1")
	require.NoError(t, err)

	testutil.CreateTestUser(t, st, "lat2-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	cp2 := maxSeq(t, st)
	// What archive 2 holds: the events surviving ≤ N2 at prune-2 time —
	// (N1, N2] plus marker 1, but NOTHING ≤ N1.
	archive2 := collectArchivedEvents(t, st, cp2)
	_, err = st.PruneEventsUpTo(ctx, cp2, "prune-lat-2", "sha2")
	require.NoError(t, err)

	_, err = st.RebuildAllFromArchive(ctx, archive2)
	require.Error(t, err,
		"the latest archive alone reaches N2 but misses everything ≤ N1 — restore must demand the full marker chain")
	assert.Contains(t, err.Error(), "checkpoint")
}

// pruneWorker builds a retention worker over a real fs archive whose
// clock is far in the future, so every already-appended event is
// prune-eligible (positive window + safety floor both satisfied).
func pruneWorker(t *testing.T, st *store.Store, dir string) (*retention.Worker, archive.ArchiveStore) {
	t.Helper()
	arch, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: dir})
	require.NoError(t, err)
	w, err := retention.NewWorker(st, arch, retention.Config{Window: time.Hour}, nil)
	require.NoError(t, err)
	future := time.Now().Add(1000 * time.Hour)
	w.SetNowForTest(func() time.Time { return future })
	return w, arch
}

// TestRestore_MultiPruneChain_FullFidelity is the end-to-end recovery
// contract across MULTIPLE prunes (spec 19 AC 21): after two prunes, the
// latest archive alone no longer contains events ≤ N1 — the full history
// exists only as the marker-chained set of archives. LoadArchivedHistory
// walks the chain (verifying each artifact against its tamper-evident
// marker hash) and RebuildAllFromArchive must then reproduce the live
// projection state byte-identically.
func TestRestore_MultiPruneChain_FullFidelity(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	w, arch := pruneWorker(t, st, t.TempDir())

	// Batch 1 → prune 1 (takes everything so far as checkpoint N1).
	testutil.CreateTestUser(t, st, "chain1-"+testutil.NewID()[:8]+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "chain1-host-"+testutil.NewID()[:6])
	res1, err := w.Prune(ctx)
	require.NoError(t, err)
	require.True(t, res1.Pruned)

	// Batch 2 → prune 2 (N2 > N1; its archive holds only (N1, N2]).
	testutil.CreateTestUser(t, st, "chain2-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	testutil.CreateTestDevice(t, st, "chain2-host-"+testutil.NewID()[:6])
	res2, err := w.Prune(ctx)
	require.NoError(t, err)
	require.True(t, res2.Pruned)
	require.Greater(t, res2.Checkpoint, res1.Checkpoint)

	// The live projections (built by the live listeners) are the truth.
	baseline := dumpRebuildTables(t, st)

	// Chain-load the full pruned history and restore.
	archived, err := retention.LoadArchivedHistory(ctx, st, arch)
	require.NoError(t, err)
	require.NotEmpty(t, archived)
	_, err = st.RebuildAllFromArchive(ctx, archived)
	require.NoError(t, err)

	after := dumpRebuildTables(t, st)
	for tbl, rows := range baseline {
		assert.Equalf(t, rows, after[tbl],
			"projection table %q not byte-identical after a multi-prune chain restore (spec 19 AC 21)", tbl)
	}
}

// TestLoadArchivedHistory_TamperDetected pins the integrity leg of the
// chain restore: an archived artifact that no longer matches the sha256
// recorded in its tamper-evident EventLogPruned marker is refused — a
// modified or replaced cold archive must never be silently replayed.
func TestLoadArchivedHistory_TamperDetected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	dir := t.TempDir()
	w, arch := pruneWorker(t, st, dir)

	testutil.CreateTestUser(t, st, "tamper-"+testutil.NewID()[:8]+"@test.com", "pass", "user")
	res, err := w.Prune(ctx)
	require.NoError(t, err)
	require.True(t, res.Pruned)

	// Corrupt one byte of the sealed artifact on disk.
	path := filepath.Join(dir, res.ArchiveRef)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	data[len(data)/2] ^= 0xFF
	require.NoError(t, os.WriteFile(path, data, 0o600))

	_, err = retention.LoadArchivedHistory(ctx, st, arch)
	require.Error(t, err, "a tampered archive must be refused")
	assert.Contains(t, err.Error(), "marker hash")
}

// TestRebuildAllFromArchive_ErasedWithoutDEKsIsSentinel pins AC 21a:
// restoring from the archived events with the DEK table empty (e.g.
// recovering only the event log) completes but reproduces ALL users' PII
// as the redaction sentinel — the archived events hold only ciphertext,
// so without the DEKs the PII is permanently unreadable. This is the
// erasure guarantee surviving a restore: a plaintext projection dump
// would have leaked PII here.
func TestRebuildAllFromArchive_ErasedWithoutDEKsIsSentinel(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// Create the user via a TYPED PII event so the email is SEALED
	// (pii:v1) in the log — CreateTestUser emits an unsealed map payload,
	// which would archive plaintext and defeat the point of this test.
	userID := testutil.NewID()
	testutil.MintTestUserDEK(t, st, userID)
	email := "shredme-" + testutil.NewID()[:8] + "@test.com"
	hash, role := "x", "user"
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  string(eventtypes.UserCreatedWithRoles),
		Data:       payloads.UserCreatedWithRoles{Email: &email, PasswordHash: &hash, Role: &role},
		ActorType:  "system",
		ActorID:    "test",
	}))

	// Sanity: with the DEK present, the projection holds plaintext.
	require.Equal(t, email, userProjectionPII(t, st, userID)["email"])

	// Archive all events, then destroy every DEK — the "restore only the
	// event log, key table lost" scenario.
	archived := collectArchivedEvents(t, st, maxSeq(t, st))
	require.NotEmpty(t, archived)
	_, err := st.TestingPool().Exec(ctx, `DELETE FROM user_encryption_keys`)
	require.NoError(t, err)

	// Restore from the archived ciphertext with no DEKs.
	_, err = st.RebuildAllFromArchive(ctx, archived)
	require.NoError(t, err, "restore must complete even with the key table empty (mass-erasure, not a fault)")

	assert.Equal(t, crypto.RedactionSentinel, userProjectionPII(t, st, userID)["email"],
		"with the DEK gone, archived PII must reproduce as the redaction sentinel — never plaintext")
}
