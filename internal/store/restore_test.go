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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

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
