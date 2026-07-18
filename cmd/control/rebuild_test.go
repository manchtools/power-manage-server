package main

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// The store layer carries the behavioral coverage for the rebuild
// subcommand (cascade expansion, unknown targets, skip counters — see
// internal/store/rebuild_cascade_test.go). These tests pin the CLI
// shell around it: exit codes for the no-database paths.

func TestRunRebuildProjections_NoDatabaseURLIsCouldNotRun(t *testing.T) {
	t.Setenv("CONTROL_DATABASE_URL", "")
	code := runRebuildProjections([]string{"--env-file", "/nonexistent/never.env"})
	assert.Equal(t, 2, code, "missing CONTROL_DATABASE_URL must exit 2 (could not run)")
}

func TestRunRebuildProjections_HelpIsSuccess(t *testing.T) {
	code := runRebuildProjections([]string{"-h"})
	assert.Equal(t, 0, code, "-h is a successful help request, not a failure")
}

// TestRunRebuildProjections_RebuildsPIIBearingProjection is the happy-path
// smoke the audit flagged as missing — and it caught a real bug: the rebuild
// CLI must wire the spec-19 PII opener (WireAll does NOT), or replaying any
// user event that carries sealed PII fails with "no PII opener is wired" and
// the whole emergency rebuild rolls back. Seeds a user with a GENUINELY sealed
// PII field (a typed UserProfileUpdated — the factory's own map event is
// deliberately plaintext), TRUNCATE-and-replays the users projection through
// the real runRebuildProjections, and asserts exit 0 with the field DECRYPTED
// (not the redaction sentinel — proving the opener decrypted rather than the
// projector redacting an "unreadable" value).
func TestRunRebuildProjections_RebuildsPIIBearingProjection(t *testing.T) {
	st, dsn := testutil.SetupPostgresWithDSN(t)
	ctx := context.Background()

	email := "rebuild-happy-" + testutil.NewID()[:8] + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "viewer")

	// A typed profile event seals given_name under the user's DEK (the factory
	// creation event stores an unsealed map, so it alone would not exercise the
	// opener). Mirrors the production UpdateUserProfile emit.
	const sealedGivenName = "Alice-Sealed"
	gn := sealedGivenName
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  string(eventtypes.UserProfileUpdated),
		Data:       payloads.UserProfileUpdated{GivenName: &gn},
		ActorType:  "system",
		ActorID:    "test",
	}))
	// Prove the event is genuinely sealed AT REST — otherwise a regression that
	// silently stopped sealing would leave given_name in plaintext, the rebuild
	// would never need the opener, and this whole test would pass vacuously.
	require.Contains(t, storedEventData(t, st, userID, eventtypes.UserProfileUpdated), "pii:v1:",
		"precondition: the given_name must be sealed (pii:v1:) in the stored event")
	require.NotContains(t, storedEventData(t, st, userID, eventtypes.UserProfileUpdated), sealedGivenName,
		"precondition: the plaintext given_name must NOT appear in the stored event")
	require.Equal(t, sealedGivenName, projectedGivenName(t, st, userID),
		"precondition: the live projector decrypted the sealed given_name")

	// Simulate a FRESH CLI process: boot never ran, so the package-global PII
	// opener is unset. (SetupPostgresWithDSN wired it to seed the user above;
	// without this reset the leaked global would let the rebuild succeed even
	// if the CLI forgot to wire its own opener — masking the very bug this
	// test exists to catch.) Restore to the unwired default on teardown so no
	// later serial test inherits this test's (torn-down) store opener.
	projectors.SetPIIOpener(nil)
	t.Cleanup(func() { projectors.SetPIIOpener(nil) })

	// The CLI opens its OWN store from these; --env-file points nowhere so the
	// process env is authoritative. The KEK MUST match the one the seed data
	// was sealed under, or the DEK unwrap fails.
	t.Setenv("CONTROL_DATABASE_URL", dsn)
	t.Setenv("CONTROL_ENCRYPTION_KEY", testutil.TestKEKHex)

	code := runRebuildProjections([]string{"--env-file", "/nonexistent/never.env", "users"})
	require.Equal(t, 0, code, "rebuilding the PII-bearing users projection must succeed (exit 0)")

	assert.Equal(t, sealedGivenName, projectedGivenName(t, st, userID),
		"given_name must be decrypted through the CLI-wired opener, not redacted to the sentinel")
}

// projectedGivenName reads users_projection.given_name directly, so the
// assertion does not depend on the repo struct's field surface.
func projectedGivenName(t *testing.T, st *store.Store, userID string) string {
	t.Helper()
	var gn *string
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT given_name FROM users_projection WHERE id = $1`, userID).Scan(&gn))
	if gn == nil {
		return ""
	}
	return *gn
}

// storedEventData returns the raw JSON payload of the user's event of the given
// type, so a test can assert the at-rest sealed representation rather than
// trusting the projection round-trip.
func storedEventData(t *testing.T, st *store.Store, userID string, eventType eventtypes.EventType) string {
	t.Helper()
	var data string
	require.NoError(t, st.TestingPool().QueryRow(context.Background(),
		`SELECT data::text FROM events WHERE stream_id = $1 AND event_type = $2`,
		userID, string(eventType)).Scan(&data))
	return data
}

func TestRunRebuildProjections_ArchiveDirWithTargetsIsCouldNotRun(t *testing.T) {
	t.Setenv("CONTROL_DATABASE_URL", "")

	// Capture stderr: exit 2 is shared with env/config failures, so the
	// assertion must prove THIS guard fired, not a missing database URL.
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	code := runRebuildProjections([]string{"--env-file", "/nonexistent/never.env", "--archive-dir", "/tmp/x", "users"})
	os.Stderr = orig
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Equal(t, 2, code, "--archive-dir restores every projection; combining it with target selection must exit 2")
	assert.Contains(t, string(out), "target selection is not supported",
		"the exit must come from the archive-target guard, not an unrelated config failure")
}
