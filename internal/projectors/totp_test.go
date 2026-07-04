package projectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestTotpListener_LifecycleEndToEnd walks the full TOTP lifecycle
// (Setup → Verify → BackupCodeUsed → Disable) through the listener,
// asserting both the totp_projection writes AND the cross-stream
// users_projection.totp_enabled flips.
//
// The lifecycle ordering matters: Verify flips users_projection
// totp_enabled=TRUE; Disable flips it back to FALSE. A regression in
// either branch silently breaks the auth/login path because that's
// where TotpEnabled is consulted.
func TestTotpListener_LifecycleEndToEnd(t *testing.T) {
	st := testutil.SetupPostgres(t)
	logger := slog.Default()
	st.RegisterEventListener(projectors.TotpListener(st, logger))

	ctx := context.Background()
	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")

	backupHashes := []string{
		"hash-aaaaaaaaaaaaaaaa",
		"hash-bbbbbbbbbbbbbbbb",
		"hash-cccccccccccccccc",
	}

	// Setup
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPSetupInitiated",
		Data: map[string]any{
			"secret_encrypted":  "ENC:dummy-secret",
			"backup_codes_hash": backupHashes,
		},
		ActorType: "user",
		ActorID:   userID,
	}))
	totp := pollForTotpRow(t, st, userID, func(r totpProjectionFields) bool {
		return r.SecretEncrypted == "ENC:dummy-secret"
	})
	assert.False(t, totp.Verified, "newly-initiated TOTP starts unverified")
	assert.False(t, totp.Enabled)
	require.Len(t, totp.BackupCodesHash, 3)
	require.Len(t, totp.BackupCodesUsed, 3)
	for i, used := range totp.BackupCodesUsed {
		assert.False(t, used, "backup code %d should start unused", i)
	}

	// Verify — flips totp_projection AND users_projection.totp_enabled.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPVerified",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userID,
	}))
	totp = pollForTotpRow(t, st, userID, func(r totpProjectionFields) bool {
		return r.Verified
	})
	assert.True(t, totp.Verified)
	assert.True(t, totp.Enabled)
	pollForUserTotpEnabled(t, st, userID, true)

	// BackupCodeUsed (zero-based index in event payload, listener
	// converts to 1-based for Postgres array indexing).
	idx := 1
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPBackupCodeUsed",
		Data:       map[string]any{"index": idx},
		ActorType:  "user",
		ActorID:    userID,
	}))
	totp = pollForTotpRow(t, st, userID, func(r totpProjectionFields) bool {
		return r.BackupCodesUsed[idx]
	})
	assert.True(t, totp.BackupCodesUsed[idx], "backup code at index %d should be marked used", idx)
	assert.False(t, totp.BackupCodesUsed[0], "untouched codes stay unused")

	// Disable — drops the row + flips users_projection.totp_enabled=FALSE.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPDisabled",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userID,
	}))
	for i := 0; i < 50; i++ {
		_, err := st.Queries().GetTOTPByUserID(ctx, userID)
		if err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, err := st.Queries().GetTOTPByUserID(ctx, userID)
	require.Error(t, err, "totp_projection row should be gone after Disable")
	pollForUserTotpEnabled(t, st, userID, false)
}

// TestTotpListener_BackupCodesRegenerated covers the regenerate
// branch separately so the lifecycle test stays focused.
func TestTotpListener_BackupCodesRegenerated(t *testing.T) {
	st := testutil.SetupPostgres(t)
	st.RegisterEventListener(projectors.TotpListener(st, slog.Default()))
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPSetupInitiated",
		Data: map[string]any{
			"secret_encrypted":  "ENC:s",
			"backup_codes_hash": []string{"a", "b"},
		},
		ActorType: "user",
		ActorID:   userID,
	}))
	pollForTotpRow(t, st, userID, func(r totpProjectionFields) bool {
		return len(r.BackupCodesHash) == 2
	})

	// Mark one as used so we can confirm regenerate resets the
	// "used" array length and contents to match the new hash list.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPBackupCodeUsed",
		Data:       map[string]any{"index": 0},
		ActorType:  "user",
		ActorID:    userID,
	}))
	pollForTotpRow(t, st, userID, func(r totpProjectionFields) bool {
		return r.BackupCodesUsed[0]
	})

	// Regenerate with a different number of codes — proves the
	// listener resets backup_codes_used to a fresh all-FALSE slice
	// of the new length, not just clears the bits.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "totp",
		StreamID:   userID,
		EventType:  "TOTPBackupCodesRegenerated",
		Data: map[string]any{
			"backup_codes_hash": []string{"new-a", "new-b", "new-c", "new-d"},
		},
		ActorType: "user",
		ActorID:   userID,
	}))
	got := pollForTotpRow(t, st, userID, func(r totpProjectionFields) bool {
		return len(r.BackupCodesHash) == 4 && !r.BackupCodesUsed[0]
	})
	assert.Equal(t, []string{"new-a", "new-b", "new-c", "new-d"}, got.BackupCodesHash)
	assert.Equal(t, []bool{false, false, false, false}, got.BackupCodesUsed)
}

// TestTotpListener_IgnoresWrongStreamType — defensive: the listener
// should be a no-op for every stream type other than "totp", even
// if event_type happens to look TOTP-shaped. Cheap to assert and
// catches an accidental classifier loosening.
func TestTotpListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	st.RegisterEventListener(projectors.TotpListener(st, slog.Default()))
	ctx := context.Background()

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pw", "user")

	// Verify pre-condition: no totp row exists.
	_, err := st.Queries().GetTOTPByUserID(ctx, userID)
	require.Error(t, err)

	// Append a TOTP-named event under the WRONG stream type.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "TOTPSetupInitiated",
		Data: map[string]any{
			"secret_encrypted":  "ENC:never",
			"backup_codes_hash": []string{"x"},
		},
		ActorType: "user",
		ActorID:   userID,
	}))

	// Wait long enough for the listener to have run if it were going to.
	time.Sleep(150 * time.Millisecond)

	_, err = st.Queries().GetTOTPByUserID(ctx, userID)
	require.Error(t, err, "wrong-stream-type event must NOT create a totp_projection row")
}

// totpProjectionFields is the subset the lifecycle test reads back.
// Mirrors generated.TotpProjection with only the columns we assert.
type totpProjectionFields struct {
	UserID          string
	SecretEncrypted string
	Verified        bool
	Enabled         bool
	BackupCodesHash []string
	BackupCodesUsed []bool
}

func pollForTotpRow(t *testing.T, st *store.Store, userID string, predicate func(totpProjectionFields) bool) totpProjectionFields {
	t.Helper()
	ctx := context.Background()
	var last totpProjectionFields
	for i := 0; i < 50; i++ {
		row, err := st.Queries().GetTOTPByUserID(ctx, userID)
		if err == nil {
			last = totpProjectionFields{
				UserID:          row.UserID,
				SecretEncrypted: row.SecretEncrypted,
				Verified:        row.Verified,
				Enabled:         row.Enabled,
				BackupCodesHash: row.BackupCodesHash,
				BackupCodesUsed: row.BackupCodesUsed,
			}
			if predicate(last) {
				return last
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("totp_projection predicate not satisfied within polling window; last=%+v", last)
	return last
}

func pollForUserTotpEnabled(t *testing.T, st *store.Store, userID string, want bool) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		got, err := st.Queries().IsTOTPEnabled(ctx, userID)
		if err == nil && got == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("users_projection.totp_enabled never reached %v for user %s", want, userID)
}

// Suppress unused-import warnings — the imports above are used by
// other tests in this package; keep them referenced even if a
// future edit accidentally removes them from the test bodies.
var _ = json.Marshal
var _ = errors.Is
