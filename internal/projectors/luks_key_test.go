package projectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestLuksKeyRotatedFromEvent_Pure mirrors the lps_password pure
// suite. The PL/pgSQL projector implicitly required every payload
// field (any missing key would have raised on the TIMESTAMPTZ cast or
// produced a row with NULL columns the table forbids); validating
// here keeps the failure surface in the listener log instead of in
// the projection.
func TestLuksKeyRotatedFromEvent_Pure(t *testing.T) {
	rotatedAt := time.Date(2026, 5, 4, 12, 30, 0, 0, time.UTC)

	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.LuksKeyRotatedFromEvent(store.PersistedEvent{
			StreamType: "luks_key",
			EventType:  "LuksKeyRotated",
			Data: jsonOrFail(t, map[string]any{
				"device_id":       "dev-1",
				"action_id":       "act-1",
				"device_path":     "/dev/sda3",
				"passphrase":      "ENC:secret",
				"rotated_at":      rotatedAt.Format(time.RFC3339),
				"rotation_reason": "scheduled",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
		assert.Equal(t, "act-1", got.ActionID)
		assert.Equal(t, "/dev/sda3", got.DevicePath)
		assert.Equal(t, "ENC:secret", got.Passphrase)
		assert.True(t, got.RotatedAt.Equal(rotatedAt))
		assert.Equal(t, "scheduled", got.RotationReason)
	})

	t.Run("missing rotation_reason defaults to scheduled", func(t *testing.T) {
		got, err := projectors.LuksKeyRotatedFromEvent(store.PersistedEvent{
			StreamType: "luks_key",
			EventType:  "LuksKeyRotated",
			Data: jsonOrFail(t, map[string]any{
				"device_id":   "d", "action_id": "a", "device_path": "/dev/sda1",
				"passphrase": "ENC:s", "rotated_at": rotatedAt.Format(time.RFC3339),
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "scheduled", got.RotationReason)
	})

	t.Run("wrong stream_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.LuksKeyRotatedFromEvent(store.PersistedEvent{
			StreamType: "lps_password",
			EventType:  "LuksKeyRotated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("wrong event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.LuksKeyRotatedFromEvent(store.PersistedEvent{
			StreamType: "luks_key",
			EventType:  "LuksDeviceKeyRevoked",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("required fields are validated individually", func(t *testing.T) {
		base := map[string]any{
			"device_id":   "dev-1",
			"action_id":   "act-1",
			"device_path": "/dev/sda1",
			"passphrase":  "ENC:s",
			"rotated_at":  rotatedAt.Format(time.RFC3339),
		}
		for _, drop := range []string{"device_id", "action_id", "device_path", "passphrase", "rotated_at"} {
			t.Run("missing "+drop, func(t *testing.T) {
				payload := map[string]any{}
				for k, v := range base {
					if k == drop {
						continue
					}
					payload[k] = v
				}
				_, err := projectors.LuksKeyRotatedFromEvent(store.PersistedEvent{
					StreamType: "luks_key",
					EventType:  "LuksKeyRotated",
					Data:       jsonOrFail(t, payload),
				})
				require.Error(t, err)
				assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
				assert.Contains(t, err.Error(), drop)
			})
		}
	})

	t.Run("malformed payload → validation error", func(t *testing.T) {
		_, err := projectors.LuksKeyRotatedFromEvent(store.PersistedEvent{
			StreamType: "luks_key",
			EventType:  "LuksKeyRotated",
			Data:       []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestLuksRevocationFromEvent_Pure covers the three revocation event
// types that the PL/pgSQL projector treated as UPDATE-only operations
// against the current row. Each one writes a different
// (status, error, at) triple — the test enumerates them in one place
// so a regression to any branch shows up as a focused failure.
func TestLuksRevocationFromEvent_Pure(t *testing.T) {
	at := time.Date(2026, 5, 4, 14, 0, 0, 0, time.UTC)

	t.Run("dispatched", func(t *testing.T) {
		got, err := projectors.LuksRevocationDispatchedFromEvent(store.PersistedEvent{
			StreamType: "luks_key",
			EventType:  "LuksDeviceKeyRevocationDispatched",
			Data: jsonOrFail(t, map[string]any{
				"device_id":     "dev-1",
				"action_id":     "act-1",
				"dispatched_at": at.Format(time.RFC3339),
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
		assert.Equal(t, "act-1", got.ActionID)
		assert.Equal(t, "dispatched", got.Status)
		assert.Nil(t, got.Error)
		assert.True(t, got.At.Equal(at))
	})

	t.Run("revoked", func(t *testing.T) {
		got, err := projectors.LuksRevokedFromEvent(store.PersistedEvent{
			StreamType: "luks_key",
			EventType:  "LuksDeviceKeyRevoked",
			Data: jsonOrFail(t, map[string]any{
				"device_id":  "dev-1",
				"action_id":  "act-1",
				"revoked_at": at.Format(time.RFC3339),
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "success", got.Status)
		assert.Nil(t, got.Error)
		assert.True(t, got.At.Equal(at))
	})

	t.Run("failed", func(t *testing.T) {
		got, err := projectors.LuksRevocationFailedFromEvent(store.PersistedEvent{
			StreamType: "luks_key",
			EventType:  "LuksDeviceKeyRevocationFailed",
			Data: jsonOrFail(t, map[string]any{
				"device_id": "dev-1",
				"action_id": "act-1",
				"error":     "agent unreachable",
				"failed_at": at.Format(time.RFC3339),
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "failed", got.Status)
		require.NotNil(t, got.Error)
		assert.Equal(t, "agent unreachable", *got.Error)
		assert.True(t, got.At.Equal(at))
	})

	t.Run("wrong stream_type is ignored", func(t *testing.T) {
		_, err := projectors.LuksRevocationDispatchedFromEvent(store.PersistedEvent{
			StreamType: "lps_password",
			EventType:  "LuksDeviceKeyRevocationDispatched",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("wrong event_type is ignored per-decoder", func(t *testing.T) {
		// Each decoder is paired with one event_type; cross-pairs
		// must return ErrIgnoredEvent so the listener wrapper can
		// silently no-op without a warning log.
		_, err := projectors.LuksRevocationDispatchedFromEvent(store.PersistedEvent{
			StreamType: "luks_key", EventType: "LuksDeviceKeyRevoked",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.LuksRevokedFromEvent(store.PersistedEvent{
			StreamType: "luks_key", EventType: "LuksDeviceKeyRevocationDispatched",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.LuksRevocationFailedFromEvent(store.PersistedEvent{
			StreamType: "luks_key", EventType: "LuksDeviceKeyRevoked",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("required fields validated for each variant", func(t *testing.T) {
		// Each variant requires (device_id, action_id, <its_at>);
		// failed additionally requires error. The decoder names the
		// missing field in its error so listener logs are actionable.
		_, err := projectors.LuksRevocationDispatchedFromEvent(store.PersistedEvent{
			StreamType: "luks_key", EventType: "LuksDeviceKeyRevocationDispatched",
			Data: jsonOrFail(t, map[string]any{"action_id": "a", "dispatched_at": at.Format(time.RFC3339)}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "device_id")

		_, err = projectors.LuksRevocationFailedFromEvent(store.PersistedEvent{
			StreamType: "luks_key", EventType: "LuksDeviceKeyRevocationFailed",
			Data: jsonOrFail(t, map[string]any{
				"device_id": "d", "action_id": "a", "failed_at": at.Format(time.RFC3339),
				// no error
			}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error")
	})
}

// TestLuksKeyListener_RotationLifecycle walks 4 rotations through the
// listener for the same (device, action, device_path) and asserts the
// projection ends with exactly 1 current + 2 history rows (trim-to-3).
func TestLuksKeyListener_RotationLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deviceID := "device-" + testutil.NewID()
	actionID := "action-" + testutil.NewID()
	devicePath := "/dev/sda1"

	rotations := []struct {
		passphrase string
		rotatedAt  time.Time
		reason     string
	}{
		{"ENC:p1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "scheduled"},
		{"ENC:p2", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), "scheduled"},
		{"ENC:p3", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), "manual"},
		{"ENC:p4", time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), "scheduled"},
	}
	for i, r := range rotations {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "luks_key",
			StreamID:   testutil.NewID(),
			EventType:  "LuksKeyRotated",
			Data: map[string]any{
				"device_id":       deviceID,
				"action_id":       actionID,
				"device_path":     devicePath,
				"passphrase":      r.passphrase,
				"rotated_at":      r.rotatedAt.Format(time.RFC3339),
				"rotation_reason": r.reason,
			},
			ActorType: "device",
			ActorID:   deviceID,
		}), "rotation %d", i)
	}

	current, err := st.Queries().GetCurrentLuksKeyForAction(ctx, db.GetCurrentLuksKeyForActionParams{DeviceID: deviceID, ActionID: actionID})
	require.NoError(t, err)
	assert.Equal(t, "ENC:p4", current.Passphrase)
	assert.Equal(t, "scheduled", current.RotationReason)

	all := dumpLuksKeysForAction(t, st, deviceID, actionID, devicePath)
	assert.Len(t, all, 3, "TrimLuksKeysToLast3 keeps current + 2 prior")
	currentCount := 0
	for _, k := range all {
		if k.IsCurrent {
			currentCount++
		}
	}
	assert.Equal(t, 1, currentCount, "exactly one is_current=TRUE row per (device,action,device_path) after the latest rotation")
}

// TestLuksKeyListener_PerActionPathScope confirms a rotation for one
// (action, device_path) does NOT touch another (action, device_path)
// on the same device. The PL/pgSQL projector keyed its UPDATE / DELETE
// on the full triple; a regression that drops device_path from the
// WHERE clause would silently invalidate other partition keys.
func TestLuksKeyListener_PerActionPathScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deviceID := "device-" + testutil.NewID()

	rotate := func(actionID, devicePath, passphrase string, rotatedAt time.Time) {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "luks_key",
			StreamID:   testutil.NewID(),
			EventType:  "LuksKeyRotated",
			Data: map[string]any{
				"device_id":       deviceID,
				"action_id":       actionID,
				"device_path":     devicePath,
				"passphrase":      passphrase,
				"rotated_at":      rotatedAt.Format(time.RFC3339),
				"rotation_reason": "scheduled",
			},
			ActorType: "device",
			ActorID:   deviceID,
		}))
	}

	rotate("act-A", "/dev/sda1", "ENC:A1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rotate("act-B", "/dev/sda2", "ENC:B1", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	rotate("act-A", "/dev/sda1", "ENC:A2", time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC))

	current, err := st.Queries().GetCurrentLuksKeys(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, current, 2, "one current row per (action, device_path)")
	byKey := map[string]string{}
	for _, k := range current {
		byKey[k.ActionID+":"+k.DevicePath] = k.Passphrase
	}
	assert.Equal(t, "ENC:A2", byKey["act-A:/dev/sda1"])
	assert.Equal(t, "ENC:B1", byKey["act-B:/dev/sda2"], "act-B's row stays current despite act-A's two rotations on the same device")
}

// TestLuksKeyListener_RevocationDispatched walks Rotate → Dispatched
// and asserts the current row's revocation_status flips to 'dispatched'
// without affecting the passphrase.
func TestLuksKeyListener_RevocationDispatched(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID, actionID := "device-"+testutil.NewID(), "action-"+testutil.NewID()

	rotateOnce(t, st, ctx, deviceID, actionID, "/dev/sda1", "ENC:k", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	dispatchedAt := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "luks_key",
		StreamID:   testutil.NewID(),
		EventType:  "LuksDeviceKeyRevocationDispatched",
		Data: map[string]any{
			"device_id":     deviceID,
			"action_id":     actionID,
			"dispatched_at": dispatchedAt.Format(time.RFC3339),
		},
		ActorType: "user", ActorID: "u-1",
	}))

	row, err := st.Queries().GetCurrentLuksKeyForAction(ctx, db.GetCurrentLuksKeyForActionParams{DeviceID: deviceID, ActionID: actionID})
	require.NoError(t, err)
	require.NotNil(t, row.RevocationStatus)
	assert.Equal(t, "dispatched", *row.RevocationStatus)
	assert.Nil(t, row.RevocationError)
	require.NotNil(t, row.RevocationAt)
	assert.True(t, row.RevocationAt.Equal(dispatchedAt))
	assert.Equal(t, "ENC:k", row.Passphrase, "passphrase column is untouched by revocation events")
}

// TestLuksKeyListener_RevocationSuccessFlow walks
// Rotate → Dispatched → Revoked. The Revoked event clears
// revocation_error (PL/pgSQL set it to NULL) and stamps revocation_at
// with revoked_at. The passphrase stays intact for audit history.
func TestLuksKeyListener_RevocationSuccessFlow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID, actionID := "device-"+testutil.NewID(), "action-"+testutil.NewID()

	rotateOnce(t, st, ctx, deviceID, actionID, "/dev/sda1", "ENC:k", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	mustAppend(t, st, ctx, store.Event{
		StreamType: "luks_key", StreamID: testutil.NewID(),
		EventType: "LuksDeviceKeyRevocationDispatched",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID,
			"dispatched_at": time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		},
		ActorType: "user", ActorID: "u-1",
	})

	revokedAt := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	mustAppend(t, st, ctx, store.Event{
		StreamType: "luks_key", StreamID: testutil.NewID(),
		EventType: "LuksDeviceKeyRevoked",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID,
			"revoked_at": revokedAt.Format(time.RFC3339),
		},
		ActorType: "device", ActorID: deviceID,
	})

	row, err := st.Queries().GetCurrentLuksKeyForAction(ctx, db.GetCurrentLuksKeyForActionParams{DeviceID: deviceID, ActionID: actionID})
	require.NoError(t, err)
	require.NotNil(t, row.RevocationStatus)
	assert.Equal(t, "success", *row.RevocationStatus)
	assert.Nil(t, row.RevocationError)
	require.NotNil(t, row.RevocationAt)
	assert.True(t, row.RevocationAt.Equal(revokedAt))
}

// TestLuksKeyListener_RevocationFailedFlow walks Rotate → Failed and
// asserts revocation_status='failed' + revocation_error captured. The
// failure payload's error message must round-trip into the projection
// so operators see WHY revocation failed without diving into the
// event log.
func TestLuksKeyListener_RevocationFailedFlow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID, actionID := "device-"+testutil.NewID(), "action-"+testutil.NewID()

	rotateOnce(t, st, ctx, deviceID, actionID, "/dev/sda1", "ENC:k", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	failedAt := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	mustAppend(t, st, ctx, store.Event{
		StreamType: "luks_key", StreamID: testutil.NewID(),
		EventType: "LuksDeviceKeyRevocationFailed",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID,
			"error":     "dispatch enqueue failed: connection refused",
			"failed_at": failedAt.Format(time.RFC3339),
		},
		ActorType: "system", ActorID: "system",
	})

	row, err := st.Queries().GetCurrentLuksKeyForAction(ctx, db.GetCurrentLuksKeyForActionParams{DeviceID: deviceID, ActionID: actionID})
	require.NoError(t, err)
	require.NotNil(t, row.RevocationStatus)
	assert.Equal(t, "failed", *row.RevocationStatus)
	require.NotNil(t, row.RevocationError)
	assert.Equal(t, "dispatch enqueue failed: connection refused", *row.RevocationError)
	require.NotNil(t, row.RevocationAt)
	assert.True(t, row.RevocationAt.Equal(failedAt))
}

// TestLuksKeyListener_RevocationRequestedIsIgnored — the deleted
// PL/pgSQL projector did NOT have a case for LuksDeviceKeyRevocationRequested
// (it's a marker event the dispatcher handler appends before enqueueing).
// The Go listener must preserve that no-op behaviour or it will
// double-write revocation_status before the dispatch even happens.
func TestLuksKeyListener_RevocationRequestedIsIgnored(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID, actionID := "device-"+testutil.NewID(), "action-"+testutil.NewID()

	rotateOnce(t, st, ctx, deviceID, actionID, "/dev/sda1", "ENC:k", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	mustAppend(t, st, ctx, store.Event{
		StreamType: "luks_key", StreamID: testutil.NewID(),
		EventType: "LuksDeviceKeyRevocationRequested",
		Data: map[string]any{
			"device_id": deviceID, "action_id": actionID,
			"requested_at": time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		},
		ActorType: "user", ActorID: "u-1",
	})

	row, err := st.Queries().GetCurrentLuksKeyForAction(ctx, db.GetCurrentLuksKeyForActionParams{DeviceID: deviceID, ActionID: actionID})
	require.NoError(t, err)
	assert.Nil(t, row.RevocationStatus, "Requested must NOT update revocation_status — that's the Dispatched/Revoked/Failed responsibility")
}

// TestLuksKeyListener_IgnoresWrongStreamType — defensive: any
// luks-shaped event under a different stream_type must be a no-op.
func TestLuksKeyListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := "device-" + testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", // wrong
		StreamID:   testutil.NewID(),
		EventType:  "LuksKeyRotated",
		Data: map[string]any{
			"device_id":   deviceID,
			"action_id":   "a",
			"device_path": "/dev/sda1",
			"passphrase":  "ENC:nope",
			"rotated_at":  time.Now().UTC().Format(time.RFC3339),
		},
		ActorType: "device", ActorID: deviceID,
	}))

	// fireListeners is synchronous (see project memory
	// `feedback_post_commit_listener_is_sync.md`): if the listener
	// were going to write, the row would already be there by the
	// time AppendEvent returns. No sleep needed.
	current, err := st.Queries().GetCurrentLuksKeys(ctx, deviceID)
	require.NoError(t, err)
	assert.Empty(t, current, "wrong-stream-type event must NOT create a luks_keys_projection row")
}

// rotateOnce is a one-event helper for tests that need a current row
// in place before driving a revocation event through the listener.
func rotateOnce(t *testing.T, st *store.Store, ctx context.Context, deviceID, actionID, devicePath, passphrase string, rotatedAt time.Time) {
	t.Helper()
	mustAppend(t, st, ctx, store.Event{
		StreamType: "luks_key", StreamID: testutil.NewID(),
		EventType: "LuksKeyRotated",
		Data: map[string]any{
			"device_id":       deviceID,
			"action_id":       actionID,
			"device_path":     devicePath,
			"passphrase":      passphrase,
			"rotated_at":      rotatedAt.Format(time.RFC3339),
			"rotation_reason": "scheduled",
		},
		ActorType: "device", ActorID: deviceID,
	})
}

func mustAppend(t *testing.T, st *store.Store, ctx context.Context, e store.Event) {
	t.Helper()
	require.NoError(t, st.AppendEvent(ctx, e))
}

// dumpLuksKeysForAction reads every row matching the partition key
// (current + history) so the lifecycle test can assert the trim count.
// Inline rather than a sqlc query because no production caller needs
// it.
func dumpLuksKeysForAction(t *testing.T, st *store.Store, deviceID, actionID, devicePath string) []luksKeyRow {
	t.Helper()
	rows, err := st.Pool().Query(context.Background(),
		`SELECT id, passphrase, rotated_at, is_current, revocation_status FROM luks_keys_projection
		 WHERE device_id = $1 AND action_id = $2 AND device_path = $3
		 ORDER BY rotated_at DESC`,
		deviceID, actionID, devicePath,
	)
	require.NoError(t, err)
	defer rows.Close()
	var out []luksKeyRow
	for rows.Next() {
		var r luksKeyRow
		require.NoError(t, rows.Scan(&r.ID, &r.Passphrase, &r.RotatedAt, &r.IsCurrent, &r.RevocationStatus))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

type luksKeyRow struct {
	ID               string
	Passphrase       string
	RotatedAt        time.Time
	IsCurrent        bool
	RevocationStatus *string
}

// jsonOrFail is defined in lps_password_test.go (same package); re-used here.
var _ = json.Marshal
