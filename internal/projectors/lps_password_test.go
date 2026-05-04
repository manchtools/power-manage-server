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
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestLpsPasswordRotatedFromEvent_Pure exercises the pure derivation
// function without touching the database. Mirrors the security_alert
// pure tests so a future change to the payload shape (added field,
// renamed key) fails fast at unit-test time.
func TestLpsPasswordRotatedFromEvent_Pure(t *testing.T) {
	rotatedAt := time.Date(2026, 5, 4, 12, 30, 0, 0, time.UTC)

	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.LpsPasswordRotatedFromEvent(store.PersistedEvent{
			StreamType: "lps_password",
			EventType:  "LpsPasswordRotated",
			Data: jsonOrFail(t, map[string]any{
				"device_id":       "dev-1",
				"action_id":       "act-1",
				"username":        "alice",
				"password":        "ENC:secret",
				"rotated_at":      rotatedAt.Format(time.RFC3339),
				"rotation_reason": "scheduled",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
		assert.Equal(t, "act-1", got.ActionID)
		assert.Equal(t, "alice", got.Username)
		assert.Equal(t, "ENC:secret", got.Password)
		assert.True(t, got.RotatedAt.Equal(rotatedAt))
		assert.Equal(t, "scheduled", got.RotationReason)
	})

	t.Run("missing rotation_reason defaults to scheduled", func(t *testing.T) {
		got, err := projectors.LpsPasswordRotatedFromEvent(store.PersistedEvent{
			StreamType: "lps_password",
			EventType:  "LpsPasswordRotated",
			Data: jsonOrFail(t, map[string]any{
				"device_id":  "dev-1",
				"action_id":  "act-1",
				"username":   "alice",
				"password":   "ENC:s",
				"rotated_at": rotatedAt.Format(time.RFC3339),
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "scheduled", got.RotationReason,
			"matches PL/pgSQL COALESCE(... 'scheduled') default so older agents that omit the field stay backward-compatible")
	})

	t.Run("wrong stream_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.LpsPasswordRotatedFromEvent(store.PersistedEvent{
			StreamType: "totp",
			EventType:  "LpsPasswordRotated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("wrong event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.LpsPasswordRotatedFromEvent(store.PersistedEvent{
			StreamType: "lps_password",
			EventType:  "SomethingElse",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("missing device_id is a validation error", func(t *testing.T) {
		_, err := projectors.LpsPasswordRotatedFromEvent(store.PersistedEvent{
			StreamType: "lps_password",
			EventType:  "LpsPasswordRotated",
			Data: jsonOrFail(t, map[string]any{
				"username":   "alice",
				"rotated_at": rotatedAt.Format(time.RFC3339),
			}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent),
			"validation failure must NOT be silently swallowed by the listener wrapper")
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.LpsPasswordRotatedFromEvent(store.PersistedEvent{
			StreamType: "lps_password",
			EventType:  "LpsPasswordRotated",
			Data:       []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestLpsPasswordListener_RotationLifecycle drives four rotations
// through the listener and asserts the projection ends in the right
// state: only the most recent row is is_current=TRUE, history is
// trimmed to 3 rows total. Mirrors the operational invariants the
// PL/pgSQL projector enforced.
func TestLpsPasswordListener_RotationLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deviceID := "device-" + testutil.NewID()
	username := "alice"

	rotations := []struct {
		password  string
		rotatedAt time.Time
		reason    string
	}{
		{"ENC:p1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "scheduled"},
		{"ENC:p2", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), "scheduled"},
		{"ENC:p3", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), "manual"},
		{"ENC:p4", time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), "scheduled"},
	}

	for i, r := range rotations {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "lps_password",
			StreamID:   testutil.NewID(),
			EventType:  "LpsPasswordRotated",
			Data: map[string]any{
				"device_id":       deviceID,
				"action_id":       "action-" + deviceID,
				"username":        username,
				"password":        r.password,
				"rotated_at":      r.rotatedAt.Format(time.RFC3339),
				"rotation_reason": r.reason,
			},
			ActorType: "device",
			ActorID:   deviceID,
		}), "append rotation %d", i)
	}

	// Listener fires synchronously inside AppendEvent (see
	// project_post_commit_listener_is_sync.md), so the assertions
	// don't need to poll. A single read is enough.
	current, err := st.Queries().GetCurrentLpsPasswords(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, current, 1, "exactly one is_current=TRUE row per (device,username) after the latest rotation")
	assert.Equal(t, "ENC:p4", current[0].Password)
	assert.Equal(t, "scheduled", current[0].RotationReason)

	history, err := st.Queries().GetLpsPasswordHistory(ctx, deviceID)
	require.NoError(t, err)
	// 4 rotations → 4 rows minus trim-to-3 → 3 total → 1 current + 2 history.
	assert.Len(t, history, 2, "TrimLpsPasswordsToLast3 keeps current + 2 prior; older rows are deleted")
	gotPasswords := []string{history[0].Password, history[1].Password}
	assert.ElementsMatch(t, []string{"ENC:p3", "ENC:p2"}, gotPasswords)
}

// TestLpsPasswordListener_PerUsernameScope confirms a rotation for
// user A does NOT touch user B's projection, even on the same device.
// The PL/pgSQL projector scoped its UPDATE / DELETE by
// (device_id, username); a regression that drops the username
// predicate would silently invalidate every other user's password on
// the same device, so this is worth a dedicated test.
func TestLpsPasswordListener_PerUsernameScope(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deviceID := "device-" + testutil.NewID()

	rotate := func(username, password string, rotatedAt time.Time) {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "lps_password",
			StreamID:   testutil.NewID(),
			EventType:  "LpsPasswordRotated",
			Data: map[string]any{
				"device_id":       deviceID,
				"action_id":       "act",
				"username":        username,
				"password":        password,
				"rotated_at":      rotatedAt.Format(time.RFC3339),
				"rotation_reason": "scheduled",
			},
			ActorType: "device",
			ActorID:   deviceID,
		}))
	}

	rotate("alice", "ENC:alice-1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rotate("bob", "ENC:bob-1", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	rotate("alice", "ENC:alice-2", time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC))

	current, err := st.Queries().GetCurrentLpsPasswords(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, current, 2, "one current row per user; rotating alice must not flip bob")
	byUser := map[string]string{}
	for _, p := range current {
		byUser[p.Username] = p.Password
	}
	assert.Equal(t, "ENC:alice-2", byUser["alice"])
	assert.Equal(t, "ENC:bob-1", byUser["bob"], "bob's row stays current despite alice's two rotations on the same device")
}

// TestLpsPasswordListener_IgnoresWrongStreamType is the cheap defence
// against a future classifier loosening that would have the listener
// react to LpsPasswordRotated under a different stream_type.
func TestLpsPasswordListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	deviceID := "device-" + testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", // wrong
		StreamID:   testutil.NewID(),
		EventType:  "LpsPasswordRotated",
		Data: map[string]any{
			"device_id":  deviceID,
			"action_id":  "act",
			"username":   "alice",
			"password":   "ENC:nope",
			"rotated_at": time.Now().UTC().Format(time.RFC3339),
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))

	// Long enough for the listener to have fired if it were going to.
	time.Sleep(150 * time.Millisecond)

	current, err := st.Queries().GetCurrentLpsPasswords(ctx, deviceID)
	require.NoError(t, err)
	assert.Empty(t, current, "wrong-stream-type event must NOT create an lps_passwords_projection row")
}

// jsonOrFail marshals the map for the pure-function tests. Inline
// helper to avoid bringing in a json import at every callsite.
func jsonOrFail(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
