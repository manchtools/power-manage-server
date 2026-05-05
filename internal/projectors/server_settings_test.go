package projectors_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestServerSettingsUpdatedFromEvent_Pure exercises the decoder.
// The PL/pgSQL projector used `COALESCE((event.data->>'k')::BOOLEAN,
// existing)` to preserve unset fields, so the Go shape must
// distinguish "field present in payload" from "field omitted" — a
// plain bool would conflate omitted with explicit false. The
// decoder returns *bool fields so the listener can pass nil through
// to the SQL UPDATE which uses COALESCE on the receiving side.
func TestServerSettingsUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("happy path with both fields", func(t *testing.T) {
		got, err := projectors.ServerSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "server_settings",
			EventType:  "ServerSettingUpdated",
			Data: jsonOrFail(t, map[string]any{
				"user_provisioning_enabled": true,
				"ssh_access_for_all":        false,
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.UserProvisioningEnabled)
		assert.True(t, *got.UserProvisioningEnabled)
		require.NotNil(t, got.SshAccessForAll)
		assert.False(t, *got.SshAccessForAll)
	})

	t.Run("partial update: only user_provisioning_enabled", func(t *testing.T) {
		got, err := projectors.ServerSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "server_settings",
			EventType:  "ServerSettingUpdated",
			Data: jsonOrFail(t, map[string]any{
				"user_provisioning_enabled": true,
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.UserProvisioningEnabled)
		assert.True(t, *got.UserProvisioningEnabled)
		assert.Nil(t, got.SshAccessForAll, "omitted field stays nil so the SQL UPDATE preserves the existing column value via COALESCE")
	})

	t.Run("partial update: only ssh_access_for_all", func(t *testing.T) {
		got, err := projectors.ServerSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "server_settings",
			EventType:  "ServerSettingUpdated",
			Data: jsonOrFail(t, map[string]any{
				"ssh_access_for_all": true,
			}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.UserProvisioningEnabled, "omitted field stays nil")
		require.NotNil(t, got.SshAccessForAll)
		assert.True(t, *got.SshAccessForAll)
	})

	t.Run("empty payload: both fields nil (caller decides whether that's an error)", func(t *testing.T) {
		got, err := projectors.ServerSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "server_settings",
			EventType:  "ServerSettingUpdated",
			Data:       jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.UserProvisioningEnabled)
		assert.Nil(t, got.SshAccessForAll)
	})

	t.Run("wrong stream_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ServerSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "luks_key",
			EventType:  "ServerSettingUpdated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("wrong event_type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.ServerSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "server_settings",
			EventType:  "Whatever",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.ServerSettingsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "server_settings",
			EventType:  "ServerSettingUpdated",
			Data:       []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestServerSettingsListener_FullUpdate drives a both-fields update
// through the listener and asserts the global row reflects them.
// The seed row from migration starts with both flags false; flipping
// to both-true is the canary case.
func TestServerSettingsListener_FullUpdate(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "server_settings",
		StreamID:   "global",
		EventType:  "ServerSettingUpdated",
		Data: map[string]any{
			"user_provisioning_enabled": true,
			"ssh_access_for_all":        true,
		},
		ActorType: "system", ActorID: "system",
	}))

	settings, err := st.Queries().GetServerSettings(ctx)
	require.NoError(t, err)
	assert.True(t, settings.UserProvisioningEnabled)
	assert.True(t, settings.SshAccessForAll)
	assert.Greater(t, settings.ProjectionVersion, int64(0), "projection_version stamps the event sequence_num")
}

// TestServerSettingsListener_PartialUpdate confirms COALESCE
// semantics: omitting a field in the payload leaves the existing
// column value alone. This is the contract the existing settings
// handler depends on for partial UpdateServerSettings RPCs.
func TestServerSettingsListener_PartialUpdate(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// Step 1: set both to true
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "server_settings", StreamID: "global",
		EventType: "ServerSettingUpdated",
		Data: map[string]any{
			"user_provisioning_enabled": true,
			"ssh_access_for_all":        true,
		},
		ActorType: "system", ActorID: "system",
	}))
	v1, err := st.Queries().GetServerSettings(ctx)
	require.NoError(t, err)
	require.True(t, v1.UserProvisioningEnabled && v1.SshAccessForAll)

	// Step 2: payload omits ssh_access_for_all entirely. The PL/pgSQL
	// `COALESCE((event.data->>'ssh_access_for_all')::BOOLEAN, existing)`
	// preserved the prior TRUE; the Go listener must do the same.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "server_settings", StreamID: "global",
		EventType: "ServerSettingUpdated",
		Data: map[string]any{
			"user_provisioning_enabled": false,
		},
		ActorType: "system", ActorID: "system",
	}))
	v2, err := st.Queries().GetServerSettings(ctx)
	require.NoError(t, err)
	assert.False(t, v2.UserProvisioningEnabled, "user_provisioning_enabled flipped to false")
	assert.True(t, v2.SshAccessForAll, "ssh_access_for_all preserved by COALESCE because the payload omitted it")
	assert.Greater(t, v2.ProjectionVersion, v1.ProjectionVersion, "projection_version monotonically increases")
}

// TestServerSettingsListener_StaleReplayRejected confirms the
// projection_version guard rejects an UPDATE whose
// projection_version is older than the row's current value. The
// reconciler safety net occasionally replays past events; without
// the guard, an old "user_provisioning_enabled=false" event would
// silently undo a later flip to true.
func TestServerSettingsListener_StaleReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	// Land a "true" event (gets the latest projection_version).
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "server_settings", StreamID: "global",
		EventType: "ServerSettingUpdated",
		Data:      map[string]any{"user_provisioning_enabled": true, "ssh_access_for_all": true},
		ActorType: "system", ActorID: "system",
	}))
	beforeReplay, err := st.Queries().GetServerSettings(ctx)
	require.NoError(t, err)
	require.True(t, beforeReplay.UserProvisioningEnabled)

	// Replay the same event semantics with an artificially older
	// projection_version directly via the sqlc query — the listener's
	// SQL guard `WHERE projection_version < $N` should reject.
	older := beforeReplay.ProjectionVersion - 5
	require.NoError(t, projectors.ApplyServerSettingsUpdateForTest(ctx, st, projectors.ServerSettingsUpdate{
		UserProvisioningEnabled: boolPtr(false),
		SshAccessForAll:         boolPtr(false),
		OccurredAt:              beforeReplay.UpdatedAt,
		ProjectionVersion:       older,
	}))

	after, err := st.Queries().GetServerSettings(ctx)
	require.NoError(t, err)
	assert.True(t, after.UserProvisioningEnabled, "stale projection_version must NOT clobber the fresher TRUE state")
	assert.True(t, after.SshAccessForAll)
	assert.Equal(t, beforeReplay.ProjectionVersion, after.ProjectionVersion, "projection_version unchanged when guard rejects")
}

// TestServerSettingsListener_IgnoresWrongStreamType — defensive.
// fireListeners is sync (project memory); a no-op listener must
// leave the projection bytes untouched.
func TestServerSettingsListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	pre, err := st.Queries().GetServerSettings(ctx)
	require.NoError(t, err)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", // wrong
		StreamID:   "global",
		EventType:  "ServerSettingUpdated",
		Data:       map[string]any{"user_provisioning_enabled": true},
		ActorType:  "system", ActorID: "system",
	}))

	post, err := st.Queries().GetServerSettings(ctx)
	require.NoError(t, err)
	assert.Equal(t, pre.UserProvisioningEnabled, post.UserProvisioningEnabled)
	assert.Equal(t, pre.ProjectionVersion, post.ProjectionVersion, "wrong-stream-type event must NOT advance projection_version")
}

func boolPtr(b bool) *bool { return &b }
