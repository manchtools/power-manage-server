package projectors_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// ============================================================================
// Pure decoder tests — pin the field defaults that match the deleted
// PL/pgSQL project_device_event() COALESCE / NULL semantics.
// ============================================================================

// TestDeviceRegisteredFromEvent_Pure pins the decoder defaults: missing
// hostname → "" (matches PL/pgSQL `COALESCE(payload, "")`); missing
// labels → "{}"; missing cert_fingerprint stays nil so the column lands
// as SQL NULL (matches PL/pgSQL permissive behaviour); assigned_user_id
// is nullable.
func TestDeviceRegisteredFromEvent_Pure(t *testing.T) {
	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.DeviceRegisteredFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceRegistered", ActorID: "u-1",
			Data: jsonOrFail(t, map[string]any{
				"hostname":              "host-1",
				"cert_fingerprint":      "abc123",
				"registration_token_id": "tok-1",
				"labels":                map[string]any{"env": "prod"},
				"assigned_user_id":      "user-A",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.ID)
		assert.Equal(t, "host-1", got.Hostname)
		require.NotNil(t, got.CertFingerprint)
		assert.Equal(t, "abc123", *got.CertFingerprint)
		require.NotNil(t, got.RegistrationTokenID)
		assert.Equal(t, "tok-1", *got.RegistrationTokenID)
		assert.Contains(t, string(got.Labels), "prod")
		require.NotNil(t, got.AssignedUserID)
		assert.Equal(t, "user-A", *got.AssignedUserID)
	})

	t.Run("defaults: missing hostname → '', missing labels → '{}', missing cert/assigned → nil", func(t *testing.T) {
		got, err := projectors.DeviceRegisteredFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-2", EventType: "DeviceRegistered",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Hostname)
		assert.JSONEq(t, "{}", string(got.Labels))
		assert.Nil(t, got.CertFingerprint)
		assert.Nil(t, got.AssignedUserID)
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceRegisteredFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceRegistered",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.DeviceRegisteredFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceSeen",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed payload bytes is a validation error", func(t *testing.T) {
		_, err := projectors.DeviceRegisteredFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceRegistered",
			Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceSeenFromEvent_Pure — empty payload is valid (heartbeat
// ping); explicit empty hostname collapses to nil so the SQL COALESCE
// preserves the existing column value (matches PL/pgSQL NULLIF).
func TestDeviceSeenFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		v := "2.0.0"
		h := "new-host"
		got, err := projectors.DeviceSeenFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceSeen",
			Data: jsonOrFail(t, map[string]any{"agent_version": v, "hostname": h}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.AgentVersion)
		assert.Equal(t, v, *got.AgentVersion)
		require.NotNil(t, got.Hostname)
		assert.Equal(t, h, *got.Hostname)
	})

	t.Run("empty payload is a valid bare ping", func(t *testing.T) {
		got, err := projectors.DeviceSeenFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceSeen",
			Data: nil,
		})
		require.NoError(t, err)
		assert.Nil(t, got.AgentVersion)
		assert.Nil(t, got.Hostname)
	})

	t.Run("explicit empty hostname collapses to nil (NULLIF)", func(t *testing.T) {
		got, err := projectors.DeviceSeenFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceSeen",
			Data: jsonOrFail(t, map[string]any{"hostname": ""}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.Hostname, "explicit empty hostname must drop to nil so SQL COALESCE preserves the existing value")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceSeenFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceHeartbeat",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceHeartbeatFromEvent_Pure — empty payload valid; missing
// agent_version stays nil so SQL COALESCE preserves existing.
func TestDeviceHeartbeatFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		v := "1.5.0"
		got, err := projectors.DeviceHeartbeatFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceHeartbeat",
			Data: jsonOrFail(t, map[string]any{"agent_version": v}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.AgentVersion)
		assert.Equal(t, v, *got.AgentVersion)
	})

	t.Run("empty payload valid", func(t *testing.T) {
		got, err := projectors.DeviceHeartbeatFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceHeartbeat",
			Data: nil,
		})
		require.NoError(t, err)
		assert.Nil(t, got.AgentVersion)
	})

	t.Run("wrong stream type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceHeartbeatFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceHeartbeat",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceCertRenewedFromEvent_Pure — cert_fingerprint required;
// cert_not_after optional (nil means SQL COALESCE preserves existing).
func TestDeviceCertRenewedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.DeviceCertRenewedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceCertRenewed",
			Data: jsonOrFail(t, map[string]any{
				"cert_fingerprint": "newfp",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "newfp", got.CertFingerprint)
		assert.Nil(t, got.CertNotAfter)
	})

	t.Run("missing cert_fingerprint fails", func(t *testing.T) {
		_, err := projectors.DeviceCertRenewedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceCertRenewed",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "cert_fingerprint")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceCertRenewedFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceSeen",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceLabelsUpdatedFromEvent_Pure — missing labels stays nil so
// the SQL COALESCE preserves the existing column value.
func TestDeviceLabelsUpdatedFromEvent_Pure(t *testing.T) {
	t.Run("explicit labels", func(t *testing.T) {
		got, err := projectors.DeviceLabelsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceLabelsUpdated",
			Data: jsonOrFail(t, map[string]any{"labels": map[string]any{"env": "prod"}}),
		})
		require.NoError(t, err)
		assert.Contains(t, string(got.Labels), "prod")
	})

	t.Run("missing labels stays nil", func(t *testing.T) {
		got, err := projectors.DeviceLabelsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceLabelsUpdated",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Nil(t, got.Labels)
	})

	t.Run("wrong stream type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceLabelsUpdatedFromEvent(store.PersistedEvent{
			StreamType: "device_group", EventType: "DeviceLabelsUpdated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceLabelSetFromEvent_Pure — key required; value defaults to "".
func TestDeviceLabelSetFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.DeviceLabelSetFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceLabelSet",
			Data: jsonOrFail(t, map[string]any{"key": "env", "value": "prod"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "env", got.Key)
		assert.Equal(t, "prod", got.Value)
	})

	t.Run("missing key fails", func(t *testing.T) {
		_, err := projectors.DeviceLabelSetFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceLabelSet",
			Data: jsonOrFail(t, map[string]any{"value": "prod"}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceLabelSetFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceLabelRemoved",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceLabelRemovedFromEvent_Pure — key required.
func TestDeviceLabelRemovedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.DeviceLabelRemovedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceLabelRemoved",
			Data: jsonOrFail(t, map[string]any{"key": "env"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "env", got.Key)
	})

	t.Run("missing key fails", func(t *testing.T) {
		_, err := projectors.DeviceLabelRemovedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceLabelRemoved",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key")
	})
}

// TestDeviceAssignedFromEvent_Pure — user_id required.
func TestDeviceAssignedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.DeviceAssignedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceAssigned",
			Data: jsonOrFail(t, map[string]any{"user_id": "user-X"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
		assert.Equal(t, "user-X", got.UserID)
	})

	t.Run("missing user_id fails", func(t *testing.T) {
		_, err := projectors.DeviceAssignedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceAssigned",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user_id")
	})

	t.Run("wrong event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.DeviceAssignedFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceUnassigned",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestDeviceUnassignedFromEvent_Pure — user_id required.
func TestDeviceUnassignedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.DeviceUnassignedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceUnassigned",
			Data: jsonOrFail(t, map[string]any{"user_id": "user-X"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "user-X", got.UserID)
	})

	t.Run("missing user_id fails", func(t *testing.T) {
		_, err := projectors.DeviceUnassignedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceUnassigned",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user_id")
	})
}

// TestDeviceGroupAssignedFromEvent_Pure — group_id required.
func TestDeviceGroupAssignedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.DeviceGroupAssignedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceGroupAssigned",
			Data: jsonOrFail(t, map[string]any{"group_id": "grp-X"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "dev-1", got.DeviceID)
		assert.Equal(t, "grp-X", got.GroupID)
	})

	t.Run("missing group_id fails", func(t *testing.T) {
		_, err := projectors.DeviceGroupAssignedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceGroupAssigned",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "group_id")
	})
}

// TestDeviceGroupUnassignedFromEvent_Pure — group_id required.
func TestDeviceGroupUnassignedFromEvent_Pure(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.DeviceGroupUnassignedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceGroupUnassigned",
			Data: jsonOrFail(t, map[string]any{"group_id": "grp-X"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "grp-X", got.GroupID)
	})

	t.Run("missing group_id fails", func(t *testing.T) {
		_, err := projectors.DeviceGroupUnassignedFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceGroupUnassigned",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "group_id")
	})
}

// TestDeviceSyncIntervalSetFromEvent_Pure — missing key collapses to 0.
func TestDeviceSyncIntervalSetFromEvent_Pure(t *testing.T) {
	t.Run("explicit value", func(t *testing.T) {
		got, err := projectors.DeviceSyncIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceSyncIntervalSet",
			Data: jsonOrFail(t, map[string]any{"sync_interval_minutes": 15}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(15), got.SyncIntervalMinutes)
	})

	t.Run("missing key → 0", func(t *testing.T) {
		got, err := projectors.DeviceSyncIntervalSetFromEvent(store.PersistedEvent{
			StreamType: "device", StreamID: "dev-1", EventType: "DeviceSyncIntervalSet",
			Data: jsonOrFail(t, map[string]any{}),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(0), got.SyncIntervalMinutes)
	})
}

// ============================================================================
// Integration tests — drive the listener via st.AppendEvent and verify
// the projection lands as expected. Use testutil.SetupPostgres which
// wires projectors.WireAll.
// ============================================================================

// registerDeviceForTest emits a DeviceRegistered event for the given
// device id with a unique cert_fingerprint and returns it. Used as the
// fixture seed for every lifecycle test below.
func registerDeviceForTest(t *testing.T, st *store.Store, ctx context.Context, deviceID, hostname string) {
	t.Helper()
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceRegistered",
		Data: map[string]any{
			"hostname":         hostname,
			"cert_fingerprint": "fp-" + deviceID,
		},
		ActorType: "user", ActorID: "u-1",
	}))
}

// TestDeviceListener_FullLifecycle drives every event type in order
// against a single device and asserts the projection lands in the
// right state at every step.
func TestDeviceListener_FullLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := testutil.NewID()

	// 1. Registered.
	registerDeviceForTest(t, st, ctx, deviceID, "lifecycle")
	got, err := st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.Equal(t, "lifecycle", got.Hostname)
	require.NotNil(t, got.CertFingerprint)
	assert.Equal(t, "fp-"+deviceID, *got.CertFingerprint)
	assert.False(t, got.IsDeleted)

	// 2. Seen — refreshes last_seen_at + agent_version.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceSeen",
		Data:      map[string]any{"agent_version": "2.0.0"},
		ActorType: "agent", ActorID: deviceID,
	}))
	got, err = st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.Equal(t, "2.0.0", got.AgentVersion)

	// 3. Heartbeat — bumps version.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceHeartbeat",
		Data:      map[string]any{"agent_version": "2.0.1"},
		ActorType: "agent", ActorID: deviceID,
	}))
	got, err = st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.Equal(t, "2.0.1", got.AgentVersion)

	// 4. CertRenewed — overwrites fingerprint.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceCertRenewed",
		Data:      map[string]any{"cert_fingerprint": "renewed-fp"},
		ActorType: "agent", ActorID: deviceID,
	}))
	got, err = st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	require.NotNil(t, got.CertFingerprint)
	assert.Equal(t, "renewed-fp", *got.CertFingerprint)

	// 5. LabelsUpdated — REPLACES the entire labels JSONB.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceLabelsUpdated",
		Data:      map[string]any{"labels": map[string]any{"env": "prod", "region": "eu"}},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.Contains(t, string(got.Labels), "prod")
	assert.Contains(t, string(got.Labels), "eu")

	// 6. LabelSet — JSONB merge keeps existing labels and adds the new key.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceLabelSet",
		Data:      map[string]any{"key": "tier", "value": "gold"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.Contains(t, string(got.Labels), "gold", "DeviceLabelSet must merge new key into labels")
	assert.Contains(t, string(got.Labels), "prod", "DeviceLabelSet must preserve existing keys")

	// 7. LabelRemoved — drops the key from labels.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceLabelRemoved",
		Data:      map[string]any{"key": "env"},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.NotContains(t, string(got.Labels), `"env"`, "DeviceLabelRemoved must drop the named key")
	assert.Contains(t, string(got.Labels), "gold", "DeviceLabelRemoved must preserve other keys")

	// 8. SyncIntervalSet — stamps the per-device override.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceSyncIntervalSet",
		Data:      map[string]any{"sync_interval_minutes": 30},
		ActorType: "user", ActorID: "u",
	}))
	got, err = st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.Equal(t, int32(30), got.SyncIntervalMinutes)

	// 9. Assigned — INSERT into device_assigned_users_projection.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceAssigned",
		Data:      map[string]any{"user_id": "user-A"},
		ActorType: "user", ActorID: "u",
	}))
	users, err := st.Queries().ListDeviceAssignedUserIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.Contains(t, users, "user-A")

	// 10. GroupAssigned — INSERT into device_assigned_groups_projection.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceGroupAssigned",
		Data:      map[string]any{"group_id": "grp-A"},
		ActorType: "user", ActorID: "u",
	}))
	groups, err := st.Queries().ListDeviceAssignedGroupIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.Contains(t, groups, "grp-A")

	// 11. Unassigned — DELETE from device_assigned_users_projection.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceUnassigned",
		Data:      map[string]any{"user_id": "user-A"},
		ActorType: "user", ActorID: "u",
	}))
	users, err = st.Queries().ListDeviceAssignedUserIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.NotContains(t, users, "user-A")

	// 12. GroupUnassigned — DELETE from device_assigned_groups_projection.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceGroupUnassigned",
		Data:      map[string]any{"group_id": "grp-A"},
		ActorType: "user", ActorID: "u",
	}))
	groups, err = st.Queries().ListDeviceAssignedGroupIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.NotContains(t, groups, "grp-A")

	// Re-add an assignment so we can prove DeviceDeleted's cascade
	// wipes both junction tables.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceAssigned",
		Data:      map[string]any{"user_id": "user-B"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceGroupAssigned",
		Data:      map[string]any{"group_id": "grp-B"},
		ActorType: "user", ActorID: "u",
	}))

	// 13. Deleted — soft-delete + cascade wipe.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	_, err = st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.Error(t, err, "GetDeviceByID filters is_deleted=FALSE; deleted device is gone from this query")

	users, err = st.Queries().ListDeviceAssignedUserIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.Empty(t, users, "DeviceDeleted cascade must wipe assigned-user rows")

	groups, err = st.Queries().ListDeviceAssignedGroupIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.Empty(t, groups, "DeviceDeleted cascade must wipe assigned-group rows")
}

// TestDeviceListener_RegisterRevivesSoftDeleted locks the PL/pgSQL
// projector's revival semantic: a DeviceRegistered against a
// previously soft-deleted device id flips is_deleted=FALSE via
// ON CONFLICT (id) DO UPDATE.
func TestDeviceListener_RegisterRevivesSoftDeleted(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := testutil.NewID()

	registerDeviceForTest(t, st, ctx, deviceID, "live")
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceDeleted",
		Data:      map[string]any{},
		ActorType: "user", ActorID: "u",
	}))

	// Confirm soft-deleted (not visible via filtered query).
	_, err := st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.Error(t, err)

	// Re-register the same id.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceRegistered",
		Data: map[string]any{
			"hostname":         "revived",
			"cert_fingerprint": "fp-revived-" + deviceID,
		},
		ActorType: "user", ActorID: "u-1",
	}))

	got, err := st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err, "DeviceRegistered ON CONFLICT (id) DO UPDATE must revive the soft-deleted row")
	assert.False(t, got.IsDeleted, "is_deleted must be flipped to FALSE on revival")
	assert.Equal(t, "revived", got.Hostname)
}

// TestDeviceListener_RegisterAutoAssignsTokenOwner locks the
// DeviceRegistered cascade: when the payload carries assigned_user_id,
// the listener inserts a row into device_assigned_users_projection
// inside the same transaction.
func TestDeviceListener_RegisterAutoAssignsTokenOwner(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceRegistered",
		Data: map[string]any{
			"hostname":         "auto-assigned",
			"cert_fingerprint": "fp-aa-" + deviceID,
			"assigned_user_id": "owner-X",
		},
		ActorType: "user", ActorID: "tok-owner",
	}))

	users, err := st.Queries().ListDeviceAssignedUserIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.Contains(t, users, "owner-X", "DeviceRegistered with assigned_user_id must auto-insert the assignment")
}

// TestDeviceListener_StaleDeleteReplayDoesNotNukeAssignments locks the
// asymmetric-guard discipline for the cascade-heavy DeviceDeleted: when
// the version-guarded SoftDelete affects zero rows, the cascade
// (assigned-user wipe + assigned-group wipe) MUST be skipped. Otherwise
// an old DeviceDeleted re-applied later would silently nuke a
// freshly-restored device's assignments.
func TestDeviceListener_StaleDeleteReplayDoesNotNukeAssignments(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := testutil.NewID()

	registerDeviceForTest(t, st, ctx, deviceID, "live")
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceAssigned",
		Data:      map[string]any{"user_id": "user-stay"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceGroupAssigned",
		Data:      map[string]any{"group_id": "grp-stay"},
		ActorType: "user", ActorID: "u",
	}))
	live, err := st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)

	// Drive the listener with a stale DeviceDeleted (older
	// projection_version than the row currently has).
	older := live.ProjectionVersion - 5
	staleAt := *live.RegisteredAt
	listener := projectors.DeviceListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &older,
		StreamType:  "device",
		StreamID:    deviceID,
		EventType:   "DeviceDeleted",
		Data:        []byte("{}"),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	// Device still alive.
	stillAlive, err := st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	assert.False(t, stillAlive.IsDeleted, "stale DeviceDeleted must NOT flip is_deleted")

	// Assignments still there — cascade was short-circuited by the
	// SoftDelete returning n == 0.
	users, err := st.Queries().ListDeviceAssignedUserIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.Contains(t, users, "user-stay", "stale DeviceDeleted must NOT cascade-wipe assigned-user rows")
	groups, err := st.Queries().ListDeviceAssignedGroupIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.Contains(t, groups, "grp-stay", "stale DeviceDeleted must NOT cascade-wipe assigned-group rows")
}

// TestDeviceListener_StaleUnassignedAfterReAssignDoesNotWipeRow locks
// the assignment-table DELETE guard (CR catch on PR #179 pattern,
// applied to the device-assignment junction tables). A stale
// DeviceUnassigned replayed AFTER a re-Assign must NOT delete the
// live row, even though the user_id matches: the live row's
// projection_version was bumped by the re-Assign INSERT, so the
// stale Unassigned's older sequence_num fails the SQL guard
// `WHERE projection_version <= $N`.
func TestDeviceListener_StaleUnassignedAfterReAssignDoesNotWipeRow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	deviceID := testutil.NewID()
	userID := "u-stale"

	registerDeviceForTest(t, st, ctx, deviceID, "live")

	// First Assign — establishes a baseline projection_version on the row.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceAssigned",
		Data:      map[string]any{"user_id": userID},
		ActorType: "user", ActorID: "u",
	}))
	// Capture the seq_num that would belong to a "would-be Unassigned"
	// emitted right now (before the re-Assign bumps it). We do this by
	// reading the assignment row's projection_version + 1 — this
	// mirrors the gap a stale event from the past carries.
	var firstAssignVer int64
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT projection_version FROM device_assigned_users_projection WHERE device_id = $1 AND user_id = $2",
		deviceID, userID,
	).Scan(&firstAssignVer))

	// Real Unassigned + Re-Assign — the second Assign bumps the
	// projection_version of the live row past the stale-event mark.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceUnassigned",
		Data:      map[string]any{"user_id": userID},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceAssigned",
		Data:      map[string]any{"user_id": userID},
		ActorType: "user", ActorID: "u",
	}))

	users, err := st.Queries().ListDeviceAssignedUserIDs(ctx, deviceID)
	require.NoError(t, err)
	require.Contains(t, users, userID, "re-Assign must restore the assignment")

	// Now drive the listener with a STALE Unassigned whose sequence_num
	// is the one the original Unassigned would have carried — older
	// than the re-Assign that bumped projection_version. The DELETE
	// guard `WHERE projection_version <= $N` must reject this and
	// leave the live row intact.
	stale := firstAssignVer
	staleAt := *getDeviceRegisteredAt(t, st, ctx, deviceID)
	listener := projectors.DeviceListener(st, slog.Default())
	listener(ctx, store.PersistedEvent{
		ID:          uuid.New(),
		SequenceNum: &stale,
		StreamType:  "device",
		StreamID:    deviceID,
		EventType:   "DeviceUnassigned",
		Data:        jsonOrFail(t, map[string]any{"user_id": userID}),
		ActorType:   "user",
		ActorID:     "u",
		OccurredAt:  staleAt,
	})

	users, err = st.Queries().ListDeviceAssignedUserIDs(ctx, deviceID)
	require.NoError(t, err)
	assert.Contains(t, users, userID,
		"stale DeviceUnassigned replayed after a re-Assign must NOT wipe the live row")
}

// ============================================================================
// Helpers
// ============================================================================

// deviceLookup builds a GetDeviceByIDParams with no user filter (the
// admin-style read path that all tests in this file want).
func deviceLookup(id string) db.GetDeviceByIDParams {
	return db.GetDeviceByIDParams{ID: id}
}

// getDeviceRegisteredAt fetches the device's registered_at timestamp
// directly so stale-event tests can construct a PersistedEvent whose
// OccurredAt sits at a plausible point in the row's history.
func getDeviceRegisteredAt(t *testing.T, st *store.Store, ctx context.Context, deviceID string) *time.Time {
	t.Helper()
	got, err := st.Queries().GetDeviceByID(ctx, deviceLookup(deviceID))
	require.NoError(t, err)
	return got.RegisteredAt
}
