package projectors_test

import (
	"context"
	"encoding/json"
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

// TestSecurityAlertProjectionFromEvent_Pure exercises the pure
// derivation function without a database. Same input → same output;
// the listener and any future handler-side immediate-render path
// share this function so they cannot diverge.
func TestSecurityAlertProjectionFromEvent_Pure(t *testing.T) {
	occurredAt := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	eventID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	t.Run("happy path with all fields", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]any{
			"alert_type": "tamper",
			"message":    "Filesystem checksum mismatch",
			"details":    map[string]any{"path": "/etc/shadow"},
		})
		event := store.PersistedEvent{
			ID:         eventID,
			StreamType: "device",
			StreamID:   "DEV1",
			EventType:  "SecurityAlert",
			Data:       payload,
			OccurredAt: occurredAt,
		}

		got, err := projectors.SecurityAlertProjectionFromEvent(event)
		require.NoError(t, err)
		assert.Equal(t, eventID, got.EventID)
		assert.Equal(t, "DEV1", got.DeviceID)
		assert.Equal(t, "tamper", got.AlertType)
		assert.Equal(t, "Filesystem checksum mismatch", got.Message)
		assert.JSONEq(t, `{"path":"/etc/shadow"}`, string(got.Details))
		assert.Equal(t, occurredAt, got.RaisedAt)
	})

	t.Run("missing details is empty bytes, not error", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]any{"alert_type": "x", "message": "y"})
		got, err := projectors.SecurityAlertProjectionFromEvent(store.PersistedEvent{
			ID: eventID, StreamType: "device", StreamID: "DEV1",
			EventType: "SecurityAlert", Data: payload, OccurredAt: occurredAt,
		})
		require.NoError(t, err)
		assert.Empty(t, got.Details, "missing details ⇒ no bytes; matches the deleted PL/pgSQL projector's NULL semantics")
	})

	t.Run("wrong event type is silently ignored", func(t *testing.T) {
		_, err := projectors.SecurityAlertProjectionFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "DeviceRegistered",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent),
			"projector must signal ignore so the listener can no-op without logging")
	})

	t.Run("wrong stream type is silently ignored", func(t *testing.T) {
		_, err := projectors.SecurityAlertProjectionFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "SecurityAlert",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("malformed JSON returns a real error", func(t *testing.T) {
		_, err := projectors.SecurityAlertProjectionFromEvent(store.PersistedEvent{
			ID: eventID, StreamType: "device", StreamID: "DEV1",
			EventType: "SecurityAlert", Data: []byte("not-json"), OccurredAt: occurredAt,
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent),
			"a malformed payload is a real fault, not an ignore — operator must see it")
	})
}

func TestSecurityAlertAckParamsFromEvent_Pure(t *testing.T) {
	alertID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	occurredAt := time.Date(2026, 5, 4, 13, 0, 0, 0, time.UTC)

	t.Run("happy path", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]any{
			"alert_id":        alertID.String(),
			"acknowledged_by": "admin@example.com",
		})
		got, err := projectors.SecurityAlertAckParamsFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "SecurityAlertAcknowledged",
			Data: payload, OccurredAt: occurredAt,
		})
		require.NoError(t, err)
		assert.Equal(t, alertID, got.Column1)
		require.NotNil(t, got.AcknowledgedAt)
		assert.Equal(t, occurredAt, *got.AcknowledgedAt)
		require.NotNil(t, got.AcknowledgedBy)
		assert.Equal(t, "admin@example.com", *got.AcknowledgedBy)
	})

	t.Run("malformed alert_id is a real error", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]any{"alert_id": "not-a-uuid"})
		_, err := projectors.SecurityAlertAckParamsFromEvent(store.PersistedEvent{
			StreamType: "device", EventType: "SecurityAlertAcknowledged",
			Data: payload, OccurredAt: occurredAt,
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent),
			"a bad alert_id is a real fault — the deleted PL/pgSQL projector RAISE'd in this case")
	})
}

// TestSecurityAlertListener_EndToEnd exercises the full pipeline:
// register the listener → AppendEvent → poll for the projection
// row to appear. Proves the listener writes correctly and that the
// row's contents match what the pure derivation produced.
//
// Polling is required because the listener fires post-commit on a
// separate goroutine — the AppendEvent call returns before the
// projection insert lands. 1s budget at 20ms intervals is generous;
// in practice the row appears within 1–2 polls on a warm container.
func TestSecurityAlertListener_EndToEnd(t *testing.T) {
	st := testutil.SetupPostgres(t)
	logger := slog.Default()
	st.RegisterEventListener(projectors.SecurityAlertListener(st, logger))

	ctx := context.Background()
	deviceID := testutil.CreateTestDevice(t, st, "alert-host-"+testutil.NewID())

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "SecurityAlert",
		Data: map[string]any{
			"alert_type": "tamper",
			"message":    "checksum mismatch",
			"details":    map[string]any{"path": "/etc/shadow"},
		},
		ActorType: "device",
		ActorID:   deviceID,
	}))

	listParams := db.ListSecurityAlertsForDeviceParams{
		DeviceID:            deviceID,
		IncludeAcknowledged: true,
		PageSize:            10,
		PageOffset:          0,
	}

	var alerts []db.ListSecurityAlertsForDeviceRow
	for i := 0; i < 50; i++ {
		var err error
		alerts, err = st.Queries().ListSecurityAlertsForDevice(ctx, listParams)
		require.NoError(t, err)
		if len(alerts) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Len(t, alerts, 1, "listener must have written the SecurityAlert projection within the polling window")

	got := alerts[0]
	assert.Equal(t, deviceID, got.DeviceID)
	assert.Equal(t, "tamper", got.AlertType)
	assert.Equal(t, "checksum mismatch", got.Message)
	assert.JSONEq(t, `{"path":"/etc/shadow"}`, string(got.Details))
	assert.False(t, got.Acknowledged, "newly-raised alert should not be acknowledged")

	// Now exercise the SecurityAlertAcknowledged path end-to-end.
	// Uses the alert's event_id as the alert_id payload — same
	// shape the (deleted) PL/pgSQL projector matched on. CR catch
	// on PR #117: this branch including the rows == 0 detection
	// was previously not integration-tested.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "SecurityAlertAcknowledged",
		Data: map[string]any{
			"alert_id":        got.EventID.String(),
			"acknowledged_by": "ops@example.com",
		},
		ActorType: "user",
		ActorID:   "ops@example.com",
	}))

	for i := 0; i < 50; i++ {
		alerts, err := st.Queries().ListSecurityAlertsForDevice(ctx, listParams)
		require.NoError(t, err)
		require.Len(t, alerts, 1)
		if alerts[0].Acknowledged {
			require.NotNil(t, alerts[0].AcknowledgedAt)
			require.NotNil(t, alerts[0].AcknowledgedBy)
			assert.Equal(t, "ops@example.com", *alerts[0].AcknowledgedBy)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener did not apply SecurityAlertAcknowledged within polling window")
}
