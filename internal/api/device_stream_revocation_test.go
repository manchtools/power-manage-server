package api_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// recordingCloser captures which devices were disconnected.
type recordingCloser struct {
	mu      sync.Mutex
	dropped []string
}

func (r *recordingCloser) Unregister(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropped = append(r.dropped, deviceID)
}

func (r *recordingCloser) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.dropped...)
}

// Spec 41 criterion 5. Revoking a certificate stops the NEXT handshake; it does
// nothing to a stream already established, because the certificate is checked
// once at connect and never re-examined. Agent streams are long-lived, so
// without this a superseded device keeps a privileged connection indefinitely.
func TestDeviceStreamRevocation_DropsStreamOnRenewalAndDeletion(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	conns := &recordingCloser{}
	st.RegisterEventListener(api.DeviceStreamRevocationListener(conns, slog.Default()))

	renewed := testutil.CreateTestDevice(t, st, "renewed-host")
	deleted := testutil.CreateTestDevice(t, st, "deleted-host")

	fp := "newfingerprint"
	notAfter := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339Nano)
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   renewed,
		EventType:  string(eventtypes.DeviceCertRenewed),
		Data:       payloads.DeviceCertRenewed{CertFingerprint: &fp, CertNotAfter: &notAfter},
		ActorType:  "device",
		ActorID:    renewed,
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deleted,
		EventType:  string(eventtypes.DeviceDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    "test",
	}))

	dropped := conns.snapshot()
	assert.Contains(t, dropped, renewed,
		"a renewed device's live stream is authenticated with the certificate renewal just superseded")
	assert.Contains(t, dropped, deleted,
		"a deleted device must not keep receiving dispatches on an open stream")
}

// Unrelated events must not disconnect anyone. A listener that dropped streams
// on every device event would disconnect the fleet on routine heartbeats.
func TestDeviceStreamRevocation_IgnoresUnrelatedEvents(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := t.Context()

	conns := &recordingCloser{}
	st.RegisterEventListener(api.DeviceStreamRevocationListener(conns, slog.Default()))

	deviceID := testutil.CreateTestDevice(t, st, "busy-host")
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  string(eventtypes.DeviceLabelSet),
		Data:       map[string]any{"key": "env", "value": "prod"},
		ActorType:  "user",
		ActorID:    "test",
	}))

	assert.Empty(t, conns.snapshot(), "only revocation-bearing events may drop a stream")
}

// The listener must tolerate an unwired connection manager rather than panic
// inside the post-commit dispatch, which runs synchronously on the append path.
func TestDeviceStreamRevocation_NilCloserIsSafe(t *testing.T) {
	l := api.DeviceStreamRevocationListener(nil, slog.Default())
	require.NotPanics(t, func() {
		l(context.Background(), store.PersistedEvent{
			StreamType: "device",
			StreamID:   "01J0000000000000000000DEVX",
			EventType:  string(eventtypes.DeviceDeleted),
		})
	})
}
