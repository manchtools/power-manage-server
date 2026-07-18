package control

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/gateway/registry"
)

// stubLookup is a DeviceGatewayLookup that returns a fixed answer, so the
// binding-classification test can drive each verdict without a live registry.
type stubLookup struct {
	gw  string
	err error
}

func (s stubLookup) LookupDeviceGateway(context.Context, string) (string, error) {
	return s.gw, s.err
}

// TestVerifyDeviceGatewayBinding_RetryClassification pins spec 31 D5: a
// PERMANENT binding verdict is dropped (SkipRetry), but a TRANSIENT registry
// lookup failure stays retryable — otherwise a Valkey blip silently discards a
// legitimate device-origin event.
func TestVerifyDeviceGatewayBinding_RetryClassification(t *testing.T) {
	newWorker := func(l stubLookup) *InboxWorker {
		return &InboxWorker{logger: slog.Default(), resolver: l}
	}

	t.Run("transient lookup failure is retryable", func(t *testing.T) {
		w := newWorker(stubLookup{err: errors.New("dial tcp: valkey unreachable")})
		err := w.verifyDeviceGatewayBinding(context.Background(), "dev1", "gw1")
		require.Error(t, err)
		assert.False(t, errors.Is(err, asynq.SkipRetry),
			"a transient registry lookup failure must NOT be SkipRetry — the event must be retried, not dropped")
	})

	t.Run("gateway mismatch is a permanent drop", func(t *testing.T) {
		// The device is live on a DIFFERENT gateway → ErrBindingMismatch.
		w := newWorker(stubLookup{gw: "gwOTHER"})
		err := w.verifyDeviceGatewayBinding(context.Background(), "dev1", "gw1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, asynq.SkipRetry),
			"a forged/mismatched binding is permanent → SkipRetry drop")
	})

	t.Run("device not live is a permanent drop", func(t *testing.T) {
		w := newWorker(stubLookup{err: registry.ErrNoGateway})
		err := w.verifyDeviceGatewayBinding(context.Background(), "dev1", "gw1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, asynq.SkipRetry),
			"device-not-live is one of the permanent sentinels → SkipRetry drop")
	})
}
