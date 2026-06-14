package handler

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithProxyDeadline_BoundsCall pins WS13 #11: a gateway→control proxy call
// runs under a per-call deadline (so a hung control server can't wedge a worker
// goroutine), and a shorter caller deadline is preserved.
func TestWithProxyDeadline_BoundsCall(t *testing.T) {
	t.Run("bounds an unbounded caller context", func(t *testing.T) {
		ctx, cancel := withProxyDeadline(context.Background())
		defer cancel()
		dl, ok := ctx.Deadline()
		require.True(t, ok, "the proxy call context must carry a deadline")
		assert.WithinDuration(t, time.Now().Add(proxyCallTimeout), dl, 2*time.Second)
	})

	t.Run("preserves a shorter caller deadline", func(t *testing.T) {
		parent, cancelParent := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancelParent()
		ctx, cancel := withProxyDeadline(parent)
		defer cancel()
		dl, ok := ctx.Deadline()
		require.True(t, ok)
		assert.WithinDuration(t, time.Now().Add(50*time.Millisecond), dl, proxyCallTimeout,
			"the earlier caller deadline must win over the per-call bound")
	})
}
