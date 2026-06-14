package api

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestRequestDeadlineInterceptor_BoundsHandlerContext pins WS13 #10: the handler
// runs under a bounded context, and a handler that exceeds it observes
// cancellation (surfaced as CodeDeadlineExceeded), while a shorter caller
// deadline is preserved.
func TestRequestDeadlineInterceptor_BoundsHandlerContext(t *testing.T) {
	interceptor := NewRequestDeadlineInterceptor(50 * time.Millisecond)

	t.Run("handler context carries the bound", func(t *testing.T) {
		var gotDeadline bool
		next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			_, gotDeadline = ctx.Deadline()
			return connect.NewResponse(&pm.GetUserResponse{}), nil
		})
		_, err := interceptor.WrapUnary(next)(context.Background(), connect.NewRequest(&pm.GetUserRequest{Id: "x"}))
		require.NoError(t, err)
		assert.True(t, gotDeadline, "the interceptor must set a deadline on the handler context")
	})

	t.Run("handler exceeding the deadline is cancelled", func(t *testing.T) {
		next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			<-ctx.Done() // a handler that respects ctx and runs past the bound
			return nil, connect.NewError(connect.CodeDeadlineExceeded, ctx.Err())
		})
		_, err := interceptor.WrapUnary(next)(context.Background(), connect.NewRequest(&pm.GetUserRequest{Id: "x"}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeDeadlineExceeded, connect.CodeOf(err))
	})

	t.Run("a shorter caller deadline is preserved", func(t *testing.T) {
		var handlerDeadline time.Time
		next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			handlerDeadline, _ = ctx.Deadline()
			return connect.NewResponse(&pm.GetUserResponse{}), nil
		})
		// Caller sets a 5ms deadline — far shorter than the interceptor's 50ms.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		_, err := interceptor.WrapUnary(next)(ctx, connect.NewRequest(&pm.GetUserRequest{Id: "x"}))
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().Add(5*time.Millisecond), handlerDeadline, 40*time.Millisecond,
			"the earlier caller deadline must win over the interceptor's bound")
	})
}
