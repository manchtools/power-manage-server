package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
)

// RequestDeadline is the default upper bound applied to every unary control RPC
// (WS13 #10). It backstops the DB statement_timeout: a handler that ignores
// cancellation or makes an unbounded non-DB call still cannot run forever.
// Generous enough for any interactive RPC (heavy operations are rate-limited and
// DB-bounded); operator-driven replays run via the CLI, not an RPC.
const RequestDeadline = 30 * time.Second

// NewRequestDeadlineInterceptor returns a unary interceptor that bounds each
// handler's context to at most d. Streaming RPCs pass through untouched
// (connect.UnaryInterceptorFunc only wraps unary) — the control server has no
// streaming RPCs and the gateway's agent stream is intentionally long-lived. A
// shorter caller-supplied deadline is preserved (context honours the earliest).
func NewRequestDeadlineInterceptor(d time.Duration) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			ctx, cancel := context.WithTimeout(ctx, d)
			defer cancel()
			return next(ctx, req)
		}
	}
}
