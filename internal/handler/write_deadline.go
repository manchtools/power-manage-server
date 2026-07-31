package handler

import (
	"context"
	"time"
)

// writeDeadliner is the slice of http.ResponseController the agent stream needs:
// arming a deadline on the underlying transport write.
//
// It exists because connect hands a streaming handler a BidiStream and nothing
// else — no ResponseWriter, no transport handle. A write to a device that has
// stopped reading therefore blocks on TCP backpressure with nothing able to
// interrupt it, and the only bound available from inside the handler would be to
// abandon the write on another goroutine, which races connect's own use of the
// stream once the handler returns.
//
// The middleware, which does hold the ResponseWriter, puts one of these in the
// request context on the way past.
type writeDeadliner interface {
	SetWriteDeadline(time.Time) error
}

type writeDeadlinerKey struct{}

func withWriteDeadliner(ctx context.Context, wd writeDeadliner) context.Context {
	return context.WithValue(ctx, writeDeadlinerKey{}, wd)
}

// writeDeadlinerFrom returns the transport's deadline control, or nil when the
// stream did not come through the middleware (unit tests, and any transport that
// does not support deadlines).
func writeDeadlinerFrom(ctx context.Context) writeDeadliner {
	wd, _ := ctx.Value(writeDeadlinerKey{}).(writeDeadliner)
	return wd
}
