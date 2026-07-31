package auth_test

import (
	"io"
	"log/slog"
)

// discardLogger keeps interceptor diagnostics out of the test output.
// The interceptor logs metadata only, so nothing is lost by dropping it.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
