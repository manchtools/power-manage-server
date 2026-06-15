package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
)

// WS16 server#331: a clean agent shutdown must be classified as graceful, not
// re-emitted as an error. isStreamClosed is the classifier; pin every shape it
// must accept and, crucially, that a genuine mid-stream transport error is NOT
// swallowed.
func TestIsStreamClosed(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not a close", nil, false},
		{"bare io.EOF", io.EOF, true},
		{"wrapped io.EOF", fmt.Errorf("receive: %w", io.EOF), true},
		{"context canceled", context.Canceled, true},
		{"wrapped context canceled", fmt.Errorf("ctx: %w", context.Canceled), true},
		{"connect CodeCanceled", connect.NewError(connect.CodeCanceled, errors.New("canceled")), true},
		{"connect CodeUnknown + EOF (v1.18.1 clean-shutdown shape)", connect.NewError(connect.CodeUnknown, errors.New("EOF")), true},
		// present-but-WRONG: real faults must stay errors.
		{"connect CodeInternal", connect.NewError(connect.CodeInternal, errors.New("boom")), false},
		{"connect CodeUnknown without EOF", connect.NewError(connect.CodeUnknown, errors.New("protocol error: unexpected frame")), false},
		{"plain transport error", errors.New("connection reset by peer"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isStreamClosed(tc.err))
		})
	}
}
