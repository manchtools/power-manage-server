package api_test

// Logging-interceptor coverage (manchtools/power-manage-server#155
// audit F034). The interceptor's severity-mapping branch
// (Warn for client errors / Error for server errors) is the most
// regression-prone surface — a misclassified server error gets
// missed by oncall pages, a misclassified client error spams them.
// These tests pin the mapping so a future addition or removal of
// a CodeXxx case doesn't drift silently.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/manchtools/power-manage/server/internal/api"
)

// captureLogs builds a slog.Logger that writes JSON records into a
// bytes buffer. Tests parse the records to assert level + key fields.
func captureLogs() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), &buf
}

// runInterceptor invokes the WrapUnary chain with `next` returning
// the supplied resp + err. Returns the buffered log output for
// assertion. Spec().Procedure is filled in via a fresh AnyRequest
// — connect's request type carries it on the spec.
func runInterceptor(t *testing.T, logger *slog.Logger, nextErr error) {
	t.Helper()
	ic := api.NewLoggingInterceptor(logger)
	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		if nextErr != nil {
			return nil, nextErr
		}
		return connect.NewResponse(&emptypb.Empty{}), nil
	}
	wrapped := ic.WrapUnary(next)
	req := connect.NewRequest(&emptypb.Empty{})
	_, _ = wrapped(context.Background(), req)
}

// parseLogLevels reads the buffer (one JSON record per line) and
// returns the level of each record in order.
func parseLogLevels(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var levels []string
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		levels = append(levels, rec["level"].(string))
	}
	return levels
}

func TestLoggingInterceptor_HappyPath_LogsAtDebug(t *testing.T) {
	logger, buf := captureLogs()
	runInterceptor(t, logger, nil)
	assert.Equal(t, []string{"DEBUG"}, parseLogLevels(t, buf))
}

func TestLoggingInterceptor_ClientError_LogsAtWarn(t *testing.T) {
	cases := []struct {
		name string
		code connect.Code
	}{
		{"InvalidArgument", connect.CodeInvalidArgument},
		{"NotFound", connect.CodeNotFound},
		{"AlreadyExists", connect.CodeAlreadyExists},
		{"PermissionDenied", connect.CodePermissionDenied},
		{"Unauthenticated", connect.CodeUnauthenticated},
		{"FailedPrecondition", connect.CodeFailedPrecondition},
		{"ResourceExhausted", connect.CodeResourceExhausted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logger, buf := captureLogs()
			runInterceptor(t, logger, connect.NewError(c.code, errors.New("boom")))
			levels := parseLogLevels(t, buf)
			require.Len(t, levels, 1)
			assert.Equal(t, "WARN", levels[0],
				"client-class connect code %q must log at Warn — Error would page oncall on a user-input bug", c.code.String())
		})
	}
}

func TestLoggingInterceptor_ServerError_LogsAtError(t *testing.T) {
	cases := []struct {
		name string
		code connect.Code
	}{
		{"Internal", connect.CodeInternal},
		{"Unavailable", connect.CodeUnavailable},
		{"Unknown", connect.CodeUnknown},
		{"DataLoss", connect.CodeDataLoss},
		{"DeadlineExceeded", connect.CodeDeadlineExceeded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logger, buf := captureLogs()
			runInterceptor(t, logger, connect.NewError(c.code, errors.New("boom")))
			levels := parseLogLevels(t, buf)
			require.Len(t, levels, 1)
			assert.Equal(t, "ERROR", levels[0],
				"server-class connect code %q must log at Error so oncall sees it; Warn would silently swallow", c.code.String())
		})
	}
}

func TestLoggingInterceptor_NonConnectError_LogsAtError(t *testing.T) {
	// A plain error (no connect.Error type) is unexpected from a
	// well-behaved handler — log at Error so the operator sees the
	// missing wrapper rather than missing the misshape entirely.
	logger, buf := captureLogs()
	runInterceptor(t, logger, errors.New("plain error from a handler that forgot to wrap"))
	levels := parseLogLevels(t, buf)
	require.Len(t, levels, 1)
	assert.Equal(t, "ERROR", levels[0])
}
