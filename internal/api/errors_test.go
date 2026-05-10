package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/middleware"
)

// TestApiError_AttachesCodeAndMessage locks the contract that
// every error returned through the api package carries (a) the
// requested Connect code, (b) the message verbatim, (c) a typed
// ErrorDetail with the api.Err* code so the web frontend can map
// the code to a localized i18n key.
func TestApiError_AttachesCodeAndMessage(t *testing.T) {
	err := apiError(ErrUserNotFound, connect.CodeNotFound, "user not found")
	require.NotNil(t, err)
	assert.Equal(t, connect.CodeNotFound, err.Code())
	assert.Contains(t, err.Message(), "user not found")

	details := err.Details()
	require.Len(t, details, 1)
	val, getErr := details[0].Value()
	require.NoError(t, getErr)
	detail, ok := val.(*pm.ErrorDetail)
	require.True(t, ok, "ErrorDetail must be the proto type so the web client can decode it")
	assert.Equal(t, ErrUserNotFound, detail.Code)
	assert.Empty(t, detail.RequestId, "apiError without context must not synthesize a request id")
}

// TestApiErrorCtx_NoRequestID locks the contract for a context
// without a request-id: the ErrorDetail still carries the code,
// the RequestId field stays empty (web client renders the error
// without a correlation id rather than failing). The hot path
// for the request-id is exercised via the middleware tests in
// internal/middleware/middleware_test.go.
func TestApiErrorCtx_NoRequestID(t *testing.T) {
	err := apiErrorCtx(context.Background(), ErrInternal, connect.CodeInternal, "boom")
	require.NotNil(t, err)
	assert.Equal(t, connect.CodeInternal, err.Code())

	details := err.Details()
	require.Len(t, details, 1)
	val, getErr := details[0].Value()
	require.NoError(t, getErr)
	detail, ok := val.(*pm.ErrorDetail)
	require.True(t, ok)
	assert.Equal(t, ErrInternal, detail.Code)
	assert.Empty(t, detail.RequestId)
	assert.Equal(t, middleware.RequestIDFromContext(context.Background()), detail.RequestId)
}

// TestErrCodes_AreSnakeCase locks the convention that every Err*
// constant is snake_case — the web/messages/{en,de}.json keys are
// `error_<code>` so a typo in casing here means a missing
// localization fallback.
func TestErrCodes_AreSnakeCase(t *testing.T) {
	cases := []string{
		ErrUserNotFound,
		ErrEmailAlreadyExists,
		ErrPermissionDenied,
		ErrNotAuthenticated,
		ErrInternal,
		ErrInvalidPageToken,
		ErrValidationFailed,
		ErrSCIMAlreadyEnabled,
		ErrTerminalNotConfigured,
		ErrGatewayNotRegistered,
		ErrLastAuthMethod,
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			for _, r := range c {
				if r == '_' {
					continue
				}
				assert.True(t, r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'),
					"error code %q has non-snake_case rune %q", c, r)
			}
		})
	}
}
