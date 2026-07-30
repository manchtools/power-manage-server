package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spyTokenValidator records whether the bridge consulted the token store, so a
// test can prove it does NOT when a token arrives via the rejected ?token=
// query transport. The redemption is single-use, so a call the bridge should
// never have made would burn a legitimate client's token.
type spyTokenValidator struct {
	validateCalls int
	validateErr   error
}

func (s *spyTokenValidator) ValidateTerminalToken(context.Context, string, string) (*TerminalSession, error) {
	s.validateCalls++
	if s.validateErr != nil {
		return nil, s.validateErr
	}
	return &TerminalSession{}, nil
}

func bridgeWithSpy(spy *spyTokenValidator) *TerminalBridgeHandler {
	return &TerminalBridgeHandler{
		tokens: spy,
		logger: slog.Default(),
	}
}

// TestExtractTerminalToken_SubprotocolPreferred pins the correct path: a
// Sec-WebSocket-Protocol: bearer.<tok> offer yields the token and the chosen
// subprotocol to echo.
func TestExtractTerminalToken_SubprotocolPreferred(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/terminal?session_id=s1", nil)
	r.Header.Set("Sec-WebSocket-Protocol", "bearer.opaque-token-123")

	tok, chosen := extractTerminalToken(r)
	assert.Equal(t, "opaque-token-123", tok)
	assert.Equal(t, "bearer.opaque-token-123", chosen)
}

// TestServeHTTP_QueryStringTokenRejected pins WS11 finding 5: a token presented
// ONLY via the legacy ?token= query parameter is hard-rejected (401) and the
// control server is NEVER consulted — the bearer token must travel in the
// Sec-WebSocket-Protocol header where it does not leak into access logs /
// Referer / devtools.
func TestServeHTTP_QueryStringTokenRejected(t *testing.T) {
	spy := &spyTokenValidator{}
	h := bridgeWithSpy(spy)

	r := httptest.NewRequest(http.MethodGet, "/terminal?session_id=s1&token=leaky-url-token", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"a ?token= query transport must be hard-rejected, not validated")
	assert.Zero(t, spy.validateCalls,
		"ValidateTerminalToken must NOT be called for a query-string token")
}

// TestServeHTTP_SubprotocolTokenReachesValidation pins the contrast: a token in
// the subprotocol header IS passed through to validation (it is not caught by
// the transport gate). The spy returns an error so the flow stops at the
// invalid-token 401 without needing a live agent/WebSocket upgrade.
func TestServeHTTP_SubprotocolTokenReachesValidation(t *testing.T) {
	spy := &spyTokenValidator{validateErr: errors.New("invalid token")}
	h := bridgeWithSpy(spy)

	r := httptest.NewRequest(http.MethodGet, "/terminal?session_id=s1", nil)
	r.Header.Set("Sec-WebSocket-Protocol", "bearer.opaque-token-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	require.Equal(t, 1, spy.validateCalls,
		"a subprotocol-borne token must reach ValidateTerminalToken")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestServeHTTP_NoTokenIsBadRequest pins that a request with neither transport
// is a 400 and never consults control.
func TestServeHTTP_NoTokenIsBadRequest(t *testing.T) {
	spy := &spyTokenValidator{}
	h := bridgeWithSpy(spy)

	r := httptest.NewRequest(http.MethodGet, "/terminal?session_id=s1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Zero(t, spy.validateCalls)
}
