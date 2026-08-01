package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/terminal"
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
// the transport gate). The spy returns the store's not-found sentinel — an
// expired, never-minted or already-consumed token — so the flow stops at the
// invalid-token 401 without needing a live agent/WebSocket upgrade.
func TestServeHTTP_SubprotocolTokenReachesValidation(t *testing.T) {
	spy := &spyTokenValidator{validateErr: terminal.ErrTokenNotFound}
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

// outageBackend is a terminal.SessionBackend that cannot answer — the token
// store's Valkey being down, a dial refused, a context deadline. Every method
// returns a real infrastructure error, NOT one of the package's sentinels,
// which is the one distinction under test.
type outageBackend struct{ err error }

func (b outageBackend) Set(context.Context, string, []byte, time.Duration) error { return b.err }
func (b outageBackend) Get(context.Context, string) ([]byte, error)              { return nil, b.err }
func (b outageBackend) Delete(context.Context, string) error                     { return b.err }
func (b outageBackend) GetAndDelete(context.Context, string) ([]byte, error)     { return nil, b.err }

// A token store that cannot answer is not a token that is invalid.
//
// Collapsing every validation error into "invalid or expired session token"
// tells the operator their perfectly good, just-minted token was rejected, and
// tells the web client the terminal is unauthorised rather than briefly
// unavailable — 401 is a terminal answer, so a retry that would succeed the
// moment the store returns is never made. The same collapse hides the outage
// from the log at Warn severity, where it reads as a client mistake.
//
// Driven through a real TokenStore over a backend that fails, so the error
// reaching the bridge is a genuine infrastructure error rather than
// ErrTokenNotFound.
func TestServeHTTP_TokenStoreOutageIsUnavailableNotUnauthorized(t *testing.T) {
	store := terminal.NewTokenStore(outageBackend{err: errors.New("dial tcp 127.0.0.1:6379: connect: connection refused")})
	h := &TerminalBridgeHandler{
		tokens: NewTokenStoreValidator(store),
		logger: slog.Default(),
	}

	r := httptest.NewRequest(http.MethodGet, "/terminal?session_id=01HZX9ABCD0000000000000000", nil)
	r.Header.Set("Sec-WebSocket-Protocol", "bearer.opaque-token-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"a token store that cannot answer must not be reported as an invalid or expired token — "+
			"the client stops retrying a session that would open the moment the store returns")
}

// The forgery discriminator has to stay reachable: ErrTokenMismatch is
// documented as distinguished so the audit log can record forgery attempts
// separately, and a sentinel no production code branches on records nothing.
//
// The wire answer is deliberately the SAME 401 with the same message as an
// expired token — only the log severity differs — so a bearer probe cannot tell
// "wrong token for a live session" from "no such session".
func TestServeHTTP_ForgedBearerIsUnauthorizedNotUnavailable(t *testing.T) {
	store := terminal.NewTokenStore(terminal.NewMemoryBackend(nil))
	minted, err := store.Mint(context.Background(), terminal.MintParams{
		UserID:   "01HZX9USER0000000000000000",
		DeviceID: "01HZX9DEV00000000000000000",
		TtyUser:  "pm-tty-tester",
	})
	require.NoError(t, err)

	h := &TerminalBridgeHandler{
		tokens: NewTokenStoreValidator(store),
		logger: slog.Default(),
	}

	r := httptest.NewRequest(http.MethodGet, "/terminal?session_id="+minted.SessionID, nil)
	r.Header.Set("Sec-WebSocket-Protocol", "bearer.not-the-minted-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"a forged bearer is a client failure, not a server one — it must stay indistinguishable "+
			"on the wire from an expired token")
}
