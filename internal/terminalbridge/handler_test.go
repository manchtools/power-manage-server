package terminalbridge

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/terminal"
)

func TestTerminalTokenAcceptsOnlyBearerSubprotocol(t *testing.T) {
	request := httptest.NewRequest("GET", "https://control.example/terminal?token=url-secret", nil)
	token, protocol := terminalToken(request)
	assert.Empty(t, token)
	assert.Empty(t, protocol)

	request.Header.Add("Sec-WebSocket-Protocol", "chat, bearer.header-secret")
	token, protocol = terminalToken(request)
	assert.Equal(t, "header-secret", token)
	assert.Equal(t, "bearer.header-secret", protocol)
}

type readDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline     time.Time
	deadlineSet  bool
	hijackCalled bool
}

func (r *readDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	r.deadline = deadline
	r.deadlineSet = true
	return nil
}

func (r *readDeadlineRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijackCalled = true
	return nil, nil, errors.New("test stops at WebSocket hijack")
}

func TestServeHTTPClearsPublicRequestReadDeadlineBeforeUpgrade(t *testing.T) {
	t.Parallel()

	manager := connection.NewManager()
	deviceID := "01J00000000000000000000001"
	userID := "01J00000000000000000000002"
	manager.Register(context.Background(), deviceID, "host", "1.0.0", nil)

	tokens := terminal.NewTokenStore(terminal.NewMemoryBackend(nil))
	minted, err := tokens.Mint(context.Background(), terminal.MintParams{
		UserID: userID, DeviceID: deviceID, TtyUser: "pm-tty-user", Cols: 80, Rows: 24,
	})
	require.NoError(t, err)

	handler := New(Config{
		Manager: manager, Sessions: connection.NewTerminalSessionRegistry(), Tokens: tokens,
		Store: &store.Store{}, Logger: slog.Default(),
	})
	request := httptest.NewRequest(http.MethodGet, "/terminal?session_id="+minted.SessionID, nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	request.Header.Set("Sec-WebSocket-Protocol", "bearer."+minted.Token)
	response := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}

	// The recorder stops at the WebSocket hijack itself. At that exact boundary,
	// the public server's ordinary-request deadline must already be gone.
	handler.ServeHTTP(response, request)

	assert.True(t, response.hijackCalled, "the test must reach the real WebSocket upgrade boundary")
	assert.True(t, response.deadlineSet)
	assert.True(t, response.deadline.IsZero(), "terminal connections must not inherit the public request timeout")
}
