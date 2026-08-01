package terminalbridge

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
