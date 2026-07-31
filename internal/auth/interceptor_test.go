package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// The trusted-proxy resolution decides which address a rate limit and
// an audit origin fingerprint are attributed to, so a caller who can
// forge it can evade both.
func TestClientIPFromHTTP_HonoursForwardedHeadersOnlyBehindATrustedProxy(t *testing.T) {
	original := auth.TrustedProxies
	t.Cleanup(func() { auth.TrustedProxies = original })

	newRequest := func(remote, xff, xri string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if xri != "" {
			r.Header.Set("X-Real-IP", xri)
		}
		return r
	}

	auth.SetTrustedProxies(nil)
	assert.Equal(t, "198.51.100.9",
		auth.ClientIPFromHTTP(newRequest("198.51.100.9:5000", "203.0.113.1", "")),
		"with no trusted proxy configured, a forwarded header is ignored entirely")

	auth.SetTrustedProxies([]string{"10.0.0.0/8"})
	assert.Equal(t, "198.51.100.9",
		auth.ClientIPFromHTTP(newRequest("198.51.100.9:5000", "203.0.113.1", "")),
		"an untrusted direct peer cannot set its own address")

	assert.Equal(t, "203.0.113.1",
		auth.ClientIPFromHTTP(newRequest("10.1.2.3:5000", "203.0.113.1", "")),
		"a trusted proxy's forwarded address is honoured")

	// Walking right to left skips our own hops and stops at the first
	// address we did not place, which defeats a spoofed leftmost entry.
	assert.Equal(t, "203.0.113.1",
		auth.ClientIPFromHTTP(newRequest("10.1.2.3:5000", "1.2.3.4, 203.0.113.1, 10.4.5.6", "")),
		"a client-supplied leftmost entry must not win over the real hop")

	// Walking right to left, the FIRST hop examined is malformed, so
	// nothing further left can be trusted and the direct peer stands.
	assert.Equal(t, "10.1.2.3",
		auth.ClientIPFromHTTP(newRequest("10.1.2.3:5000", "203.0.113.1, not-an-ip", "")),
		"a malformed hop makes the chain untrustworthy from there leftward")

	// A malformed hop FARTHER LEFT than a trustworthy client is never
	// reached: the client was already established.
	assert.Equal(t, "203.0.113.1",
		auth.ClientIPFromHTTP(newRequest("10.1.2.3:5000", "not-an-ip, 203.0.113.1", "")),
		"the first untrusted address from the right is the client")

	assert.Equal(t, "10.1.2.3",
		auth.ClientIPFromHTTP(newRequest("10.1.2.3:5000", "10.9.9.9, 10.8.8.8", "")),
		"an all-proxy chain falls back to the direct peer")

	assert.Equal(t, "203.0.113.7",
		auth.ClientIPFromHTTP(newRequest("10.1.2.3:5000", "", "203.0.113.7")),
		"X-Real-IP applies only when there is no forwarded chain")

	assert.Empty(t, auth.ClientIPFromHTTP(newRequest("not-an-address", "", "")),
		"an unidentifiable peer yields no address rather than a made-up key")
}

func TestRateLimiter_BoundsAttemptsPerKeyWithinTheWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	rl := auth.NewRateLimiter(2, time.Minute, auth.WithClock(func() time.Time { return now }))
	t.Cleanup(rl.Stop)

	assert.True(t, rl.Allow("a"))
	assert.True(t, rl.Allow("a"))
	assert.False(t, rl.Allow("a"), "the third attempt in the window is refused")
	assert.True(t, rl.Allow("b"), "another key has its own budget")

	assert.True(t, rl.Blocked("a"))
	assert.False(t, rl.Blocked("b"))

	// The window slides: an attempt older than the window no longer
	// counts.
	now = now.Add(2 * time.Minute)
	assert.False(t, rl.Blocked("a"))
	assert.True(t, rl.Allow("a"))
}

// The control API is unary. A streaming request must be refused rather
// than falling through some path where the unary authentication gate
// does not run.
func TestInterceptors_RefuseStreaming(t *testing.T) {
	t.Parallel()
	_, priv, err := auth.GenerateSessionKey()
	require.NoError(t, err)
	m, err := auth.NewJWTManager(auth.JWTConfig{PrivateKey: priv})
	require.NoError(t, err)

	authn := auth.NewAuthInterceptor(discardLogger(), m, auth.RateLimiters{}, nil)
	authz := auth.NewAuthzInterceptor()

	for name, wrapped := range map[string]connect.StreamingHandlerFunc{
		"authentication": authn.WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
			return nil
		}),
		"authorization": authz.WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
			return nil
		}),
	} {
		t.Run(name, func(t *testing.T) {
			err := wrapped(context.Background(), nil)
			require.Error(t, err)
			assert.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))
		})
	}
}
