package idp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewBoundedOIDCClient_IsBounded pins that the OIDC HTTP client carries a
// non-zero overall timeout plus dial/TLS/response-header bounds — without these
// go-oidc falls back to http.DefaultClient (no timeout). Fast structural check
// complementing the live timeout test below (WS5 #6/#14).
func TestNewBoundedOIDCClient_IsBounded(t *testing.T) {
	c := newBoundedOIDCClient()
	require.NotNil(t, c)
	assert.Positive(t, c.Timeout, "overall client timeout must be set")
	tr, ok := c.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Positive(t, tr.TLSHandshakeTimeout)
	assert.Positive(t, tr.ResponseHeaderTimeout)
}

// TestNewOIDCProvider_DiscoveryRespectsTimeout pins WS5 #6/#14: discovery is
// bounded. Pointed at a server that accepts the connection but never responds,
// NewOIDCProvider must RETURN (with an error) rather than hang — proving the
// bounded client is threaded into discovery via oidc.ClientContext. RED before
// the fix (http.DefaultClient has no timeout).
func TestNewOIDCProvider_DiscoveryRespectsTimeout(t *testing.T) {
	// Shrink the client timeout so the test is fast.
	orig := oidcHTTPTimeout
	oidcHTTPTimeout = 400 * time.Millisecond
	t.Cleanup(func() { oidcHTTPTimeout = orig })

	// Cleanup ordering matters: httptest's srv.Close() blocks until the
	// in-flight (blocked) handler returns, so close(block) MUST run first.
	// t.Cleanup is LIFO, so register srv.Close FIRST (runs last) and the
	// unblock SECOND (runs first) — otherwise srv.Close deadlocks on the
	// handler that's waiting for the channel.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block // never respond until the test ends
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(block) })

	done := make(chan error, 1)
	go func() {
		_, err := NewOIDCProvider(context.Background(), ProviderConfig{
			IssuerURL: srv.URL,
			ClientID:  "test",
		})
		done <- err
	}()

	select {
	case err := <-done:
		assert.Error(t, err, "discovery against a hanging server must fail, not succeed")
	case <-time.After(5 * time.Second):
		t.Fatal("NewOIDCProvider hung past the bounded timeout — discovery is not bounded")
	}
}
