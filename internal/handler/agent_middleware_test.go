package handler

// Coverage for BootstrapRedirectMiddleware — the host-rewrite
// middleware that catches enrollment-time agent connections to a
// bootstrap hostname and redirects them to the operator-assigned
// hostname. Closes audit-tagged 0% coverage on this middleware.
//
// Critical: an IPv6 host header without bracketing previously
// caused the strings.IndexByte(':') bug to truncate the host at
// the first colon — a CR-caught regression that cost an outage.
// One of the cases here pins that fix in place.

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/mtls"
)

func newOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// =============================================================================
// BootstrapRedirectMiddleware: configuration validation
// =============================================================================

func TestBootstrapRedirectMiddleware_EmptyBootstrapHost_PassesThrough(t *testing.T) {
	// bootstrapHost="" disables the middleware entirely. Verify
	// the returned handler is the same one we passed in (no
	// wrapping) — this is what makes the middleware safe to mount
	// unconditionally even when bootstrap isn't configured.
	inner := newOKHandler()
	got := BootstrapRedirectMiddleware(inner, "", "anything.example.com", newTestLogger())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://whatever.example.com/path", nil)
	got.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "with bootstrap disabled, every request must reach the inner handler")
}

func TestBootstrapRedirectMiddleware_BootstrapHostWithoutAssignedHost_Panics(t *testing.T) {
	// Misconfiguration: bootstrap hostname set without an assigned
	// destination. Construction MUST panic so the operator notices
	// at boot — silently passing through every request would mean
	// every agent that hits the bootstrap endpoint stays stranded.
	defer func() {
		r := recover()
		require.NotNil(t, r, "BootstrapRedirectMiddleware must panic when bootstrapHost is set but assignedHost is empty")
	}()
	BootstrapRedirectMiddleware(newOKHandler(), "bootstrap.example.com", "", newTestLogger())
}

// =============================================================================
// BootstrapRedirectMiddleware: redirect behaviour
// =============================================================================

func TestBootstrapRedirectMiddleware_BootstrapHostRedirects307(t *testing.T) {
	mw := BootstrapRedirectMiddleware(newOKHandler(), "bootstrap.example.com", "assigned.example.com", newTestLogger())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://bootstrap.example.com/some/path?q=1", nil)
	req.Host = "bootstrap.example.com"
	mw.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code,
		"307 (not 301) — agents must POST-preserve bodies on the retry; a 301 would convert subsequent calls to GET")
	assert.Equal(t, "https://assigned.example.com/some/path?q=1", rec.Header().Get("Location"))
}

func TestBootstrapRedirectMiddleware_OtherHostPassesThrough(t *testing.T) {
	mw := BootstrapRedirectMiddleware(newOKHandler(), "bootstrap.example.com", "assigned.example.com", newTestLogger())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://other.example.com/foo", nil)
	req.Host = "other.example.com"
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "non-bootstrap host must reach the inner handler unchanged")
}

func TestBootstrapRedirectMiddleware_BootstrapHostWithPortStillRedirects(t *testing.T) {
	// The agent may include a port in the Host header. Strip-and-
	// match must still hit the bootstrap branch.
	mw := BootstrapRedirectMiddleware(newOKHandler(), "bootstrap.example.com", "assigned.example.com", newTestLogger())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://bootstrap.example.com:8443/x", nil)
	req.Host = "bootstrap.example.com:8443"
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	assert.Equal(t, "https://assigned.example.com/x", rec.Header().Get("Location"),
		"port stripped from comparison so the operator-facing assigned URL is clean")
}

// =============================================================================
// AgentHandler constructors + setters — small but uncovered
// =============================================================================

func TestNewAgentHandler_DefaultsRequireTLSFalse(t *testing.T) {
	// The non-TLS constructor is used by the dev / single-tenant
	// gateway path. requireTLS MUST default to false; flipping the
	// default would cause every dev deploy to start refusing
	// connections without an obvious mTLS misconfig error.
	h := NewAgentHandler(nil, nil, nil, nil, "v-test", 0, newTestLogger())
	require.NotNil(t, h)
	assert.False(t, h.requireTLS)
	assert.Equal(t, "v-test", h.serverVersion)
}

func TestNewAgentHandlerWithTLS_RequiresTLS(t *testing.T) {
	// Production mTLS path: requireTLS MUST be true. Stream() and
	// SyncActions both gate device-ID verification on this flag.
	h := NewAgentHandlerWithTLS(nil, nil, nil, nil, "v-tls", 0, newTestLogger())
	require.NotNil(t, h)
	assert.True(t, h.requireTLS)
}

func TestSetGatewayRouting_StoresRegistryAndID(t *testing.T) {
	h := NewAgentHandler(nil, nil, nil, nil, "v", 0, newTestLogger())
	// nil registry is the documented "single-gateway mode" — verify
	// the setter records nil without crashing, since tests + dev
	// deploys both rely on this shape.
	h.SetGatewayRouting(nil, "gw-1")
	assert.Nil(t, h.registry)
	assert.Equal(t, "gw-1", h.gatewayID)
}

func TestSetTerminalSessions_StoresRegistry(t *testing.T) {
	h := NewAgentHandler(nil, nil, nil, nil, "v", 0, newTestLogger())
	// nil disables terminal routing — same defensive contract as
	// SetGatewayRouting. The bidi-stream's terminal-output path
	// nil-guards on this.
	h.SetTerminalSessions(nil)
	assert.Nil(t, h.terminalSessions)
}

// =============================================================================
// MTLSMiddleware
// =============================================================================

// fakeTLSStateWithPeerClass returns a *tls.ConnectionState whose
// peer cert carries the given device CN and a SPIFFE URI matching
// the requested peer class. nil for class skips the URI SAN entirely
// (used to exercise the peer-class missing branch).
func fakeTLSStateWithPeerClass(t *testing.T, deviceID string, class *mtls.PeerClass) *tls.ConnectionState {
	t.Helper()
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: deviceID}}
	if class != nil {
		u, err := mtls.PeerClassURI(*class)
		require.NoError(t, err)
		cert.URIs = []*url.URL{u}
	}
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
}

func TestMTLSMiddleware_HealthBypassesAllChecks(t *testing.T) {
	// /health and /ready MUST bypass mTLS — load balancer probes
	// don't present client certs and a 401 here would mark the
	// gateway pod unhealthy and trigger a flap-restart loop.
	called := false
	mw := MTLSMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }), nil, newTestLogger())

	for _, path := range []string{"/health", "/ready"} {
		t.Run(path, func(t *testing.T) {
			called = false
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.True(t, called, "%s must reach the inner handler with no TLS state", path)
		})
	}
}

func TestMTLSMiddleware_NoTLSState_Returns401(t *testing.T) {
	mw := MTLSMiddleware(newOKHandler(), nil, newTestLogger())
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.TLS = nil
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"a request without TLS state on a non-health path MUST be rejected — passing through would let an HTTP-only attacker call AgentService")
}

func TestMTLSMiddleware_PeerClassMissing_Returns403(t *testing.T) {
	mw := MTLSMiddleware(newOKHandler(), nil, newTestLogger())
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.TLS = fakeTLSStateWithPeerClass(t, "device-1", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"cert without a peer-class URI SAN MUST be 403 — fail-closed when the class can't be determined")
}

func TestMTLSMiddleware_GatewayClassRejectedOnAgentService(t *testing.T) {
	// A gateway cert presented to AgentService MUST be rejected.
	// The agent listener is for managed devices only; admitting a
	// gateway cert would let one gateway impersonate every connected
	// agent simultaneously.
	mw := MTLSMiddleware(newOKHandler(), nil, newTestLogger())
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	gw := mtls.PeerClassGateway
	req.TLS = fakeTLSStateWithPeerClass(t, "gateway-1", &gw)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"gateway peer-class on AgentService MUST be 403 — admitting it would let one gateway impersonate every agent")
}

func TestMTLSMiddleware_AgentClassReachesInnerWithDeviceIDInContext(t *testing.T) {
	// Happy path: cert is an agent cert, device ID lands on the
	// downstream context. Stream() and SyncActions both rely on
	// DeviceIDFromContext returning ok+id from this exact path.
	var gotDeviceID string
	var gotOK bool
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotDeviceID, gotOK = DeviceIDFromContext(r.Context())
	})
	mw := MTLSMiddleware(inner, nil, newTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	agent := mtls.PeerClassAgent
	req.TLS = fakeTLSStateWithPeerClass(t, "device-happy", &agent)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, gotOK, "device ID MUST be present in the downstream ctx after a successful agent-class verification")
	assert.Equal(t, "device-happy", gotDeviceID)
}

func TestBootstrapRedirectMiddleware_IPv6HostHeaderHandledCorrectly(t *testing.T) {
	// REGRESSION GUARD: a previous strings.IndexByte(':') split
	// at the first internal colon of an IPv6 address, leaving
	// reqHost == "[". The fix uses net.SplitHostPort which
	// correctly handles bracketed IPv6 authorities. This test
	// pins the fix in place — if a future change reintroduces
	// the naive split, this case will fail.
	mw := BootstrapRedirectMiddleware(newOKHandler(), "[2001:db8::1]", "assigned.example.com", newTestLogger())

	rec := httptest.NewRecorder()
	// Bracketed-IPv6 Host header without port → SplitHostPort returns
	// an error; the fallback must keep the raw r.Host for comparison,
	// which equals bootstrapHost as configured above.
	req := httptest.NewRequest(http.MethodGet, "http://[2001:db8::1]/p", nil)
	req.Host = "[2001:db8::1]"
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code,
		"IPv6 bracketed authority MUST match — the strings.IndexByte(':') bug truncated host at the first internal colon, leaving reqHost = '['")
}

// fakeRevocation is a RevocationChecker whose verdict is fixed, so a CRL test
// doesn't have to predict the synthetic cert's fingerprint.
type fakeRevocation struct{ revoked bool }

func (f fakeRevocation) IsRevoked(string) bool { return f.revoked }

// TestMTLSMiddleware_RevokedCertRejected pins the CRL gate (audit #6): an
// agent cert whose fingerprint is on the revocation list is rejected at the
// mTLS layer (403, never reaches AgentService), while a non-revoked one passes.
func TestMTLSMiddleware_RevokedCertRejected(t *testing.T) {
	agent := mtls.PeerClassAgent

	called := false
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	// Revoked → 403, inner not reached.
	mw := MTLSMiddleware(inner, fakeRevocation{revoked: true}, newTestLogger())
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.TLS = fakeTLSStateWithPeerClass(t, "device-1", &agent)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "a revoked agent cert MUST be rejected at the mTLS layer")
	assert.False(t, called, "a revoked cert must not reach AgentService")

	// Not revoked → reaches inner.
	called = false
	mw2 := MTLSMiddleware(inner, fakeRevocation{revoked: false}, newTestLogger())
	req2 := httptest.NewRequest(http.MethodGet, "/api", nil)
	req2.TLS = fakeTLSStateWithPeerClass(t, "device-1", &agent)
	rec2 := httptest.NewRecorder()
	mw2.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.True(t, called, "a non-revoked agent cert must reach AgentService")
}
