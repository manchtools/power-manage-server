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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/crl"
	"github.com/manchtools/power-manage/server/internal/mtls"
)

// newRealAgentCert builds a real x509 agent cert (populated .Raw, agent SPIFFE
// URI SAN) so the production crl.Cache + ca.FingerprintFromCert path can be
// exercised end to end — unlike fakeTLSStateWithPeerClass, whose cert has no
// DER. Each call yields a distinct cert (distinct key → distinct fingerprint).
func newRealAgentCert(t *testing.T) (*x509.Certificate, *tls.ConnectionState) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	agentURI, err := mtls.PeerClassURI(mtls.PeerClassAgent)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device-real"},
		NotBefore:    time.Unix(1_000_000, 0),
		NotAfter:     time.Unix(2_000_000_000, 0),
		URIs:         []*url.URL{agentURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}

// loadedCacheWithRevoked returns a real, already-loaded crl.Cache (miniredis
// backed) with the given fingerprints revoked, under a fixed clock (no
// time.Now()).
func loadedCacheWithRevoked(t *testing.T, now time.Time, fps ...string) *crl.Cache {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := crl.NewStore(rdb, crl.WithClock(func() time.Time { return now }))
	for _, fp := range fps {
		require.NoError(t, store.Revoke(context.Background(), fp, now.Add(time.Hour)))
	}
	cache := crl.NewCache(store, newTestLogger())
	require.NoError(t, cache.Refresh(context.Background()))
	return cache
}

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
	// Explicit NoopRevocationChecker (the typed dev opt-out) — a bare nil now
	// fails closed (see TestMTLSMiddleware_NilRevocationChecker), so the happy
	// path must pass an explicit loaded checker.
	mw := MTLSMiddleware(inner, mtls.NoopRevocationChecker{}, newTestLogger())

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
// doesn't have to predict the synthetic cert's fingerprint. It reports loaded so
// it exercises the IsRevoked branch (not the fail-closed-unloaded branch).
type fakeRevocation struct{ revoked bool }

func (f fakeRevocation) IsRevoked(string) bool { return f.revoked }
func (f fakeRevocation) Loaded() bool          { return true }

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

// TestMTLSMiddleware_RealCacheRevokesByFingerprint pins WS12 #3: the production
// crl.Cache (not the fakeRevocation stub) rejects a cert whose real DER
// fingerprint was revoked, and the match is over the EXACT DER. "Revoked" is
// sourced via ca.FingerprintFromCert into a real Store, never from the value the
// middleware computes.
func TestMTLSMiddleware_RealCacheRevokesByFingerprint(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	revokedCert, revokedTLS := newRealAgentCert(t)
	fp := ca.FingerprintFromCert(revokedCert)
	cache := loadedCacheWithRevoked(t, now, fp)

	called := false
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })
	mw := MTLSMiddleware(inner, cache, newTestLogger())

	// correct: revoked fp → 403, inner NOT reached.
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.TLS = revokedTLS
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "the real Cache must reject a cert whose DER fingerprint is revoked")
	assert.False(t, called)

	// ABSENT: a different non-revoked agent cert through the SAME cache → 200
	// (the gate keys on the actual fingerprint, not a blanket deny).
	called = false
	_, otherTLS := newRealAgentCert(t)
	req2 := httptest.NewRequest(http.MethodGet, "/api", nil)
	req2.TLS = otherTLS
	rec2 := httptest.NewRecorder()
	mw.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.True(t, called, "a non-revoked cert through a loaded cache must be admitted")

	// present-but-WRONG (tampered cert): the same revoked cert with one DER byte
	// flipped → its fingerprint no longer matches the revoked entry → admitted
	// (proves the match is over the exact DER, not a prefix/length check). The
	// in-memory URIs are intact, so peer-class still passes.
	called = false
	tampered := *revokedCert
	tampered.Raw = append([]byte(nil), revokedCert.Raw...)
	tampered.Raw[len(tampered.Raw)-1] ^= 0xFF
	req3 := httptest.NewRequest(http.MethodGet, "/api", nil)
	req3.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{&tampered}}
	rec3 := httptest.NewRecorder()
	mw.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code, "flipping a DER byte changes the fingerprint so it no longer matches the revoked entry")

	// present-but-WRONG (tampered seed): a flipped fingerprint string seeded into
	// the CRL can never equal a real cert's fingerprint, so the unflipped cert is
	// admitted — proves the binding is the exact fingerprint, sourced from intent.
	flipped := []byte(fp)
	flipped[len(flipped)-1] ^= 0xFF // any mutation makes the seed differ from every real fingerprint
	cacheBadSeed := loadedCacheWithRevoked(t, now, string(flipped))
	called = false
	mw4 := MTLSMiddleware(inner, cacheBadSeed, newTestLogger())
	req4 := httptest.NewRequest(http.MethodGet, "/api", nil)
	req4.TLS = revokedTLS
	rec4 := httptest.NewRecorder()
	mw4.ServeHTTP(rec4, req4)
	assert.Equal(t, http.StatusOK, rec4.Code, "a tampered seed fingerprint matches no real cert → admitted")
}

// TestMTLSMiddleware_NotLoadedCacheFailsClosed is the RED→GREEN pivot for
// WS12 #1/#4 at the middleware seam: a never-loaded (or only-errored) CRL cache
// cannot prove a cert is unrevoked, so the middleware must fail CLOSED. RED
// today (an empty cache reports IsRevoked==false → admits).
func TestMTLSMiddleware_NotLoadedCacheFailsClosed(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	agent := mtls.PeerClassAgent

	// never-loaded cache: Refresh never called → Loaded()==false.
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	notLoaded := crl.NewCache(crl.NewStore(rdb, crl.WithClock(func() time.Time { return now })), newTestLogger())
	require.False(t, notLoaded.Loaded())

	called := false
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })
	mw := MTLSMiddleware(inner, notLoaded, newTestLogger())
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.TLS = fakeTLSStateWithPeerClass(t, "device-1", &agent)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "a not-yet-loaded CRL must fail closed — cannot prove the cert is unrevoked")
	assert.False(t, called, "an unloaded CRL must not admit")

	// loaded-but-empty cache → admits (a genuinely empty CRL still admits).
	called = false
	loadedEmpty := loadedCacheWithRevoked(t, now)
	mw2 := MTLSMiddleware(inner, loadedEmpty, newTestLogger())
	req2 := httptest.NewRequest(http.MethodGet, "/api", nil)
	req2.TLS = fakeTLSStateWithPeerClass(t, "device-1", &agent)
	rec2 := httptest.NewRecorder()
	mw2.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code, "a loaded-but-empty CRL must still admit non-revoked certs")
	assert.True(t, called)
}

// TestMTLSMiddleware_NilRevocationChecker pins WS12 #4: a bare nil checker fails
// closed; only the explicit, typed NoopRevocationChecker admits without a real
// CRL. RED today (a nil checker is silently skipped → admits).
func TestMTLSMiddleware_NilRevocationChecker(t *testing.T) {
	agent := mtls.PeerClassAgent
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	// bare nil → fail closed (403).
	mwNil := MTLSMiddleware(inner, nil, newTestLogger())
	reqNil := httptest.NewRequest(http.MethodGet, "/api", nil)
	reqNil.TLS = fakeTLSStateWithPeerClass(t, "device-1", &agent)
	recNil := httptest.NewRecorder()
	mwNil.ServeHTTP(recNil, reqNil)
	assert.Equal(t, http.StatusForbidden, recNil.Code, "a bare nil checker must fail closed, never silently admit")

	// explicit NoopRevocationChecker → admits non-revoked (typed dev opt-out).
	called := false
	innerOK := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })
	mwNoop := MTLSMiddleware(innerOK, mtls.NoopRevocationChecker{}, newTestLogger())
	reqNoop := httptest.NewRequest(http.MethodGet, "/api", nil)
	reqNoop.TLS = fakeTLSStateWithPeerClass(t, "device-1", &agent)
	recNoop := httptest.NewRecorder()
	mwNoop.ServeHTTP(recNoop, reqNoop)
	assert.Equal(t, http.StatusOK, recNoop.Code, "the explicit NoopRevocationChecker is the dev opt-out and admits non-revoked")
	assert.True(t, called)
}
