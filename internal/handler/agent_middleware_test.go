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
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/ca"
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

// revocationSet is a RevocationChecker over a fixed fingerprint set, or a fixed
// lookup error.
//
// It replaces a miniredis-backed crl.Cache. The cache is gone because
// revocations are no longer a published list — control queries its own table
// per handshake — but the property this file tests is unchanged and does not
// depend on the backing store: the middleware must compute the REAL DER
// fingerprint of the presented certificate and match it exactly. The
// fingerprints below still come from ca.FingerprintFromCert over a real cert,
// which is the part that matters.
type revocationSet struct {
	revoked map[string]bool
	err     error
}

func (r revocationSet) IsRevoked(_ context.Context, fp string) (bool, error) {
	if r.err != nil {
		return false, r.err
	}
	return r.revoked[fp], nil
}

func revocationWith(fps ...string) revocationSet {
	set := map[string]bool{}
	for _, fp := range fps {
		set[fp] = true
	}
	return revocationSet{revoked: set}
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

func TestSetTerminalSessions_StoresRegistry(t *testing.T) {
	h := NewAgentHandler(nil, nil, nil, nil, "v", 0, newTestLogger())
	// nil disables terminal routing; the bidi-stream terminal-output path
	// nil-guards on it, so the setter must record nil without crashing.
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
	gw := mtls.PeerClassControl
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
	// A loaded checker with nothing revoked — the happy path must pass an
	// explicit loaded checker because a bare nil now fails closed (see
	// TestMTLSMiddleware_NilRevocationChecker).
	mw := MTLSMiddleware(inner, fakeRevocation{revoked: false}, newTestLogger())

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

// fakeRevocation is a RevocationChecker whose verdict is fixed, so a test does
// not have to predict a synthetic cert's fingerprint. It answers without error,
// exercising the revoked/not-revoked branches rather than the fail-closed one.
type fakeRevocation struct{ revoked bool }

func (f fakeRevocation) IsRevoked(context.Context, string) (bool, error) { return f.revoked, nil }

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
	revokedCert, revokedTLS := newRealAgentCert(t)
	fp := ca.FingerprintFromCert(revokedCert)
	cache := revocationWith(fp)

	called := false
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })
	mw := MTLSMiddleware(inner, cache, newTestLogger())

	// correct: revoked fp → 403, inner NOT reached.
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.TLS = revokedTLS
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "a revoked DER fingerprint must be rejected")
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
	cacheBadSeed := revocationWith(string(flipped))
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
	agent := mtls.PeerClassAgent

	// never-loaded cache: Refresh never called → Loaded()==false.
	// The "not yet loaded" state is gone: there is no snapshot to be unloaded.
	// Its replacement is an indeterminate lookup, which must fail closed for the
	// same reason — we cannot prove the certificate is unrevoked.
	notLoaded := revocationSet{err: errors.New("revocation backend unreachable")}

	called := false
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })
	mw := MTLSMiddleware(inner, notLoaded, newTestLogger())
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.TLS = fakeTLSStateWithPeerClass(t, "device-1", &agent)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "an indeterminate revocation lookup must fail closed — cannot prove the cert is unrevoked")
	assert.False(t, called, "an indeterminate lookup must not admit")

	// loaded-but-empty cache → admits (a genuinely empty CRL still admits).
	called = false
	loadedEmpty := revocationWith()
	mw2 := MTLSMiddleware(inner, loadedEmpty, newTestLogger())
	req2 := httptest.NewRequest(http.MethodGet, "/api", nil)
	req2.TLS = fakeTLSStateWithPeerClass(t, "device-1", &agent)
	rec2 := httptest.NewRecorder()
	mw2.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code, "an empty revocation set must still admit non-revoked certs")
	assert.True(t, called)
}

// TestMTLSMiddleware_NilRevocationChecker pins WS12 #4 / audit L11: a nil checker
// fails closed (403), never silently admits. With NoopRevocationChecker removed
// there is no opt-out — a deployment without a CRL rejects every call here, and a
// loaded-but-empty CRL (which admits non-revoked) is covered by
// TestMTLSMiddleware_RevokedCertRejected.
func TestMTLSMiddleware_NilRevocationChecker(t *testing.T) {
	agent := mtls.PeerClassAgent
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	// bare nil → fail closed (403).
	mwNil := MTLSMiddleware(inner, nil, newTestLogger())
	reqNil := httptest.NewRequest(http.MethodGet, "/api", nil)
	reqNil.TLS = fakeTLSStateWithPeerClass(t, "device-1", &agent)
	recNil := httptest.NewRecorder()
	mwNil.ServeHTTP(recNil, reqNil)
	assert.Equal(t, http.StatusForbidden, recNil.Code, "a nil checker must fail closed, never silently admit")
}

// TestMTLSMiddleware_SetsTheKeyTheHandlerReads pins the compatibility between
// the wrapper that establishes agent identity and the handler that consumes it.
//
// This is the defect it exists for, found in review after every other check was
// green: control's agent listener was wrapped with mtls.WithPeerCert instead of
// MTLSMiddleware. Both put the authenticated peer into the request context, so
// the wiring type-checked and compiled. But they use different keys and
// different shapes — WithPeerCert carries the raw x509 leaf, MTLSMiddleware
// carries the extracted device id — so DeviceIDFromContext found nothing and
// EVERY real agent call failed Unauthenticated.
//
// No unit test caught it because handler tests inject DeviceIDContextKey
// directly, which is exactly the shortcut that makes a wiring bug invisible:
// the tests prove the handler reads the key, and separately the middleware sets
// it, while nothing proves the two are the same key.
func TestMTLSMiddleware_SetsTheKeyTheHandlerReads(t *testing.T) {
	cert, tlsState := newRealAgentCert(t)
	require.NotEmpty(t, cert.Subject.CommonName, "fixture must carry a CN to compare against")

	var (
		reached  bool
		gotID    string
		gotFound bool
	)
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		gotID, gotFound = DeviceIDFromContext(r.Context())
	})

	mw := MTLSMiddleware(inner, revocationWith(), newTestLogger())
	req := httptest.NewRequest(http.MethodPost, "/pm.v1.AgentService/Stream", nil)
	req.TLS = tlsState
	mw.ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, reached, "the middleware must admit a valid agent cert")
	require.True(t, gotFound,
		"DeviceIDFromContext found nothing — the middleware wrapping the agent listener "+
			"does not set the key the handler reads, so every real agent call fails Unauthenticated")
	assert.Equal(t, cert.Subject.CommonName, gotID,
		"the device id the handler sees must be the certificate CN, not some other value")
}
