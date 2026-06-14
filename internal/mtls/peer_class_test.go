package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeRev is a RevocationChecker with a fixed revoked-set and loaded flag.
type fakeRev struct {
	revoked map[string]bool
	loaded  bool
}

func (f fakeRev) IsRevoked(fp string) bool { return f.revoked[fp] }
func (f fakeRev) Loaded() bool             { return f.loaded }

// realCertWithClass builds a real x509 cert (populated .Raw) carrying the given
// peer-class SPIFFE URI, so the revocation gate's DER fingerprint is meaningful.
func realCertWithClass(t *testing.T, class PeerClass) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := PeerClassURI(class)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		URIs:         []*url.URL{u},
		NotBefore:    time.Unix(1_000_000, 0),
		NotAfter:     time.Unix(2_000_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// indepFingerprint computes hex(sha256(DER)) via an INDEPENDENT code path from
// the middleware's fingerprintFromCert, so a bug in the latter (e.g. a wrong
// hash) is caught rather than masked — "wrong" is sourced from intent.
func indepFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

// TestPeerClassFromCert_Roundtrip asserts that every well-known
// class encodes to a SPIFFE URI and decodes back to the same class.
func TestPeerClassFromCert_Roundtrip(t *testing.T) {
	for _, class := range []PeerClass{PeerClassAgent, PeerClassGateway, PeerClassControl} {
		t.Run(string(class), func(t *testing.T) {
			u, err := PeerClassURI(class)
			if err != nil {
				t.Fatalf("PeerClassURI(%q): %v", class, err)
			}
			cert := &x509.Certificate{URIs: []*url.URL{u}}
			got, err := PeerClassFromCert(cert)
			if err != nil {
				t.Fatalf("PeerClassFromCert: %v", err)
			}
			if got != class {
				t.Errorf("got %q, want %q", got, class)
			}
		})
	}
}

// TestPeerClassFromCert_Errors covers the rejection surface:
// missing URI, non-spiffe scheme, wrong host, unknown class, and
// ambiguous multi-class certs.
func TestPeerClassFromCert_Errors(t *testing.T) {
	cases := map[string]*x509.Certificate{
		"nil cert":      nil,
		"no URI SAN":    {},
		"wrong scheme":  {URIs: []*url.URL{mustURL(t, "https://power-manage/agent")}},
		"wrong host":    {URIs: []*url.URL{mustURL(t, "spiffe://other/agent")}},
		"unknown class": {URIs: []*url.URL{mustURL(t, "spiffe://power-manage/admin")}},
		"empty class":   {URIs: []*url.URL{mustURL(t, "spiffe://power-manage/")}},
		"multi-class": {URIs: []*url.URL{
			mustURL(t, "spiffe://power-manage/agent"),
			mustURL(t, "spiffe://power-manage/gateway"),
		}},
	}
	for name, cert := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := PeerClassFromCert(cert); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestRequirePeerClass_AllowsAllowedRejectsOthers spins up a mTLS
// test server with the middleware installed and asserts it
// accepts an allowed class and rejects every other.
func TestRequirePeerClass_AllowsAllowedRejectsOthers(t *testing.T) {
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequirePeerClass(discardLogger, PeerClassGateway)(next)

	// Simulate a TLS connection state carrying a peer cert with a
	// given class. httptest.Server with a real TLS handshake would
	// be overkill for unit coverage; the middleware only reads
	// r.TLS.PeerCertificates, so we inject that directly.
	call := func(class PeerClass) int {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(""))
		u, _ := PeerClassURI(class)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}},
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := call(PeerClassGateway); code != http.StatusOK {
		t.Errorf("allowed class got %d, want 200", code)
	}
	if code := call(PeerClassAgent); code != http.StatusForbidden {
		t.Errorf("disallowed agent class got %d, want 403", code)
	}
	if code := call(PeerClassControl); code != http.StatusForbidden {
		t.Errorf("disallowed control class got %d, want 403", code)
	}
}

// TestRequirePeerClass_HealthBypass asserts /health and /ready skip
// the peer-class check so external load-balancer probes work
// without a client cert.
func TestRequirePeerClass_HealthBypass(t *testing.T) {
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequirePeerClass(discardLogger, PeerClassGateway)(next)

	for _, path := range []string{"/health", "/ready"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			// No TLS state at all — still should pass.
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("health bypass: got %d", rr.Code)
			}
		})
	}
}

// TestRequirePeerClassNotRevoked_RejectsRevokedFingerprint pins WS12 #2: the
// CRL-consulting wrapper for the internal mTLS listeners. Peer-class is enforced
// FIRST (additive, not replaced), then revocation; a nil/unloaded checker fails
// closed; the match is the exact DER fingerprint; health bypasses.
func TestRequirePeerClassNotRevoked_RejectsRevokedFingerprint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	gwCert := realCertWithClass(t, PeerClassGateway)
	revokedFP := indepFingerprint(gwCert) // sourced independently of the middleware

	callWith := func(rev RevocationChecker, cert *x509.Certificate, path string) int {
		h := RequirePeerClassNotRevoked(logger, rev, PeerClassGateway)(next)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(""))
		if cert != nil {
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	loaded := func(fps ...string) fakeRev {
		set := map[string]bool{}
		for _, fp := range fps {
			set[fp] = true
		}
		return fakeRev{revoked: set, loaded: true}
	}

	t.Run("gateway class, not revoked, loaded → 200", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, callWith(loaded(), gwCert, "/x"))
	})
	t.Run("gateway class, revoked → 403", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, callWith(loaded(revokedFP), gwCert, "/x"),
			"a revoked gateway cert must be rejected at the internal listener (no ProxyGetLuksKey/LPS)")
	})
	t.Run("wrong class rejected first (peer-class is additive)", func(t *testing.T) {
		controlCert := realCertWithClass(t, PeerClassControl)
		// Even with an empty revocation set, a control-class cert on a
		// gateway-only listener is 403 from the peer-class gate.
		assert.Equal(t, http.StatusForbidden, callWith(loaded(), controlCert, "/x"))
	})
	t.Run("byte-tampered seed → real cert admitted (exact-fingerprint binding)", func(t *testing.T) {
		flipped := []byte(revokedFP)
		flipped[len(flipped)-1] ^= 0xFF
		assert.Equal(t, http.StatusOK, callWith(loaded(string(flipped)), gwCert, "/x"),
			"a tampered seed fingerprint matches no real cert → admitted")
	})
	t.Run("not-loaded cache fails closed even for a non-revoked cert", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, callWith(fakeRev{loaded: false}, gwCert, "/x"),
			"an unloaded CRL must fail closed on the internal listener too")
	})
	t.Run("nil checker fails closed", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, callWith(nil, gwCert, "/x"),
			"a bare nil checker must fail closed, never silently admit")
	})
	t.Run("health bypasses with no cert", func(t *testing.T) {
		for _, p := range []string{"/health", "/ready"} {
			assert.Equal(t, http.StatusOK, callWith(fakeRev{loaded: false}, nil, p),
				"%s must bypass both peer-class and revocation", p)
		}
	})
}

// TestRequirePeerClass_RejectsMissingTLS asserts a request without
// any TLS state is rejected before a nil dereference can happen.
func TestRequirePeerClass_RejectsMissingTLS(t *testing.T) {
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RequirePeerClass(discardLogger, PeerClassGateway)(http.NotFoundHandler())
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("missing TLS: got %d, want 401", rr.Code)
	}
}
