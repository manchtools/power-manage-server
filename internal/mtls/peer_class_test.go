package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

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
		"nil cert":        nil,
		"no URI SAN":      {},
		"wrong scheme":    {URIs: []*url.URL{mustURL(t, "https://power-manage/agent")}},
		"wrong host":      {URIs: []*url.URL{mustURL(t, "spiffe://other/agent")}},
		"unknown class":   {URIs: []*url.URL{mustURL(t, "spiffe://power-manage/admin")}},
		"empty class":     {URIs: []*url.URL{mustURL(t, "spiffe://power-manage/")}},
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
