package mtls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// PeerClass identifies the role of a mTLS peer. The internal CA
// issues every non-CA certificate with exactly one URI SAN of the
// form `spiffe://power-manage/<class>`, where `<class>` is one of
// the constants below. Middleware on each listener requires a
// specific class so a leaked cert of one class (e.g. an agent
// cert pulled from a compromised host) cannot be used to reach
// a listener intended for another class (e.g. the control
// agent listener, which accepts only agent peers).
//
// The SPIFFE URI shape is standard, machine-readable, and puts the
// class in a field (SAN URI) that X.509 parsers treat as structured
// data — unlike the CN, which is a free-form string reused for
// device IDs on agent certs.
type PeerClass string

const (
	// PeerClassAgent identifies a managed-device cert issued by the
	// control server's Register / RenewCertificate RPC. Agents
	// present this on control's own mTLS listener.
	PeerClassAgent PeerClass = "agent"
	// PeerClassControl identifies the control server's own cert,
	// issued out of band by setup.sh and presented on its agent
	// listener.
	PeerClassControl PeerClass = "control"
)

// peerClassURIScheme and peerClassURIHost match the URI SAN layout
// that ca.IssueCertificateFromCSR emits for agent certs and that
// setup.sh emits for the control cert. Keeping them in one
// place makes it obvious where to add a new class.
const (
	peerClassURIScheme = "spiffe"
	peerClassURIHost   = "power-manage"
)

// peerClassURI builds the canonical SPIFFE URI for a class. Kept in
// one place so emitters (CA + setup.sh) and verifiers agree.
func peerClassURI(class PeerClass) string {
	return fmt.Sprintf("%s://%s/%s", peerClassURIScheme, peerClassURIHost, class)
}

// PeerClassFromCert inspects the URI SANs on a peer certificate and
// returns the identified class, or an error if the cert carries no
// `spiffe://power-manage/<class>` URI or carries more than one such
// URI (ambiguous class is a hard error — the CA MUST emit exactly
// one).
func PeerClassFromCert(cert *x509.Certificate) (PeerClass, error) {
	if cert == nil {
		return "", errors.New("nil certificate")
	}
	var found PeerClass
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		if u.Scheme != peerClassURIScheme || u.Host != peerClassURIHost {
			continue
		}
		class := PeerClass(strings.TrimPrefix(u.Path, "/"))
		if class == "" {
			continue
		}
		if found != "" && found != class {
			return "", fmt.Errorf("certificate carries multiple peer-class URIs (%q and %q)", found, class)
		}
		found = class
	}
	if found == "" {
		return "", errors.New("certificate has no peer-class URI SAN")
	}
	switch found {
	case PeerClassAgent, PeerClassControl:
		return found, nil
	default:
		return "", fmt.Errorf("unknown peer class %q", found)
	}
}

// PeerClassFromTLS extracts the peer class from the first peer
// certificate of a TLS connection state. Callers that already have
// an *x509.Certificate should use PeerClassFromCert directly.
func PeerClassFromTLS(state *tls.ConnectionState) (PeerClass, error) {
	if state == nil {
		return "", errors.New("no TLS connection state")
	}
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("no peer certificate")
	}
	return PeerClassFromCert(state.PeerCertificates[0])
}

// RequirePeerClass returns middleware that extracts the peer class
// from the client certificate and rejects requests whose peer does
// not match one of allowed. Health endpoints (/health, /ready) are
// passed through untouched so they work without mTLS on the ops
// listener.
//
// The classes are allowed as a set (variadic) rather than a single
// class so a listener that serves multiple peer populations (not
// currently needed, but possible — e.g. an endpoint
// reachable by both control and admin CLI peers) does not need to
// be wrapped twice.
func RequirePeerClass(logger *slog.Logger, allowed ...PeerClass) func(http.Handler) http.Handler {
	allowSet := make(map[PeerClass]struct{}, len(allowed))
	for _, c := range allowed {
		allowSet[c] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || r.URL.Path == "/ready" {
				next.ServeHTTP(w, r)
				return
			}
			if r.TLS == nil {
				http.Error(w, "mTLS required", http.StatusUnauthorized)
				return
			}
			class, err := PeerClassFromTLS(r.TLS)
			if err != nil {
				if logger != nil {
					logger.Warn("peer-class check failed: cert missing class",
						"remote_addr", r.RemoteAddr,
						"path", r.URL.Path,
						"error", err,
					)
				}
				http.Error(w, "peer class required", http.StatusForbidden)
				return
			}
			if _, ok := allowSet[class]; !ok {
				if logger != nil {
					logger.Warn("peer-class check failed: wrong class",
						"remote_addr", r.RemoteAddr,
						"path", r.URL.Path,
						"presented", class,
						"allowed", allowedClassString(allowed),
					)
				}
				http.Error(w, "peer class not allowed", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RevocationChecker reports whether a peer cert (by SHA-256 DER fingerprint) is
// revoked. This interface lives in mtls (not handler) so the listener wrappers
// here can consult it without importing handler — handler imports mtls, so the
// reverse would be an import cycle.
//
// Revocation is a direct indexed database query on every handshake. A cached
// snapshot would create a stale admission window after revocation.
//
// A nil checker, or a lookup that ERRORS, is FAIL-CLOSED: without an answer we
// cannot prove the cert is unrevoked, so we reject. There is deliberately no
// opt-out.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, fingerprint string) (bool, error)
}

// fingerprintFromCert returns hex(sha256(cert.Raw)), matching
// ca.FingerprintFromCert. Reimplemented here (rather than imported) because ca
// imports mtls — see RevocationChecker. Empty for a nil cert (fails safe: an
// empty fingerprint matches no revoked entry, and nil certs are already rejected
// upstream by the peer-class / TLS checks).
func fingerprintFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// RequirePeerClassNotRevoked is RequirePeerClass plus a fail-closed CRL gate, for
// control's agent mTLS listener. After the peer-class checks pass it consults
// the revocation list, so a revoked cert is rejected at connect time rather
// than usable until its natural expiry. Health endpoints bypass as in
// RequirePeerClass.
//
// Revocation is ADDITIVE: a wrong-class cert is still rejected first by the
// peer-class check. A nil checker, or a lookup that errors, fails closed (403).
func RequirePeerClassNotRevoked(logger *slog.Logger, revocation RevocationChecker, allowed ...PeerClass) func(http.Handler) http.Handler {
	peerClass := RequirePeerClass(logger, allowed...)
	return func(next http.Handler) http.Handler {
		// Wrap the existing peer-class middleware so class is enforced FIRST,
		// then revocation. The revocation check sees only requests that already
		// passed the class gate (and the health bypass).
		revocationGate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || r.URL.Path == "/ready" {
				next.ServeHTTP(w, r)
				return
			}
			// r.TLS and PeerCertificates are guaranteed non-nil here:
			// RequirePeerClass rejected a nil r.TLS / class-less cert before
			// delegating to this handler.
			if revocation == nil {
				if logger != nil {
					logger.Warn("mTLS rejected: no revocation checker configured (fail-closed)",
						"remote_addr", r.RemoteAddr, "path", r.URL.Path)
				}
				http.Error(w, "client certificate revocation unavailable", http.StatusForbidden)
				return
			}
			fp := fingerprintFromCert(r.TLS.PeerCertificates[0])
			revoked, err := revocation.IsRevoked(r.Context(), fp)
			if err != nil {
				// Fail closed on an indeterminate answer. A database blip must
				// not become an admission: we cannot prove this certificate is
				// unrevoked, so we refuse it.
				if logger != nil {
					logger.Error("mTLS rejected: revocation lookup failed (fail-closed)",
						"remote_addr", r.RemoteAddr, "path", r.URL.Path, "error", err)
				}
				http.Error(w, "client certificate revocation unavailable", http.StatusForbidden)
				return
			}
			if revoked {
				if logger != nil {
					logger.Warn("mTLS rejected: certificate revoked",
						"remote_addr", r.RemoteAddr, "path", r.URL.Path)
				}
				http.Error(w, "client certificate revoked", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
		return peerClass(revocationGate)
	}
}

func allowedClassString(classes []PeerClass) string {
	out := make([]string, 0, len(classes))
	for _, c := range classes {
		out = append(out, string(c))
	}
	return strings.Join(out, ",")
}

// PeerClassURI returns the SPIFFE URI shape a CA emitter should
// stamp onto a newly-issued certificate for the given class. Kept
// exported so ca.IssueCertificateFromCSR can use it without
// duplicating the format literal.
func PeerClassURI(class PeerClass) (*url.URL, error) {
	switch class {
	case PeerClassAgent, PeerClassControl:
	default:
		return nil, fmt.Errorf("unknown peer class %q", class)
	}
	return url.Parse(peerClassURI(class))
}
