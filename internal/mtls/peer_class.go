package mtls

import (
	"crypto/tls"
	"crypto/x509"
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
// server's InternalService, which accepts only gateway peers).
//
// The SPIFFE URI shape is standard, machine-readable, and puts the
// class in a field (SAN URI) that X.509 parsers treat as structured
// data — unlike the CN, which is a free-form string reused for
// device IDs on agent certs.
type PeerClass string

const (
	// PeerClassAgent identifies a managed-device cert issued by the
	// control server's Register / RenewCertificate RPC. Agents
	// present this on the gateway's public mTLS listener.
	PeerClassAgent PeerClass = "agent"
	// PeerClassGateway identifies a gateway replica cert issued out
	// of band by setup.sh. Gateways present this when calling the
	// control server's InternalService (ProxyGetLuksKey, etc.).
	PeerClassGateway PeerClass = "gateway"
	// PeerClassControl identifies the control server's internal
	// cert issued out of band by setup.sh. The control server
	// presents this when calling the gateway's GatewayService
	// (admin list/terminate fan-out).
	PeerClassControl PeerClass = "control"
)

// peerClassURIScheme and peerClassURIHost match the URI SAN layout
// that ca.IssueCertificateFromCSR emits for agent certs and that
// setup.sh emits for gateway/control certs. Keeping them in one
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
	case PeerClassAgent, PeerClassGateway, PeerClassControl:
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
// currently needed, but possible — e.g. a GatewayService endpoint
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
	case PeerClassAgent, PeerClassGateway, PeerClassControl:
	default:
		return nil, fmt.Errorf("unknown peer class %q", class)
	}
	return url.Parse(peerClassURI(class))
}
