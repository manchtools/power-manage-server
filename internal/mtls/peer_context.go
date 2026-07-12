package mtls

import (
	"context"
	"crypto/x509"
	"net/http"
)

// peerCertCtxKey keys the authenticated peer leaf certificate in a request
// context. Unexported so only this package can set it.
type peerCertCtxKey struct{}

// WithPeerCert injects the authenticated mTLS peer leaf certificate into the
// request context, so a Connect handler (which cannot reach r.TLS directly) can
// read the peer identity — its CN (gateway_id) and its key/fingerprint for
// proof-of-possession and revocation. Intended to wrap an internal mTLS handler
// AFTER RequirePeerClassNotRevoked has already validated class + revocation, so
// a cert reaching here is a verified peer. A missing peer cert leaves the
// context untouched (PeerCertFromContext then reports absent → the handler
// rejects, fail-closed).
func WithPeerCert(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			r = r.WithContext(ContextWithPeerCert(r.Context(), r.TLS.PeerCertificates[0]))
		}
		next.ServeHTTP(w, r)
	})
}

// ContextWithPeerCert returns ctx carrying cert as the authenticated peer leaf.
// WithPeerCert uses it on the HTTP path; handler tests use it to exercise the
// peer-cert-dependent path (e.g. gateway renewal) without a live TLS handshake.
func ContextWithPeerCert(ctx context.Context, cert *x509.Certificate) context.Context {
	return context.WithValue(ctx, peerCertCtxKey{}, cert)
}

// PeerCertFromContext returns the authenticated peer leaf certificate injected
// by WithPeerCert, or (nil, false) if none is present.
func PeerCertFromContext(ctx context.Context) (*x509.Certificate, bool) {
	c, ok := ctx.Value(peerCertCtxKey{}).(*x509.Certificate)
	return c, ok && c != nil
}
