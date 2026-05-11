// HTTP-server boot helpers extracted from main.go (audit F043 / #157,
// slice 2). The public listener and the internal mTLS listener
// previously inlined ~50 LOC of TLS+http2 plumbing each in main(); the
// builders here own that plumbing so main() reads as wire-the-handlers
// + start-the-listeners rather than wire-the-handlers + load-certs +
// build-tls-config + configure-h2 + start-the-listeners.
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/http2"

	"github.com/manchtools/power-manage/server/internal/ca"
)

// buildPublicServer constructs the public-facing HTTP server with the
// supplied handler, configuring TLS + HTTP/2 when cfg.TLSEnabled. Plain
// HTTP/1.1 is used otherwise (development / behind-Traefik deployments).
//
// Idle/read-header timeouts are fixed (120s / 10s) — they're tuned for
// long-poll style RPCs and a header parse window that catches slow-loris
// without breaking the slowest legitimate client we've seen. No operator
// knob is exposed because nobody has ever needed to tune these.
func buildPublicServer(cfg *Config, handler http.Handler) (*http.Server, error) {
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if !cfg.TLSEnabled {
		return srv, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("load public TLS key pair: %w", err)
	}
	srv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		return nil, fmt.Errorf("configure HTTP/2 for public server: %w", err)
	}
	return srv, nil
}

// buildInternalServer constructs the mTLS-protected internal listener
// the gateway connects to for InternalService RPCs. Client certs MUST
// be presented and verified against the control's CA pool — a
// compromised agent cert (which uses a different chain in production
// but can race during enrollment) is rejected at the TLS layer before
// any handler sees the request. The peer-class gate inside the handler
// chain is a defence-in-depth on top of this.
//
// HTTP/2 is mandatory: Connect-RPC's bidirectional streaming uses h2
// frames over the TLS transport.
func buildInternalServer(cfg *Config, certAuth *ca.CA, handler http.Handler) (*http.Server, error) {
	internalTLSCert, err := tls.LoadX509KeyPair(cfg.InternalTLSCert, cfg.InternalTLSKey)
	if err != nil {
		return nil, fmt.Errorf("load internal TLS key pair (cert=%s key=%s): %w", cfg.InternalTLSCert, cfg.InternalTLSKey, err)
	}

	srv := &http.Server{
		Addr:    cfg.InternalListenAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{internalTLSCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certAuth.TrustPool(),
			MinVersion:   tls.VersionTLS13,
		},
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		return nil, fmt.Errorf("configure HTTP/2 for internal server: %w", err)
	}
	return srv, nil
}
