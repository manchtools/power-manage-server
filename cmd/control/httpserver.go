package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"

	"github.com/manchtools/power-manage/server/internal/ca"
)

const publicRequestReadTimeout = 30 * time.Second

func buildPublicServer(cfg *Config, handler http.Handler) (*http.Server, error) {
	server := &http.Server{
		Addr: cfg.PublicListen, Handler: handler, IdleTimeout: 120 * time.Second,
		ReadTimeout: publicRequestReadTimeout, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	if cfg.PublicTLSCertFile == "" {
		return server, nil
	}
	certificate, err := tls.LoadX509KeyPair(cfg.PublicTLSCertFile, cfg.PublicTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load public TLS certificate: %w", err)
	}
	server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return nil, fmt.Errorf("configure public HTTP/2: %w", err)
	}
	return server, nil
}

func buildAgentServer(cfg *Config, certificateAuthority *ca.CA, handler http.Handler) (*http.Server, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.AgentTLSCertFile, cfg.AgentTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load agent-listener TLS certificate: %w", err)
	}
	server := &http.Server{
		Addr: cfg.AgentListen, Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: certificateAuthority.TrustPool(), MinVersion: tls.VersionTLS13,
		},
		IdleTimeout: 120 * time.Second, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return nil, fmt.Errorf("configure agent HTTP/2: %w", err)
	}
	return server, nil
}

// serveAgent accepts only PROXY-v2-prefixed connections from the configured
// isolated Traefik network, then performs device mTLS on the remaining stream.
// The PROXY header is outside TLS, so the proxy listener wraps the raw socket
// and the TLS listener wraps it in turn.
func serveAgent(server *http.Server, sources []string) error {
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	proxyListener, err := agentProxyListener(listener, sources)
	if err != nil {
		_ = listener.Close()
		return err
	}
	return server.Serve(tls.NewListener(proxyListener, server.TLSConfig))
}

func agentProxyListener(listener net.Listener, sources []string) (net.Listener, error) {
	if listener == nil {
		return nil, fmt.Errorf("agent listener is required")
	}
	policy, err := proxyproto.TrustProxyHeaderFromRanges(sources)
	if err != nil {
		return nil, fmt.Errorf("agent proxy sources: %w", err)
	}
	return &proxyproto.Listener{
		Listener: listener, ConnPolicy: policy, ReadHeaderTimeout: 5 * time.Second,
		ValidateHeader: func(header *proxyproto.Header) error {
			if header.Version != 2 {
				return fmt.Errorf("agent listener requires PROXY protocol v2")
			}
			return nil
		},
	}, nil
}
