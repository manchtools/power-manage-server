package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/http2"

	"github.com/manchtools/power-manage/server/internal/ca"
)

func buildPublicServer(cfg *Config, handler http.Handler) (*http.Server, error) {
	server := &http.Server{
		Addr: cfg.PublicListen, Handler: handler, IdleTimeout: 120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 1 << 20,
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
