package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
)

// NewServerTLSConfigFromPEM builds a mTLS server config from in-memory PEM (spec
// 31): the gateway holds its enrolled cert + key in the process and never writes
// them to disk. Mirrors NewTLSConfig (file-based) but takes bytes.
func NewServerTLSConfigFromPEM(certPEM, keyPEM, caPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse CA certificate")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// CertRotator holds the gateway's current client certificate behind an atomic
// swap, so a renewal goroutine can install a new cert (spec 31 Part B) without
// dropping live agent connections or rebuilding listeners. Wire it into a
// tls.Config via GetCertificate (server) and GetClientCertificate (client): TLS
// calls the callback per handshake, so new handshakes pick up the rotated cert
// while in-flight ones finish on the old one.
type CertRotator struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

// NewCertRotator seeds a rotator with the initial keypair.
func NewCertRotator(cert tls.Certificate) *CertRotator {
	return &CertRotator{cert: &cert}
}

// Set atomically installs a new certificate for subsequent handshakes.
func (r *CertRotator) Set(cert tls.Certificate) {
	r.mu.Lock()
	r.cert = &cert
	r.mu.Unlock()
}

// current returns the live certificate under the read lock.
func (r *CertRotator) current() *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert
}

// GetCertificate is the tls.Config server callback: returns the current cert for
// each ClientHello.
func (r *CertRotator) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current(), nil
}

// GetClientCertificate is the tls.Config client callback: returns the current
// cert when a server requests one.
func (r *CertRotator) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.current(), nil
}

// ServerTLSConfig builds a mTLS server config whose leaf is served from the
// rotator (dynamic), validating agent client certs against caPEM.
func (r *CertRotator) ServerTLSConfig(caPEM []byte) (*tls.Config, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse CA certificate")
	}
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
		MinVersion:     tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig builds a mTLS client config that presents the rotator's cert
// and trusts caPEM (for the gateway's control-facing InternalService client).
func (r *CertRotator) ClientTLSConfig(caPEM []byte) (*tls.Config, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse CA certificate")
	}
	return &tls.Config{
		GetClientCertificate: r.GetClientCertificate,
		RootCAs:              caPool,
		MinVersion:           tls.VersionTLS13,
	}, nil
}
