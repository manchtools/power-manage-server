// Package mtls provides mTLS configuration for the gateway server.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// Config holds the mTLS configuration.
type Config struct {
	// CertFile is the path to the server certificate.
	CertFile string
	// KeyFile is the path to the server private key.
	KeyFile string
	// CAFile is the path to the CA certificate for validating client certs.
	CAFile string
}

// NewTLSConfig creates a TLS configuration for mTLS.
func NewTLSConfig(cfg Config) (*tls.Config, error) {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}

	// Load CA certificate for client validation
	caCert, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// DeviceIDFromRequest extracts the device ID from the client certificate CN.
// The certificate CN should be set to the device ID during registration.
func DeviceIDFromRequest(r *http.Request) (string, error) {
	if r.TLS == nil {
		return "", errors.New("no TLS connection")
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate")
	}

	cert := r.TLS.PeerCertificates[0]
	deviceID := cert.Subject.CommonName

	if deviceID == "" {
		return "", errors.New("certificate CN is empty")
	}

	return deviceID, nil
}

// DeviceIDFromTLS extracts the device ID from a TLS connection state.
func DeviceIDFromTLS(state *tls.ConnectionState) (string, error) {
	if state == nil {
		return "", errors.New("no TLS connection state")
	}

	if len(state.PeerCertificates) == 0 {
		return "", errors.New("no client certificate")
	}

	cert := state.PeerCertificates[0]
	deviceID := cert.Subject.CommonName

	if deviceID == "" {
		return "", errors.New("certificate CN is empty")
	}

	return deviceID, nil
}

// CertificateFingerprint returns the SHA256 fingerprint of a certificate.
func CertificateFingerprint(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate")
	}

	cert := r.TLS.PeerCertificates[0]
	return fmt.Sprintf("%x", cert.Raw), nil
}
