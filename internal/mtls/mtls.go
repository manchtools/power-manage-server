// Package mtls extracts and validates agent identities from mutual TLS.
package mtls

import (
	"crypto/tls"
	"errors"
	"net/http"
)

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
