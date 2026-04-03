package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeviceIDFromRequest_Success(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "device-abc123"}},
		},
	}

	id, err := DeviceIDFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "device-abc123" {
		t.Fatalf("got %q, want %q", id, "device-abc123")
	}
}

func TestDeviceIDFromRequest_NoTLS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = nil

	_, err := DeviceIDFromRequest(req)
	if err == nil {
		t.Fatal("expected error for nil TLS")
	}
	if err.Error() != "no TLS connection" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeviceIDFromRequest_NoPeerCerts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}

	_, err := DeviceIDFromRequest(req)
	if err == nil {
		t.Fatal("expected error for empty peer certificates")
	}
	if err.Error() != "no client certificate" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeviceIDFromRequest_EmptyCN(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: ""}},
		},
	}

	_, err := DeviceIDFromRequest(req)
	if err == nil {
		t.Fatal("expected error for empty CN")
	}
	if err.Error() != "certificate CN is empty" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeviceIDFromTLS_Success(t *testing.T) {
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "device-xyz"}},
		},
	}

	id, err := DeviceIDFromTLS(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "device-xyz" {
		t.Fatalf("got %q, want %q", id, "device-xyz")
	}
}

func TestDeviceIDFromTLS_NilState(t *testing.T) {
	_, err := DeviceIDFromTLS(nil)
	if err == nil {
		t.Fatal("expected error for nil state")
	}
	if err.Error() != "no TLS connection state" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeviceIDFromTLS_NoPeerCerts(t *testing.T) {
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}

	_, err := DeviceIDFromTLS(state)
	if err == nil {
		t.Fatal("expected error for empty peer certificates")
	}
}

func TestDeviceIDFromTLS_EmptyCN(t *testing.T) {
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: ""}},
		},
	}

	_, err := DeviceIDFromTLS(state)
	if err == nil {
		t.Fatal("expected error for empty CN")
	}
}

func TestCertificateFingerprint_Success(t *testing.T) {
	rawBytes := []byte("test-certificate-bytes")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Raw: rawBytes},
		},
	}

	fp, err := CertificateFingerprint(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	// The fingerprint is hex-encoded raw bytes
	if fp != "746573742d63657274696669636174652d6279746573" {
		t.Fatalf("unexpected fingerprint: %s", fp)
	}
}

func TestCertificateFingerprint_NoTLS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = nil

	_, err := CertificateFingerprint(req)
	if err == nil {
		t.Fatal("expected error for nil TLS")
	}
}

func TestCertificateFingerprint_NoPeerCerts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}

	_, err := CertificateFingerprint(req)
	if err == nil {
		t.Fatal("expected error for empty peer certificates")
	}
}

func TestDeviceIDFromRequest_UsesFirstCert(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "first-device"}},
			{Subject: pkix.Name{CommonName: "second-device"}},
		},
	}

	id, err := DeviceIDFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "first-device" {
		t.Fatalf("expected first cert CN, got %q", id)
	}
}
