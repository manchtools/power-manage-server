package datastore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedPEM returns a throwaway leaf cert + key + a CA PEM (self-signed, so
// cert == its own CA) for exercising ValkeyClientTLS without external fixtures.
func selfSignedPEM(t *testing.T) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pm-control"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, certPEM // self-signed: the cert is its own CA
}

func TestValkeyClientTLS_BuildsStrictClientConfig(t *testing.T) {
	certPEM, keyPEM, caPEM := selfSignedPEM(t)
	cfg, err := ValkeyClientTLS(certPEM, keyPEM, caPEM)
	if err != nil {
		t.Fatalf("ValkeyClientTLS: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected the client certificate to be installed, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs must pin the internal CA (server verification), got nil")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3 (%x)", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestValkeyClientTLS_RejectsBadMaterial(t *testing.T) {
	certPEM, keyPEM, _ := selfSignedPEM(t)
	if _, err := ValkeyClientTLS(certPEM, keyPEM, []byte("not a ca")); err == nil {
		t.Error("a malformed CA must be rejected")
	}
	if _, err := ValkeyClientTLS([]byte("not a cert"), keyPEM, certPEM); err == nil {
		t.Error("a malformed client cert/key pair must be rejected")
	}
}

func TestRequirePostgresTLS(t *testing.T) {
	const certs = "&sslrootcert=/c/ca.crt&sslcert=/c/pg.crt&sslkey=/c/pg.key"
	cases := []struct {
		name string
		dsn  string
		ok   bool
	}{
		{"url verify-full + certs", "postgres://u:p@h:5432/db?sslmode=verify-full" + certs, true},
		{"keyword verify-full + certs", "host=h dbname=db sslmode=verify-full sslrootcert=/c/ca.crt sslcert=/c/pg.crt sslkey=/c/pg.key", true},
		{"sslmode=disable rejected", "postgres://u:p@h:5432/db?sslmode=disable", false},
		{"absent sslmode rejected", "postgres://u:p@h:5432/db", false},
		{"verify-full but no client cert", "postgres://u:p@h:5432/db?sslmode=verify-full&sslrootcert=/c/ca.crt", false},
		{"require (not verify-full) rejected", "postgres://u:p@h:5432/db?sslmode=require" + certs, false},
		// Fail-closed regression: the real sslmode is disable; a quoted value
		// embedding "sslmode=verify-full" must NOT be split into a spurious token
		// that overwrites it (a bare strings.Fields split would wrongly accept).
		{"keyword quoted value cannot forge sslmode",
			"host=h dbname=db sslmode=disable sslrootcert=/c/ca.crt sslcert=/c/pg.crt sslkey=/c/pg.key application_name='x sslmode=verify-full'",
			false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RequirePostgresTLS(tc.dsn)
			if tc.ok && err != nil {
				t.Errorf("expected acceptance, got: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("expected fail-closed rejection, got nil")
			}
		})
	}
}
