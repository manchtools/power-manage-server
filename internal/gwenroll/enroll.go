// Package gwenroll is the gateway's client side of spec 31 self-enrollment: it
// generates a keypair, submits a CSR to GatewayAuthService.EnrollGateway over
// control's public plane, and later renews via InternalService over the mTLS
// plane. The private key never leaves the process.
package gwenroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/mtls"
)

// Identity is a gateway's enrolled identity: the issued cert, the private key it
// was issued against (retained for renewal proof-of-possession), the CA trust
// anchor, and the gateway_id read from the cert CN.
type Identity struct {
	GatewayID string
	CertPEM   []byte
	KeyPEM    []byte
	CACertPEM []byte
	key       *ecdsa.PrivateKey
	// TLSCert is the parsed keypair, ready to seed a mtls.CertRotator.
	TLSCert tls.Certificate
}

// generateKeyAndCSR makes a fresh P-256 key and a plain (no-SAN) CSR bound to it.
// The CN is a placeholder — the CA overwrites the identity with the assigned
// gateway_id, so the CSR CN is never trusted.
func generateKeyAndCSR() (*ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "gateway"}}, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return key, csrPEM, keyPEM, nil
}

// Enroll submits a CSR to GatewayAuthService.EnrollGateway at enrollURL (control's
// public plane) with the bootstrap token, and returns the issued identity. The
// http.Client must trust control's public TLS (system CA or an operator pin).
func Enroll(ctx context.Context, httpClient connect.HTTPClient, enrollURL, token, hostname string) (*Identity, error) {
	key, csrPEM, keyPEM, err := generateKeyAndCSR()
	if err != nil {
		return nil, err
	}
	client := pmv1connect.NewGatewayAuthServiceClient(httpClient, enrollURL)
	resp, err := client.EnrollGateway(ctx, connect.NewRequest(&pm.EnrollGatewayRequest{
		Token:    token,
		Hostname: hostname,
		Csr:      csrPEM,
	}))
	if err != nil {
		return nil, fmt.Errorf("enroll gateway: %w", err)
	}
	return buildIdentity(key, keyPEM, resp.Msg.Certificate, resp.Msg.CaCert)
}

// Renew submits a new CSR (reusing the same key for proof-of-possession) to
// InternalService.RenewGatewayCertificate over the control-facing mTLS plane.
// On success it UPDATES id in place (CertPEM + TLSCert become the renewed cert,
// key unchanged) so id stays the live identity, and returns the new cert's
// not_after so the caller can schedule the next renewal at 80% of lifetime. The
// presented client cert is the current gateway cert supplied by the mTLS
// transport on internalClient.
func Renew(ctx context.Context, internalClient pmv1connect.InternalServiceClient, id *Identity) (notAfter time.Time, err error) {
	if id == nil || id.key == nil {
		return time.Time{}, fmt.Errorf("gwenroll: renew requires an enrolled identity holding its key")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "gateway"}}, id.key)
	if err != nil {
		return time.Time{}, fmt.Errorf("create renewal CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	resp, err := internalClient.RenewGatewayCertificate(ctx, connect.NewRequest(&pm.RenewGatewayCertificateRequest{
		Csr: csrPEM,
	}))
	if err != nil {
		return time.Time{}, fmt.Errorf("renew gateway certificate: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(resp.Msg.Certificate, id.KeyPEM)
	if err != nil {
		return time.Time{}, fmt.Errorf("load renewed keypair: %w", err)
	}
	if resp.Msg.NotAfter == nil {
		return time.Time{}, fmt.Errorf("renewal response missing not_after")
	}
	// Update the identity in place so id never goes stale relative to the wire.
	id.CertPEM = resp.Msg.Certificate
	id.TLSCert = tlsCert
	return resp.Msg.NotAfter.AsTime(), nil
}

// buildIdentity assembles an Identity from the issued cert, verifying the cert
// profile, reading the gateway_id from the CN, and loading the keypair.
func buildIdentity(key *ecdsa.PrivateKey, keyPEM, certPEM, caCertPEM []byte) (*Identity, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("issued gateway cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse issued gateway cert: %w", err)
	}
	// D7 (AC 6): reject a returned cert whose profile is not exactly what a
	// gateway needs. Checking only a non-empty CN would let a mis-issued cert
	// (wrong class, no DNS SAN, or missing an EKU) through here and fail agents'
	// TLS later at connection time; verify the whole profile so a wrong cert is a
	// loud boot failure instead.
	if err := verifyGatewayCertProfile(cert); err != nil {
		return nil, fmt.Errorf("issued gateway cert has the wrong profile: %w", err)
	}
	gatewayID := cert.Subject.CommonName
	if gatewayID == "" {
		return nil, fmt.Errorf("issued gateway cert has an empty CN")
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load issued keypair: %w", err)
	}
	return &Identity{
		GatewayID: gatewayID,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		CACertPEM: caCertPEM,
		key:       key,
		TLSCert:   tlsCert,
	}, nil
}

// verifyGatewayCertProfile asserts the CA returned exactly the cert a gateway
// needs before the gateway commits to it: the gateway peer class (SPIFFE URI
// SAN), at least one DNS SAN (the name agents verify at the mTLS handshake), and
// BOTH the ServerAuth EKU (it serves agents) and the ClientAuth EKU (it dials
// control's internal plane). Any deviation is a boot failure.
func verifyGatewayCertProfile(cert *x509.Certificate) error {
	class, err := mtls.PeerClassFromCert(cert)
	if err != nil {
		return fmt.Errorf("read peer class: %w", err)
	}
	if class != mtls.PeerClassGateway {
		return fmt.Errorf("peer class is %q, want %q", class, mtls.PeerClassGateway)
	}
	if len(cert.DNSNames) == 0 {
		return fmt.Errorf("no DNS SAN (agents could not verify the gateway server name)")
	}
	var hasServer, hasClient bool
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			hasServer = true
		case x509.ExtKeyUsageClientAuth:
			hasClient = true
		}
	}
	if !hasServer || !hasClient {
		return fmt.Errorf("EKUs %v are missing ServerAuth and/or ClientAuth", cert.ExtKeyUsage)
	}
	return nil
}
