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

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/ca"
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
// InternalService.RenewGatewayCertificate over the control-facing mTLS plane,
// and returns the new cert PEM + a parsed keypair ready to install in the
// rotator. The presented client cert is the current gateway cert supplied by the
// mTLS transport on internalClient.
func Renew(ctx context.Context, internalClient pmv1connect.InternalServiceClient, id *Identity) ([]byte, tls.Certificate, error) {
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "gateway"}}, id.key)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("create renewal CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	resp, err := internalClient.RenewGatewayCertificate(ctx, connect.NewRequest(&pm.RenewGatewayCertificateRequest{
		Csr: csrPEM,
	}))
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("renew gateway certificate: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(resp.Msg.Certificate, id.KeyPEM)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("load renewed keypair: %w", err)
	}
	return resp.Msg.Certificate, tlsCert, nil
}

// buildIdentity assembles an Identity from the issued cert, validating that the
// keypair loads and reading the gateway_id from the cert CN.
func buildIdentity(key *ecdsa.PrivateKey, keyPEM, certPEM, caCertPEM []byte) (*Identity, error) {
	gatewayID, err := ca.DeviceIDFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("read gateway_id from issued cert: %w", err)
	}
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
