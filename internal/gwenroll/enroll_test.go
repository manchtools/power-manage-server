package gwenroll_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/gwenroll"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func buildTestCA(t *testing.T) *ca.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	c, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)
	return c
}

// TestEnroll_EndToEnd exercises the gateway enrollment client against the REAL
// GatewayAuthService handler in-process (spec 31): a gateway generates a keypair,
// submits a CSR, and receives an identity whose gateway_id is a ULID and whose
// cert verifies against the returned CA *as a TLS server cert* (ServerAuth EKU) —
// the property the agent-facing mTLS listener relies on.
func TestEnroll_EndToEnd(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := buildTestCA(t)
	const token = "e2e-enroll-token"
	h := api.NewGatewayAuthHandler(st, certAuth, token, "https://gw1.example.com", nil, slog.Default())

	mux := http.NewServeMux()
	path, handler := pmv1connect.NewGatewayAuthServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	const hostname = "gw1.example.com"
	id, err := gwenroll.Enroll(context.Background(), srv.Client(), srv.URL, token, hostname)
	require.NoError(t, err)

	_, err = ulid.Parse(id.GatewayID)
	require.NoError(t, err, "gateway_id must be a ULID read from the cert CN")
	require.NotEmpty(t, id.CertPEM)
	require.NotEmpty(t, id.KeyPEM)
	require.NotEmpty(t, id.CACertPEM)

	// The enrolled cert must verify against the returned CA AS A TLS SERVER CERT.
	// This fails on a client-auth-only cert, so it regression-guards the
	// gateway-cert ServerAuth EKU the agent-facing listener needs.
	block, _ := pem.Decode(id.CertPEM)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(id.CACertPEM))
	// Verify exactly as the agent does: standard TLS verification against the CA
	// with the gateway's hostname as ServerName — this exercises BOTH the
	// ServerAuth EKU and the server-stamped DNS SAN, the two properties a
	// client-auth-only / no-DNS-SAN cert would fail.
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   hostname,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err, "enrolled gateway cert must verify as a TLS server cert for its hostname against the returned CA")
}

func TestEnroll_WrongTokenErrors(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := buildTestCA(t)
	h := api.NewGatewayAuthHandler(st, certAuth, "correct-token", "https://gw1.example.com", nil, slog.Default())
	mux := http.NewServeMux()
	path, handler := pmv1connect.NewGatewayAuthServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := gwenroll.Enroll(context.Background(), srv.Client(), srv.URL, "wrong-token", "gw1")
	require.Error(t, err, "enrollment with a wrong token must fail")
}
