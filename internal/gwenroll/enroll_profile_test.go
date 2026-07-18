package gwenroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"
)

// TestBuildIdentity_RejectsWrongCertProfile pins spec 31 D7 (AC 6): a returned
// cert that is not a proper gateway cert — here a plain self-signed cert with a
// CN but no gateway SPIFFE URI SAN, no DNS SAN, and no gateway EKUs — must fail
// at boot, not be accepted and blow up against agents' TLS later.
func TestBuildIdentity_RejectsWrongCertProfile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ulid.Make().String()},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	_, err = buildIdentity(key, keyPEM, certPEM, certPEM)
	require.Error(t, err)
	require.Contains(t, err.Error(), "wrong profile",
		"a non-gateway cert profile must be rejected at boot")
}
