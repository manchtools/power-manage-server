package mtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/mtls"
)

// TestFingerprintFromCert_MatchesTheCAImplementation pins that mtls's private
// fingerprintFromCert and ca.FingerprintFromCert produce the SAME string.
//
// They are duplicate implementations by necessity — ca imports mtls, so mtls
// cannot import ca back and reuses the algorithm instead — and they meet on the
// revoked_certificates table: the renewal/deletion handlers store and revoke
// the fingerprint ca computes, while the handshake gate
// (RequirePeerClassNotRevoked) looks up the fingerprint mtls computes. Nothing
// in the build couples them, so if one drifts — a different hash, a different
// encoding, hashing RawTBSCertificate instead of Raw — every lookup misses,
// every revoked certificate is admitted, and no test goes red. The duplication
// is fine; the un-pinned duplication is the finding.
//
// The certificate is really generated (not a hand-built struct) so cert.Raw is
// genuine DER, and the value is additionally checked against an independently
// written hex(sha256(cert.Raw)) — otherwise two implementations could agree on
// the same wrong answer.
func TestFingerprintFromCert_MatchesTheCAImplementation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "01J0000000000000000000DEV1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	fromMTLS := mtls.FingerprintFromCertForTest(cert)
	fromCA := ca.FingerprintFromCert(cert)

	require.NotEmpty(t, fromMTLS, "a real certificate must produce a fingerprint, or the comparison below is vacuous")
	assert.Equal(t, fromCA, fromMTLS,
		"the handshake gate derives the fingerprint with mtls.fingerprintFromCert while renewal/deletion store and "+
			"revoke the one ca.FingerprintFromCert derives; a drift between them silently admits every revoked certificate")

	sum := sha256.Sum256(cert.Raw)
	want := hex.EncodeToString(sum[:])
	assert.Equal(t, want, fromMTLS,
		"both implementations must be hex(sha256(DER)) — agreeing on a different value would still break the "+
			"fingerprints already stored in revoked_certificates")
}

// A nil leaf must yield the empty string from BOTH, not panic on a hot
// handshake path and not diverge. Each implementation documents the nil case as
// fail-safe (an empty fingerprint matches no revoked row); an asymmetry here
// would mean one of them panics where the other returns.
func TestFingerprintFromCert_NilCertAgreesWithTheCAImplementation(t *testing.T) {
	assert.Equal(t, ca.FingerprintFromCert(nil), mtls.FingerprintFromCertForTest(nil))
	assert.Empty(t, mtls.FingerprintFromCertForTest(nil))
}
