package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// issueTestDeviceCert issues a certificate for the given device ID using the
// provided CA, and returns the PEM cert, its fingerprint, and a fresh CSR for renewal.
func issueTestDeviceCert(t *testing.T, certAuth *ca.CA, deviceID string) (certPEM []byte, fingerprint string, csrPEM []byte) {
	t.Helper()

	// Generate device key and CSR for initial issuance
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: deviceID},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, deviceKey)
	require.NoError(t, err)
	initialCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	cert, err := certAuth.IssueCertificateFromCSR(deviceID, initialCSR)
	require.NoError(t, err)

	// Generate a new key + CSR for renewal
	renewKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	renewCSRDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, renewKey)
	require.NoError(t, err)
	renewCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: renewCSRDER})

	return cert.CertPEM, cert.Fingerprint, renewCSR
}

// setDeviceCertFingerprint stores a cert fingerprint on a device via event.
func setDeviceCertFingerprint(t *testing.T, st *store.Store, deviceID, fingerprint string) {
	t.Helper()
	err := st.AppendEvent(t.Context(), store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceCertRenewed",
		Data: map[string]any{
			"cert_fingerprint": fingerprint,
			"cert_not_after":   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		},
		ActorType: "device",
		ActorID:   deviceID,
	})
	require.NoError(t, err)
}

func TestRenewCertificate_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewCertificateHandler(st, certAuth, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "renew-host")
	certPEM, fingerprint, csrPEM := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, fingerprint)

	resp, err := h.RenewCertificate(t.Context(), connect.NewRequest(&pm.RenewCertificateRequest{
		CurrentCertificate: certPEM,
		Csr:                csrPEM,
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Certificate)
	assert.NotNil(t, resp.Msg.NotAfter)
	assert.NotEmpty(t, resp.Msg.CaCertificate)
}

func TestRenewCertificate_DeviceNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewCertificateHandler(st, certAuth, slog.Default())

	// Issue a cert for a device that does not exist in the DB
	fakeDeviceID := testutil.NewID()
	certPEM, _, csrPEM := issueTestDeviceCert(t, certAuth, fakeDeviceID)

	_, err := h.RenewCertificate(t.Context(), connect.NewRequest(&pm.RenewCertificateRequest{
		CurrentCertificate: certPEM,
		Csr:                csrPEM,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestRenewCertificate_DeletedDevice(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewCertificateHandler(st, certAuth, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "deleted-host")
	certPEM, fingerprint, csrPEM := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, fingerprint)

	// Delete the device
	err := st.AppendEvent(t.Context(), store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  "DeviceDeleted",
		Data:       map[string]any{},
		ActorType:  "system",
		ActorID:    "test",
	})
	require.NoError(t, err)

	_, err = h.RenewCertificate(t.Context(), connect.NewRequest(&pm.RenewCertificateRequest{
		CurrentCertificate: certPEM,
		Csr:                csrPEM,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestRenewCertificate_FingerprintMismatch(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewCertificateHandler(st, certAuth, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "mismatch-host")
	certPEM, _, csrPEM := issueTestDeviceCert(t, certAuth, deviceID)

	// Store a DIFFERENT fingerprint on the device
	setDeviceCertFingerprint(t, st, deviceID, "0000000000000000000000000000000000000000000000000000000000000000")

	_, err := h.RenewCertificate(t.Context(), connect.NewRequest(&pm.RenewCertificateRequest{
		CurrentCertificate: certPEM,
		Csr:                csrPEM,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}
