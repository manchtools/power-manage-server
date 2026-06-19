package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
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

	// Renewal CSR reuses the SAME key — this matches real agent behavior
	// (cert_rotation.go calls GenerateCSRFromKey on the existing private key)
	// and is required by the renewal proof-of-possession check (#361): the
	// renewer must prove possession of the key bound to the current cert.
	renewCSRDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, deviceKey)
	require.NoError(t, err)
	renewCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: renewCSRDER})

	return cert.CertPEM, cert.Fingerprint, renewCSR
}

// genDeviceCSR builds a renewal CSR for deviceID with a FRESH, independent key
// — i.e. a request that does NOT possess the current certificate's key. Used to
// simulate the impersonation attempt the proof-of-possession check rejects.
func genDeviceCSR(t *testing.T, deviceID string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: deviceID}}, k)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
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

// TestRenewCertificate_RejectsKeyMismatch pins the #361 proof-of-possession
// fix: a renewal whose CSR public key differs from the current certificate's
// must be refused. Certificates are public (returned at registration + stored
// in the event log), so without this an attacker who reads a device's cert PEM
// could submit a CSR for a key they control and mint an impersonation cert
// bound to that device id.
func TestRenewCertificate_RejectsKeyMismatch(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewCertificateHandler(st, certAuth, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "renew-mismatch-host")
	certPEM, fingerprint, _ := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, fingerprint)

	// Valid current cert + correct fingerprint, but a CSR for a DIFFERENT key.
	foreignCSR := genDeviceCSR(t, deviceID)
	_, err := h.RenewCertificate(t.Context(), connect.NewRequest(&pm.RenewCertificateRequest{
		CurrentCertificate: certPEM,
		Csr:                foreignCSR,
	}))
	require.Error(t, err, "renewal must reject a CSR whose key differs from the current certificate")
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
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

// TestRenewCertificate_ConcurrentRenewalsSerialize pins the CF6 fix: two or
// more renewals presenting the SAME current certificate concurrently must not
// both succeed. Without serialization both pass the fingerprint check and both
// issue a certificate, leaving a valid-but-untracked live cert whose fingerprint
// never lands in the projection. With the per-device advisory lock, exactly one
// wins and the rest are rejected because the stored fingerprint has advanced —
// and the device's stored fingerprint must equal the single winning cert.
func TestRenewCertificate_ConcurrentRenewalsSerialize(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewCertificateHandler(st, certAuth, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "renew-concurrent-host")
	certPEM, fingerprint, csrPEM := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, fingerprint)

	// Widen the window between the fingerprint check and the append so the race
	// is deterministic: without the per-device advisory lock all goroutines read
	// the same (stale) fingerprint during this sleep and each issues a cert.
	api.SetRenewCertTestHook(func() { time.Sleep(120 * time.Millisecond) })
	t.Cleanup(func() { api.SetRenewCertTestHook(nil) })

	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	resps := make([]*pm.RenewCertificateResponse, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all goroutines together to maximise contention
			resp, err := h.RenewCertificate(t.Context(), connect.NewRequest(&pm.RenewCertificateRequest{
				CurrentCertificate: certPEM,
				Csr:                csrPEM,
			}))
			if err != nil {
				errs[i] = err
				return
			}
			resps[i] = resp.Msg
		}(i)
	}
	close(start)
	wg.Wait()

	var successes int
	var winningFP string
	for i := range n {
		if errs[i] != nil {
			// Losers fail closed: the presented cert is no longer the stored one.
			assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(errs[i]),
				"a losing concurrent renewal must be rejected as unrecognized, got: %v", errs[i])
			continue
		}
		successes++
		fp, ferr := ca.FingerprintFromPEM(resps[i].Certificate)
		require.NoError(t, ferr)
		winningFP = fp
	}
	require.Equal(t, 1, successes, "exactly one concurrent renewal may win against a single current certificate")

	// No orphaned issuance: the stored fingerprint must equal the single winner.
	dev, err := st.Repos().Device.Get(t.Context(), store.GetDeviceKey{ID: deviceID})
	require.NoError(t, err)
	require.NotNil(t, dev.CertFingerprint)
	assert.Equal(t, winningFP, *dev.CertFingerprint, "stored fingerprint must match the single winning cert")
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
