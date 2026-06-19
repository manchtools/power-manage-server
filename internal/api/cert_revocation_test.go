package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/crl"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func testCRLStore(t *testing.T) *crl.Store {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return crl.NewStore(rdb)
}

// TestRenewCertificate_RevokesSupersededCert pins that a successful renewal puts
// the OLD cert's fingerprint on the CRL, so the superseded cert stops working at
// the gateway instead of staying valid for its full year (audit #6).
func TestRenewCertificate_RevokesSupersededCert(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewCertificateHandler(st, certAuth, slog.Default())

	crlStore := testCRLStore(t)
	h.SetCRLStore(crlStore)

	deviceID := testutil.CreateTestDevice(t, st, "renew-revoke-host")
	certPEM, oldFingerprint, csrPEM := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, oldFingerprint)

	_, err := h.RenewCertificate(t.Context(), connect.NewRequest(&pm.RenewCertificateRequest{
		CurrentCertificate: certPEM,
		Csr:                csrPEM,
	}))
	require.NoError(t, err)

	active, err := crlStore.LoadActive(t.Context())
	require.NoError(t, err)
	assert.Contains(t, active, oldFingerprint, "the superseded cert must be revoked after renewal")
}

// TestDeleteDevice_RevokesCert pins that deleting a device revokes its current
// cert — otherwise the deleted device's still-valid cert keeps connecting at the
// gateway until its 1-year expiry (audit #6).
func TestDeleteDevice_RevokesCert(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewDeviceHandler(st, enc, slog.Default(), api.NoOpSigner{})

	crlStore := testCRLStore(t)
	h.SetCRLStore(crlStore)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "delete-revoke-host")
	_, fingerprint, _ := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, fingerprint)

	_, err := h.DeleteDevice(testutil.AdminContext(adminID), connect.NewRequest(&pm.DeleteDeviceRequest{
		Id: deviceID,
	}))
	require.NoError(t, err)

	active, err := crlStore.LoadActive(t.Context())
	require.NoError(t, err)
	assert.Contains(t, active, fingerprint, "a deleted device's cert must be revoked")
}
