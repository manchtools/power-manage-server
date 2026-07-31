package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 41 criterion 6 / R4, at the HANDLER boundary.
//
// internal/store/revocation_test.go already pins that AppendEventAndRevoke is
// atomic. That says nothing about whether RenewCertificate and DeleteDevice
// reach it, or reach it with the right arguments — and the predecessor of this
// file (internal/api/cert_revocation_test.go, deleted in 240af44 along with the
// Valkey CRL it asserted against) was the only thing that did. Nothing replaced
// it, so between then and now a renewal that revoked the WRONG fingerprint —
// the freshly issued one instead of the superseded one — would have left the
// old certificate live and every test green.
//
// These drive the real RPCs and read the answer back out of the store the
// handshake gate itself queries (store.RevocationChecker), not out of the
// handler's response.

// isRevoked answers the same question the mTLS handshake asks, through the same
// checker, so these tests cannot pass against a row the gate would not see.
func isRevoked(t *testing.T, st *store.Store, fingerprint string) bool {
	t.Helper()
	revoked, err := store.NewRevocationChecker(st).IsRevoked(context.Background(), fingerprint)
	require.NoError(t, err)
	return revoked
}

// breakRevocationWrites makes every INSERT into revoked_certificates fail while
// leaving the events table untouched — the R4 fault, injected at the only place
// it can come from in production (the database refusing the revocation write).
//
// The predicate is unsatisfiable rather than literally false: fingerprint is the
// NOT NULL primary key, so no row a handler could construct can pass it. NOT
// VALID skips the (empty) existing rows, so the ALTER itself cannot fail for an
// unrelated reason and silently leave the fault uninjected.
func breakRevocationWrites(t *testing.T, st *store.Store) {
	t.Helper()
	_, err := st.TestingPool().Exec(context.Background(),
		`ALTER TABLE revoked_certificates
		   ADD CONSTRAINT test_revocation_writes_fail CHECK (fingerprint IS NULL) NOT VALID`)
	require.NoError(t, err, "the fault must actually be injected, or the rollback assertions below pass vacuously")
}

// A renewal revokes the certificate it SUPERSEDES — and not the one it just
// issued. Revoking the new fingerprint would look identical from the handler's
// side (a row lands, the RPC succeeds, the agent gets a certificate) while
// inverting the outcome completely: the superseded certificate stays admitted
// and the agent's brand-new one is refused at its next handshake. The old-vs-new
// distinction is the whole property, so both halves are asserted.
func TestRenewCertificate_RevokesTheSupersededFingerprintNotTheNewOne(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewCertificateHandler(st, certAuth, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "renew-revoke-host")
	certPEM, oldFingerprint, csrPEM := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, oldFingerprint)

	require.False(t, isRevoked(t, st, oldFingerprint), "not revoked before the renewal")

	resp, err := h.RenewCertificate(t.Context(), connect.NewRequest(&pm.RenewCertificateRequest{
		CurrentCertificate: certPEM,
		Csr:                csrPEM,
	}))
	require.NoError(t, err)

	newFingerprint, err := ca.FingerprintFromPEM(resp.Msg.Certificate)
	require.NoError(t, err)
	require.NotEqual(t, oldFingerprint, newFingerprint,
		"the renewal must issue a different certificate, or old-vs-new below is not a distinction")

	assert.True(t, isRevoked(t, st, oldFingerprint),
		"the superseded certificate stays cryptographically valid for its full remaining lifetime; if renewal does "+
			"not revoke it, two certificates authenticate this device")
	assert.False(t, isRevoked(t, st, newFingerprint),
		"the certificate the agent was just handed must NOT be revoked — revoking it locks the device out at its "+
			"next handshake while leaving the superseded one admitted")
}

// Deleting a device revokes its certificate. Without this the credential
// outlives the device it identifies, for up to its full remaining lifetime.
func TestDeleteDevice_RevokesTheDeletedDevicesCertificate(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewDeviceHandler(st, nil, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "delete-revoke-host")
	_, fingerprint, _ := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, fingerprint)

	require.False(t, isRevoked(t, st, fingerprint), "not revoked before the deletion")

	_, err := h.DeleteDevice(testutil.AdminContext(adminID), connect.NewRequest(&pm.DeleteDeviceRequest{
		Id: deviceID,
	}))
	require.NoError(t, err)

	assert.True(t, isRevoked(t, st, fingerprint),
		"a deleted device's certificate must be revoked — the projection row is gone, so nothing else can name "+
			"this fingerprint afterwards")
}

// R4 at the renewal handler: when the revocation write fails, the renewal it
// belongs to must not survive it.
//
// The predecessor ordering appended DeviceCertRenewed, let it commit, and then
// revoked best-effort — so this exact fault produced a device whose stored
// fingerprint had advanced while the superseded certificate was never listed:
// the old certificate admitted indefinitely, and no error anywhere. The
// assertions therefore go past "the RPC failed" to the two pieces of durable
// state that ordering corrupted.
func TestRenewCertificate_RevocationWriteFailureRollsBackTheRenewal(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewCertificateHandler(st, certAuth, slog.Default())

	deviceID := testutil.CreateTestDevice(t, st, "renew-rollback-host")
	certPEM, oldFingerprint, csrPEM := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, oldFingerprint)

	// One DeviceCertRenewed exists already: the seeding append above.
	before := countEventsByTypeForActor(t, st, "DeviceCertRenewed", deviceID)
	require.Equal(t, 1, before, "the fixture must have seeded exactly one renewal event")

	breakRevocationWrites(t, st)

	_, err := h.RenewCertificate(t.Context(), connect.NewRequest(&pm.RenewCertificateRequest{
		CurrentCertificate: certPEM,
		Csr:                csrPEM,
	}))
	require.Error(t, err, "a renewal whose revocation cannot be written must fail, not succeed quietly")
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))

	assert.Equal(t, before, countEventsByTypeForActor(t, st, "DeviceCertRenewed", deviceID),
		"the renewal event must NOT survive the failed revocation — that is the window criterion 6 closes")

	dev, err := st.Repos().Device.Get(t.Context(), store.GetDeviceKey{ID: deviceID})
	require.NoError(t, err)
	require.NotNil(t, dev.CertFingerprint)
	assert.Equal(t, oldFingerprint, *dev.CertFingerprint,
		"the stored fingerprint must not have advanced: a device pinned to a certificate whose predecessor is "+
			"still admitted is exactly the best-effort ordering's failure")

	assert.False(t, isRevoked(t, st, oldFingerprint),
		"nothing was revoked — the point is that the renewal did not happen either")
}

// R4 at the deletion handler. Same fault, different durable consequence: the
// DeviceDeleted projection removes the row, so a delete that commits without its
// revocation destroys the only record of which fingerprint to revoke. There is
// no recovering from that afterwards, which is why the deletion has to roll back
// with it.
func TestDeleteDevice_RevocationWriteFailureRollsBackTheDeletion(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewDeviceHandler(st, nil, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	deviceID := testutil.CreateTestDevice(t, st, "delete-rollback-host")
	_, fingerprint, _ := issueTestDeviceCert(t, certAuth, deviceID)
	setDeviceCertFingerprint(t, st, deviceID, fingerprint)

	before := countEventsByTypeForActor(t, st, "DeviceDeleted", adminID)

	breakRevocationWrites(t, st)

	_, err := h.DeleteDevice(testutil.AdminContext(adminID), connect.NewRequest(&pm.DeleteDeviceRequest{
		Id: deviceID,
	}))
	require.Error(t, err, "a deletion whose revocation cannot be written must fail, not report success")
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))

	// Asserted against the EVENT, not only the projection. A DeviceDeleted that
	// commits without its revocation is durable and will be replayed into the
	// projection on any rebuild — so a projection that still shows the device
	// (because the post-commit projector never ran) is not evidence the
	// deletion rolled back. The event count is.
	assert.Equal(t, before, countEventsByTypeForActor(t, st, "DeviceDeleted", adminID),
		"the deletion event must NOT survive the failed revocation — a committed DeviceDeleted destroys the only "+
			"record of which fingerprint to revoke")

	dev, err := st.Repos().Device.Get(t.Context(), store.GetDeviceKey{ID: deviceID})
	require.False(t, store.IsNotFound(err),
		"the device must survive the failed deletion — otherwise its fingerprint is unrecoverable and the "+
			"certificate is admitted forever")
	require.NoError(t, err)
	assert.False(t, dev.IsDeleted)
	require.NotNil(t, dev.CertFingerprint)
	assert.Equal(t, fingerprint, *dev.CertFingerprint)
}
