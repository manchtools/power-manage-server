package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/manchtools/power-manage/server/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/enrollment"
	"github.com/manchtools/power-manage/server/internal/store"
)

type enrollmentFixture struct {
	t        *testing.T
	store    *store.Store
	raw      *testdb.DB
	handlers *enrollment.Handlers
	ca       *ca.CA
	now      time.Time
	sealing  []byte

	closeMu sync.Mutex
	closed  []string
}

func newEnrollmentFixture(t *testing.T) *enrollmentFixture {
	t.Helper()
	st, raw := setupSQLite(t)
	now := time.Now().UTC().Truncate(time.Second)
	certPEM, keyPEM := enrollmentTestCA(t, now)
	certAuth, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour, ca.WithClock(func() time.Time { return now }))
	require.NoError(t, err)
	f := &enrollmentFixture{
		t: t, store: st, raw: raw, ca: certAuth, now: now,
		sealing: bytes.Repeat([]byte{0x42}, 32),
	}
	f.handlers = enrollment.New(enrollment.Config{
		Store: st, CA: certAuth,
		Logger: slog.Default(),
		Now:    func() time.Time { return now }, ControlURL: "https://agents.example.test:8443",
		ControlSealingPublicKey: f.sealing,
		CloseStream: func(deviceID string) {
			f.closeMu.Lock()
			defer f.closeMu.Unlock()
			f.closed = append(f.closed, deviceID)
		},
	})
	return f
}

func enrollmentTestCA(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Enrollment Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func enrollmentCSR(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func newEnrollmentIdentity(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return enrollmentCSR(t, key), key
}

func (f *enrollmentFixture) insertToken(plaintext string, oneTime bool, maxUses int32, ownerID *string) string {
	f.t.Helper()
	digest := sha256.Sum256([]byte(plaintext))
	id := newID()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO tokens (
			id, value_hash, name, one_time, max_uses, current_uses,
			created_at, created_by, owner_id
		) VALUES ($1, $2, 'enrollment', $3, $4, 0, $5, 'test', $6)`,
		id, hex.EncodeToString(digest[:]), oneTime, maxUses, f.now, ownerID)
	require.NoError(f.t, err)
	return id
}

func registerRequest(token string, csr []byte, sealingByte byte) *connect.Request[pmv1.RegisterRequest] {
	return connect.NewRequest(&pmv1.RegisterRequest{
		Token: token, Hostname: "host-1", AgentVersion: "v1", Csr: csr,
		AgentSealingPublicKey: bytes.Repeat([]byte{sealingByte}, 32),
	})
}

func TestEnrollment_ValidatesBeforeCredentialUse(t *testing.T) {
	f := newEnrollmentFixture(t)
	_, err := f.handlers.Register(context.Background(), connect.NewRequest(&pmv1.RegisterRequest{Token: "unknown"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	token := "still-usable"
	f.insertToken(token, true, 1, nil)
	_, err = f.handlers.Register(context.Background(), registerRequest(token, []byte("not a CSR"), 1))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	var uses int32
	require.NoError(t, f.raw.QueryRow(context.Background(), `SELECT current_uses FROM tokens WHERE value_hash = $1`,
		hex.EncodeToString(sha256Digest(token))).Scan(&uses))
	assert.Zero(t, uses, "an invalid CSR must not consume enrollment authority")
}

func TestEnrollment_RegisterCommitsOneAuditedDevice(t *testing.T) {
	f := newEnrollmentFixture(t)
	ownerID := newID()
	_, err := f.raw.Exec(context.Background(), `
		INSERT INTO users (id, email, display_name, linux_username, linux_uid, created_at)
		VALUES ($1, 'owner@example.test', 'Owner', 'owner', 200001, $2)`, ownerID, f.now)
	require.NoError(t, err)
	token := "one-use-token"
	tokenID := f.insertToken(token, true, 1, &ownerID)
	csr, _ := newEnrollmentIdentity(t)

	resp, err := f.handlers.Register(context.Background(), registerRequest(token, csr, 0x24))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.DeviceId)
	deviceID := resp.Msg.DeviceId.Value
	assert.Equal(t, "https://agents.example.test:8443", resp.Msg.ControlUrl)
	assert.Equal(t, f.sealing, resp.Msg.ControlSealingPublicKey)
	assert.NotEmpty(t, resp.Msg.Certificate)
	assert.NotEmpty(t, resp.Msg.CaCert)

	var uses int32
	var storedTokenID, assignedUser string
	var storedSealing []byte
	require.NoError(t, f.raw.QueryRow(context.Background(), `
		SELECT d.registration_token_id, d.agent_sealing_public_key, t.current_uses
		FROM devices d JOIN tokens t ON t.id = d.registration_token_id
		WHERE d.id = $1`, deviceID).Scan(&storedTokenID, &storedSealing, &uses))
	assert.Equal(t, tokenID, storedTokenID)
	assert.Equal(t, bytes.Repeat([]byte{0x24}, 32), storedSealing)
	assert.Equal(t, int32(1), uses)
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT user_id FROM device_assigned_users WHERE device_id = $1`, deviceID).Scan(&assignedUser))
	assert.Equal(t, ownerID, assignedUser)

	op, err := latestOperationFor(t, f.store, f.raw, powermanagev1connect.ControlServiceRegisterProcedure)
	require.NoError(t, err)
	effects, err := f.store.ListAuditEffects(context.Background(), op.OperationID)
	require.NoError(t, err)
	assert.Len(t, effects, 3)

	_, err = f.handlers.Register(context.Background(), registerRequest(token, csr, 0x24))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	var devices int
	require.NoError(t, f.raw.QueryRow(context.Background(), `SELECT COUNT(*) FROM devices`).Scan(&devices))
	assert.Equal(t, 1, devices)
}

func TestEnrollment_SingleUseTokenWinsExactlyOnce(t *testing.T) {
	f := newEnrollmentFixture(t)
	token := "raced-one-use-token"
	f.insertToken(token, true, 1, nil)
	csr, _ := newEnrollmentIdentity(t)

	const callers = 12
	var succeeded atomic.Int32
	var denied atomic.Int32
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.handlers.Register(context.Background(), registerRequest(token, csr, 0x33))
			switch connect.CodeOf(err) {
			case connect.CodeUnknown:
				if err == nil {
					succeeded.Add(1)
				}
			case connect.CodePermissionDenied:
				denied.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), succeeded.Load())
	assert.Equal(t, int32(callers-1), denied.Load())
	var uses, devices int32
	require.NoError(t, f.raw.QueryRow(context.Background(), `SELECT current_uses FROM tokens WHERE name = 'enrollment'`).Scan(&uses))
	require.NoError(t, f.raw.QueryRow(context.Background(), `SELECT COUNT(*) FROM devices`).Scan(&devices))
	assert.Equal(t, int32(1), uses)
	assert.Equal(t, int32(1), devices)
}

func TestEnrollment_RenewalReplacesRevokesAndCloses(t *testing.T) {
	f := newEnrollmentFixture(t)
	token := "renew-token"
	f.insertToken(token, true, 1, nil)
	csr, identity := newEnrollmentIdentity(t)
	registered, err := f.handlers.Register(context.Background(), registerRequest(token, csr, 0x55))
	require.NoError(t, err)
	deviceID := registered.Msg.DeviceId.Value
	oldFingerprint, err := ca.FingerprintFromPEM(registered.Msg.Certificate)
	require.NoError(t, err)

	renewed, err := f.handlers.RenewCertificate(context.Background(), connect.NewRequest(&pmv1.RenewCertificateRequest{
		Csr: enrollmentCSR(t, identity), CurrentCertificate: registered.Msg.Certificate,
	}))
	require.NoError(t, err)
	newFingerprint, err := ca.FingerprintFromPEM(renewed.Msg.Certificate)
	require.NoError(t, err)
	assert.NotEqual(t, oldFingerprint, newFingerprint)
	assert.True(t, renewed.Msg.NotAfter.AsTime().Equal(f.now.Add(24*time.Hour)))

	var storedFingerprint string
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT cert_fingerprint FROM devices WHERE id = $1`, deviceID).Scan(&storedFingerprint))
	assert.Equal(t, newFingerprint, storedFingerprint)
	var reason string
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT reason FROM revoked_certificates WHERE fingerprint = $1`, oldFingerprint).Scan(&reason))
	assert.Equal(t, "superseded by renewal", reason)
	f.closeMu.Lock()
	assert.Equal(t, []string{deviceID}, f.closed)
	f.closeMu.Unlock()

	_, err = f.handlers.RenewCertificate(context.Background(), connect.NewRequest(&pmv1.RenewCertificateRequest{
		Csr: enrollmentCSR(t, identity), CurrentCertificate: registered.Msg.Certificate,
	}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	var revocations int
	require.NoError(t, f.raw.QueryRow(context.Background(), `SELECT COUNT(*) FROM revoked_certificates`).Scan(&revocations))
	assert.Equal(t, 1, revocations)

	op, err := latestOperationFor(t, f.store, f.raw, powermanagev1connect.ControlServiceRenewCertificateProcedure)
	require.NoError(t, err)
	assert.Equal(t, string(store.ClassRejectedAuthentication), op.OperationClass)
}

func TestEnrollment_RenewalRequiresSameIdentityKey(t *testing.T) {
	f := newEnrollmentFixture(t)
	token := "key-binding-token"
	f.insertToken(token, true, 1, nil)
	csr, _ := newEnrollmentIdentity(t)
	registered, err := f.handlers.Register(context.Background(), registerRequest(token, csr, 0x66))
	require.NoError(t, err)
	otherCSR, _ := newEnrollmentIdentity(t)

	_, err = f.handlers.RenewCertificate(context.Background(), connect.NewRequest(&pmv1.RenewCertificateRequest{
		Csr: otherCSR, CurrentCertificate: registered.Msg.Certificate,
	}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	f.closeMu.Lock()
	assert.Empty(t, f.closed)
	f.closeMu.Unlock()
	var revocations int
	require.NoError(t, f.raw.QueryRow(context.Background(), `SELECT COUNT(*) FROM revoked_certificates`).Scan(&revocations))
	assert.Zero(t, revocations)
}

func TestEnrollment_MountsExactSurface(t *testing.T) {
	f := newEnrollmentFixture(t)
	assert.ElementsMatch(t, enrollment.MutationProcedures(), f.handlers.Mount(http.NewServeMux()))
	assert.Equal(t, []string{
		powermanagev1connect.ControlServiceRegisterProcedure,
		powermanagev1connect.ControlServiceRenewCertificateProcedure,
	}, enrollment.MutationProcedures())
}

func sha256Digest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}
