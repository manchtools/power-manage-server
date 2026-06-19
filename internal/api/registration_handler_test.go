package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// newTestCA generates a self-signed CA for testing.
func newTestCA(t *testing.T) *ca.CA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"power-manage-test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	testCA, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	require.NoError(t, err)
	return testCA
}

// generateCSR creates a PEM-encoded CSR for testing.
func generateCSR(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-device",
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// generateCSRWithTemplate builds a CSR after letting the caller stamp fields
// (CN, SANs) onto the template — used to prove the issued identity comes from
// the server, not the CSR, and that a SAN-bearing CSR is refused.
func generateCSRWithTemplate(t *testing.T, modify func(*x509.CertificateRequest)) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "default-cn"}}
	modify(tmpl)
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestRegister_IssuedCertBindsServerDeviceIDNotCSRCN drives the real handler and
// pins that the issued cert's CN is the SERVER-minted device id, never the
// attacker-controlled CSR Subject, and that no CSR SAN leaks into the cert.
func TestRegister_IssuedCertBindsServerDeviceIDNotCSRCN(t *testing.T) {
	st := testutil.SetupPostgres(t)
	testCA := newTestCA(t)
	h := api.NewRegistrationHandler(st, testCA, "https://gateway.test:8080", slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	_, tokenValue := createTestTokenWithValue(t, st, adminID, false)

	csr := generateCSRWithTemplate(t, func(c *x509.CertificateRequest) {
		c.Subject.CommonName = "victim-device-id" // attacker-chosen
	})
	resp, err := h.Register(context.Background(), connect.NewRequest(&pm.RegisterRequest{
		Token: tokenValue, Hostname: "h", AgentVersion: "1.0.0", Csr: csr,
	}))
	require.NoError(t, err)

	block, _ := pem.Decode(resp.Msg.Certificate)
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, resp.Msg.DeviceId.Value, parsed.Subject.CommonName,
		"issued CN must be the server-minted device id")
	assert.NotEqual(t, "victim-device-id", parsed.Subject.CommonName,
		"the attacker-controlled CSR CN must never become the cert identity")
	assert.Empty(t, parsed.DNSNames)
	assert.Empty(t, parsed.IPAddresses)
	assert.Empty(t, parsed.EmailAddresses)
}

// TestRegister_SANBearingCSRRejected drives the real handler with a SAN-bearing
// CSR and asserts no certificate is issued (the CA refuses any caller-supplied
// SAN, so an enrolling agent cannot mint a non-agent peer-class identity).
func TestRegister_SANBearingCSRRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	testCA := newTestCA(t)
	h := api.NewRegistrationHandler(st, testCA, "https://gateway.test:8080", slog.Default())
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	_, tokenValue := createTestTokenWithValue(t, st, adminID, false)

	csr := generateCSRWithTemplate(t, func(c *x509.CertificateRequest) {
		c.DNSNames = []string{"control-server.example.com"}
	})
	_, err := h.Register(context.Background(), connect.NewRequest(&pm.RegisterRequest{
		Token: tokenValue, Hostname: "h", AgentVersion: "1.0.0", Csr: csr,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err),
		"a SAN-bearing CSR must not yield a certificate (CA refuses it -> handler maps to Internal)")
}

// createTestTokenWithValue creates a registration token and returns both the
// token ID and the plaintext token value (needed for registration).
func createTestTokenWithValue(t *testing.T, st *store.Store, actorID string, oneTime bool) (tokenID, tokenValue string) {
	t.Helper()
	ctx := context.Background()
	id := testutil.NewID()

	value := "test-token-" + testutil.NewID()
	hash := sha256.Sum256([]byte(value))
	hashHex := hex.EncodeToString(hash[:])

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   id,
		EventType:  "TokenCreated",
		Data: map[string]any{
			"name":       "test-token",
			"value_hash": hashHex,
			"one_time":   oneTime,
			"max_uses":   0,
			"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	require.NoError(t, err)

	return id, value
}

func TestRegister_ValidToken(t *testing.T) {
	st := testutil.SetupPostgres(t)
	testCA := newTestCA(t)
	h := api.NewRegistrationHandler(st, testCA, "https://gateway.test:8080", slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	_, tokenValue := createTestTokenWithValue(t, st, adminID, false)

	csr := generateCSR(t)

	resp, err := h.Register(context.Background(), connect.NewRequest(&pm.RegisterRequest{
		Token:        tokenValue,
		Hostname:     "test-device-01",
		AgentVersion: "1.0.0",
		Csr:          csr,
	}))
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Msg.DeviceId.Value)
	assert.NotEmpty(t, resp.Msg.Certificate)
	assert.NotEmpty(t, resp.Msg.CaCert)
	assert.Equal(t, "https://gateway.test:8080", resp.Msg.GatewayUrl)

	// Verify device projection exists
	device, err := st.Queries().GetDeviceByID(context.Background(), db.GetDeviceByIDParams{
		ID: resp.Msg.DeviceId.Value,
	})
	require.NoError(t, err)
	assert.Equal(t, "test-device-01", device.Hostname)
}

func TestRegister_OneTimeTokenDisabledAfterUse(t *testing.T) {
	st := testutil.SetupPostgres(t)
	testCA := newTestCA(t)
	h := api.NewRegistrationHandler(st, testCA, "https://gateway.test:8080", slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	_, tokenValue := createTestTokenWithValue(t, st, adminID, true)

	csr := generateCSR(t)

	// First registration should succeed
	_, err := h.Register(context.Background(), connect.NewRequest(&pm.RegisterRequest{
		Token:        tokenValue,
		Hostname:     "device-one",
		AgentVersion: "1.0.0",
		Csr:          csr,
	}))
	require.NoError(t, err)

	// Second registration with same one-time token should fail
	csr2 := generateCSR(t)
	_, err = h.Register(context.Background(), connect.NewRequest(&pm.RegisterRequest{
		Token:        tokenValue,
		Hostname:     "device-two",
		AgentVersion: "1.0.0",
		Csr:          csr2,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestRegister_DisabledTokenFails(t *testing.T) {
	st := testutil.SetupPostgres(t)
	testCA := newTestCA(t)
	h := api.NewRegistrationHandler(st, testCA, "https://gateway.test:8080", slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	tokenID, tokenValue := createTestTokenWithValue(t, st, adminID, false)

	// Disable the token
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "token",
		StreamID:   tokenID,
		EventType:  "TokenDisabled",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    adminID,
	})
	require.NoError(t, err)

	csr := generateCSR(t)
	_, err = h.Register(context.Background(), connect.NewRequest(&pm.RegisterRequest{
		Token:        tokenValue,
		Hostname:     "blocked-device",
		AgentVersion: "1.0.0",
		Csr:          csr,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestRegister_InvalidTokenFails(t *testing.T) {
	st := testutil.SetupPostgres(t)
	testCA := newTestCA(t)
	h := api.NewRegistrationHandler(st, testCA, "https://gateway.test:8080", slog.Default())

	csr := generateCSR(t)
	_, err := h.Register(context.Background(), connect.NewRequest(&pm.RegisterRequest{
		Token:        "completely-invalid-token",
		Hostname:     "rogue-device",
		AgentVersion: "1.0.0",
		Csr:          csr,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestRegister_MissingCSRFails(t *testing.T) {
	st := testutil.SetupPostgres(t)
	testCA := newTestCA(t)
	h := api.NewRegistrationHandler(st, testCA, "https://gateway.test:8080", slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	_, tokenValue := createTestTokenWithValue(t, st, adminID, false)

	_, err := h.Register(context.Background(), connect.NewRequest(&pm.RegisterRequest{
		Token:        tokenValue,
		Hostname:     "no-csr-device",
		AgentVersion: "1.0.0",
		Csr:          nil,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestRegister_ReusableTokenAllowsMultipleUses(t *testing.T) {
	st := testutil.SetupPostgres(t)
	testCA := newTestCA(t)
	h := api.NewRegistrationHandler(st, testCA, "https://gateway.test:8080", slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	_, tokenValue := createTestTokenWithValue(t, st, adminID, false)

	for i := 0; i < 3; i++ {
		csr := generateCSR(t)
		resp, err := h.Register(context.Background(), connect.NewRequest(&pm.RegisterRequest{
			Token:        tokenValue,
			Hostname:     "multi-device",
			AgentVersion: "1.0.0",
			Csr:          csr,
		}))
		require.NoError(t, err, "registration %d should succeed", i+1)
		assert.NotEmpty(t, resp.Msg.DeviceId.Value)
	}
}

func TestRegister_ExpiredTokenFails(t *testing.T) {
	st := testutil.SetupPostgres(t)
	testCA := newTestCA(t)
	h := api.NewRegistrationHandler(st, testCA, "https://gateway.test:8080", slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := context.Background()
	id := testutil.NewID()

	value := "expired-token-" + testutil.NewID()
	hash := sha256.Sum256([]byte(value))
	hashHex := hex.EncodeToString(hash[:])

	// Create token that already expired
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   id,
		EventType:  "TokenCreated",
		Data: map[string]any{
			"name":       "expired-token",
			"value_hash": hashHex,
			"one_time":   false,
			"max_uses":   0,
			"expires_at": time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	csr := generateCSR(t)
	_, err = h.Register(ctx, connect.NewRequest(&pm.RegisterRequest{
		Token:        value,
		Hostname:     "expired-device",
		AgentVersion: "1.0.0",
		Csr:          csr,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}
