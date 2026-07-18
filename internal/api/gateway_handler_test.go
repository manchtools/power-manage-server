package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

const testEnrollToken = "test-gateway-enroll-token-value"

// testGatewayURL is the CONTROL_GATEWAY_URL a test handler is built with;
// testGatewayHost is its authoritative host — the DNS SAN the handler stamps
// and the hostname an enroll request must declare (spec 31 D1).
const (
	testGatewayURL  = "https://gw1.example.com"
	testGatewayHost = "gw1.example.com"
)

// genGatewayCSR builds a plain PKCS#10 CSR (no SAN) and returns the PEM plus the
// key, so a renewal CSR can reuse the key for proof-of-possession.
func genGatewayCSR(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "unused"}}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func csrForGatewayKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "unused"}}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// enrollTestGateway enrolls a gateway and returns its gateway_id (the cert CN)
// and the issued cert fingerprint (from the projection).
func enrollTestGateway(t *testing.T, st *store.Store, certAuth *ca.CA) (gatewayID, fingerprint string) {
	t.Helper()
	h := api.NewGatewayAuthHandler(st, certAuth, testEnrollToken, testGatewayURL, nil, slog.Default())
	csr, _ := genGatewayCSR(t)
	resp, err := h.EnrollGateway(t.Context(), connect.NewRequest(&pm.EnrollGatewayRequest{
		Token:    testEnrollToken,
		Hostname: testGatewayHost,
		Csr:      csr,
	}))
	require.NoError(t, err)
	id, err := ca.DeviceIDFromPEM(resp.Msg.Certificate)
	require.NoError(t, err)
	row, err := st.Queries().GetGatewayFingerprint(t.Context(), id)
	require.NoError(t, err)
	return id, row.Fingerprint
}

// --- EnrollGateway ---------------------------------------------------------

func TestEnrollGateway_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewGatewayAuthHandler(st, certAuth, testEnrollToken, testGatewayURL, nil, slog.Default())

	csr, _ := genGatewayCSR(t)
	resp, err := h.EnrollGateway(t.Context(), connect.NewRequest(&pm.EnrollGatewayRequest{
		Token:    testEnrollToken,
		Hostname: "gw1.example.com",
		Csr:      csr,
	}))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Msg.CaCert)
	require.NotEmpty(t, resp.Msg.Certificate)

	// The gateway_id is the cert CN — the single source of truth (AC1). Parse it
	// and assert it is a ULID and the cert is the gateway peer class.
	block, _ := pem.Decode(resp.Msg.Certificate)
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	_, err = ulid.Parse(parsed.Subject.CommonName)
	require.NoError(t, err, "cert CN must be a ULID gateway_id")
	class, err := mtls.PeerClassFromCert(parsed)
	require.NoError(t, err)
	assert.Equal(t, mtls.PeerClassGateway, class)

	// GatewayEnrolled projected: the fingerprint↦gateway_id mapping exists.
	row, err := st.Queries().GetGatewayFingerprint(t.Context(), parsed.Subject.CommonName)
	require.NoError(t, err)
	assert.NotEmpty(t, row.Fingerprint)
	assert.Nil(t, row.RevokedAt, "a freshly enrolled gateway is not revoked")
}

// TestEnrollGateway_HostnameMustMatchAuthoritative pins spec 31 D1: the DNS SAN
// on a gateway cert is control-authoritative, never the enrollee's claim. A
// valid-token enroll whose declared hostname is anything but this deployment's
// authoritative gateway host (host of CONTROL_GATEWAY_URL) is rejected — an
// unlisted name, an IP literal, mixed case, or a trailing dot — and no gateway
// is enrolled. The matching case is issued with exactly the authoritative host
// as its sole DNS SAN, proving the server stamps its own name rather than
// copying the request.
func TestEnrollGateway_HostnameMustMatchAuthoritative(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewGatewayAuthHandler(st, certAuth, testEnrollToken, testGatewayURL, nil, slog.Default())

	// Every one of these is NOT the authoritative host "gw1.example.com".
	for _, bad := range []string{
		"evil.example.com", // unlisted name — the core attack
		"10.0.0.1",         // IP literal
		"GW1.example.com",  // mixed case (DNS is case-insensitive; we are not)
		"gw1.example.com.", // trailing dot
	} {
		t.Run("rejected/"+bad, func(t *testing.T) {
			csr, _ := genGatewayCSR(t)
			_, err := h.EnrollGateway(t.Context(), connect.NewRequest(&pm.EnrollGatewayRequest{
				Token:    testEnrollToken,
				Hostname: bad,
				Csr:      csr,
			}))
			require.Error(t, err)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
				"a hostname that is not the authoritative gateway host must be InvalidArgument")
		})
	}

	// No gateway was enrolled by any rejected attempt.
	list, err := st.Queries().ListGateways(t.Context())
	require.NoError(t, err)
	assert.Empty(t, list, "no gateway may be enrolled from a mismatched-hostname request")

	// The matching hostname is issued — with the authoritative host as its ONLY
	// DNS SAN.
	csr, _ := genGatewayCSR(t)
	resp, err := h.EnrollGateway(t.Context(), connect.NewRequest(&pm.EnrollGatewayRequest{
		Token:    testEnrollToken,
		Hostname: testGatewayHost,
		Csr:      csr,
	}))
	require.NoError(t, err)
	block, _ := pem.Decode(resp.Msg.Certificate)
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, []string{testGatewayHost}, parsed.DNSNames,
		"the issued cert's DNS SAN must be the control-authoritative host, verbatim")
}

// TestNewGatewayAuthHandler_RejectsIPGatewayURL pins the config-side half of D1:
// a CONTROL_GATEWAY_URL whose host is an IP literal or a non-canonical DNS name
// (wildcard, underscore, trailing dot) cannot back a DNS-SAN mTLS identity, so
// the handler refuses to construct (fail fast at boot rather than issue certs
// agents cannot verify — or a wildcard SAN that would broaden the identity).
func TestNewGatewayAuthHandler_RejectsIPGatewayURL(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	for name, url := range map[string]string{
		"IP literal":       "https://10.0.0.1:8443",
		"wildcard host":    "https://*.example.com",
		"underscore label": "https://gw_1.example.com",
		"trailing dot":     "https://gw.example.com.",
		"leading hyphen":   "https://-gw.example.com",
	} {
		assert.Panics(t, func() {
			api.NewGatewayAuthHandler(st, certAuth, testEnrollToken, url, nil, slog.Default())
		}, "%s in the gateway URL host must panic (no valid DNS SAN)", name)
	}
}

func TestEnrollGateway_WrongTokenRejectedWithProbeLog(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := api.NewGatewayAuthHandler(st, certAuth, testEnrollToken, testGatewayURL, nil, logger)

	csr, _ := genGatewayCSR(t)
	_, err := h.EnrollGateway(t.Context(), connect.NewRequest(&pm.EnrollGatewayRequest{
		Token:    "wrong-token-guess",
		Hostname: "attacker-host",
		Csr:      csr,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// AC3 observability backstop: a WARN carrying the hostname so probing is
	// alertable — but NO token material, not even a hash prefix (D3): neither the
	// raw token nor any digest of it may be logged.
	logged := buf.String()
	assert.NotContains(t, logged, "token_hash_prefix", "no token digest may be logged (D3)")
	assert.Contains(t, logged, "attacker-host")
	assert.NotContains(t, logged, "wrong-token-guess", "the raw token must never be logged")

	// No gateway was enrolled.
	list, err := st.Queries().ListGateways(t.Context())
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestEnrollGateway_CSRWithSANRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	h := api.NewGatewayAuthHandler(st, certAuth, testEnrollToken, testGatewayURL, nil, slog.Default())

	// A CSR requesting the control peer class — must be refused so an enrolling
	// gateway cannot mint a non-gateway identity (AC2).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	u, _ := url.Parse("spiffe://power-manage/control")
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}, URIs: []*url.URL{u}}, key)
	require.NoError(t, err)
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	_, err = h.EnrollGateway(t.Context(), connect.NewRequest(&pm.EnrollGatewayRequest{
		Token:    testEnrollToken,
		Hostname: testGatewayHost,
		Csr:      csr,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestEnrollGateway_RateLimited(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	limiter := auth.NewRateLimiter(5, time.Minute)
	h := api.NewGatewayAuthHandler(st, certAuth, testEnrollToken, testGatewayURL, limiter, slog.Default())

	csr, _ := genGatewayCSR(t)
	// The first 5 attempts (same empty client-IP bucket) pass the limiter.
	for i := 0; i < 5; i++ {
		_, err := h.EnrollGateway(t.Context(), connect.NewRequest(&pm.EnrollGatewayRequest{
			Token:    testEnrollToken,
			Hostname: testGatewayHost,
			Csr:      csr,
		}))
		require.NoError(t, err, "attempt %d should pass", i+1)
	}
	// The 6th is rejected ResourceExhausted (AC4).
	_, err := h.EnrollGateway(t.Context(), connect.NewRequest(&pm.EnrollGatewayRequest{
		Token:    testEnrollToken,
		Hostname: testGatewayHost,
		Csr:      csr,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
}

// --- RevokeGatewayCertificate / GetCRL / ListGateways ----------------------

func TestRevokeGatewayCertificate_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	gatewayID, fingerprint := enrollTestGateway(t, st, certAuth)

	crlStore := testCRLStore(t)
	h := api.NewGatewayHandler(st, slog.Default())
	h.SetCRLStore(crlStore)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	_, err := h.RevokeGatewayCertificate(testutil.AdminContext(adminID), connect.NewRequest(&pm.RevokeGatewayCertificateRequest{
		GatewayId: gatewayID,
	}))
	require.NoError(t, err)

	// The fingerprint is on the CRL and the projection is marked revoked.
	active, err := crlStore.LoadActive(t.Context())
	require.NoError(t, err)
	assert.Contains(t, active, fingerprint)

	row, err := st.Queries().GetGatewayFingerprint(t.Context(), gatewayID)
	require.NoError(t, err)
	require.NotNil(t, row.RevokedAt, "GatewayRevoked must set revoked_at")
}

func TestRevokeGatewayCertificate_Idempotent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	gatewayID, _ := enrollTestGateway(t, st, certAuth)

	h := api.NewGatewayHandler(st, slog.Default())
	h.SetCRLStore(testCRLStore(t))
	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	req := connect.NewRequest(&pm.RevokeGatewayCertificateRequest{GatewayId: gatewayID})

	_, err := h.RevokeGatewayCertificate(ctx, req)
	require.NoError(t, err)
	// A second revoke is a no-op success — it must NOT emit a duplicate audit event.
	_, err = h.RevokeGatewayCertificate(ctx, req)
	require.NoError(t, err)

	events, err := st.LoadStream(t.Context(), "gateway", gatewayID)
	require.NoError(t, err)
	revoked := 0
	for _, e := range events {
		if e.EventType == "GatewayRevoked" {
			revoked++
		}
	}
	assert.Equal(t, 1, revoked, "re-revoking must not emit a duplicate GatewayRevoked event")
}

func TestRevokeGatewayCertificate_UnknownGateway(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewGatewayHandler(st, slog.Default())
	h.SetCRLStore(testCRLStore(t))

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	_, err := h.RevokeGatewayCertificate(testutil.AdminContext(adminID), connect.NewRequest(&pm.RevokeGatewayCertificateRequest{
		GatewayId: ulid.Make().String(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestGetCertificateRevocationList_ReturnsActiveAndFreshness(t *testing.T) {
	st := testutil.SetupPostgres(t)
	crlStore := testCRLStore(t)
	h := api.NewGatewayHandler(st, slog.Default())
	h.SetCRLStore(crlStore)

	// Revoke a fingerprint directly and confirm the RPC surfaces it.
	require.NoError(t, crlStore.Revoke(t.Context(), "deadbeef", time.Now().Add(time.Hour)))

	resp, err := h.GetCertificateRevocationList(t.Context(), connect.NewRequest(&pm.GetCertificateRevocationListRequest{}))
	require.NoError(t, err)
	assert.Contains(t, resp.Msg.RevokedFingerprints, "deadbeef")
	require.NotNil(t, resp.Msg.NotAfter)
	require.NotNil(t, resp.Msg.RefreshedAt)
	assert.True(t, resp.Msg.NotAfter.AsTime().After(resp.Msg.RefreshedAt.AsTime()),
		"not_after must be a future freshness bound past refreshed_at")
}

func TestListGateways_ReturnsEnrolled(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	id1, _ := enrollTestGateway(t, st, certAuth)
	id2, _ := enrollTestGateway(t, st, certAuth)

	h := api.NewGatewayHandler(st, slog.Default())
	resp, err := h.ListGateways(t.Context(), connect.NewRequest(&pm.ListGatewaysRequest{}))
	require.NoError(t, err)

	got := map[string]bool{}
	for _, g := range resp.Msg.Gateways {
		got[g.GatewayId] = true
	}
	assert.True(t, got[id1] && got[id2], "both enrolled gateways must be listed")
}

// fakeGatewayLiveness satisfies the handler's (unexported) gatewayLiveness
// interface structurally, so external tests can drive the ListGateways filter.
type fakeGatewayLiveness struct {
	live map[string]struct{}
	err  error
}

func (f fakeGatewayLiveness) ListLiveGatewayIDs(context.Context) (map[string]struct{}, error) {
	return f.live, f.err
}

// TestListGateways_FiltersToLive pins the spec-31 fix: only gateways currently
// live in the registry are returned, so a restarted gateway's departed
// ephemeral id (enrolled + cert-valid, but no live heartbeat) drops off instead
// of lingering as "Active".
func TestListGateways_FiltersToLive(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	id1, _ := enrollTestGateway(t, st, certAuth)
	id2, _ := enrollTestGateway(t, st, certAuth)

	h := api.NewGatewayHandler(st, slog.Default())
	h.SetGatewayLiveness(fakeGatewayLiveness{live: map[string]struct{}{id1: {}}}) // only id1 is live

	resp, err := h.ListGateways(t.Context(), connect.NewRequest(&pm.ListGatewaysRequest{}))
	require.NoError(t, err)

	got := map[string]bool{}
	for _, g := range resp.Msg.Gateways {
		got[g.GatewayId] = true
	}
	assert.True(t, got[id1], "the live gateway must be listed")
	assert.False(t, got[id2], "the enrolled-but-not-live gateway must be filtered out")
}

// TestListGateways_LivenessError_FailsOpen pins that a registry error does NOT
// blank the operator's list — it falls back to the not_after view.
func TestListGateways_LivenessError_FailsOpen(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	id1, _ := enrollTestGateway(t, st, certAuth)
	id2, _ := enrollTestGateway(t, st, certAuth)

	h := api.NewGatewayHandler(st, slog.Default())
	h.SetGatewayLiveness(fakeGatewayLiveness{err: errors.New("valkey unreachable")})

	resp, err := h.ListGateways(t.Context(), connect.NewRequest(&pm.ListGatewaysRequest{}))
	require.NoError(t, err)

	got := map[string]bool{}
	for _, g := range resp.Msg.Gateways {
		got[g.GatewayId] = true
	}
	assert.True(t, got[id1] && got[id2], "a liveness error must fall back to listing all not-yet-expired gateways")
}
