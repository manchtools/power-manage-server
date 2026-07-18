package api_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/mtls"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// enrollGatewayWithKey enrolls a gateway with a caller-held key so the renewal
// proof-of-possession can reuse it. Returns the gateway_id, the issued cert PEM,
// and the private key.
func enrollGatewayWithKey(t *testing.T, st *store.Store, certAuth *ca.CA) (gatewayID string, certPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	h := api.NewGatewayAuthHandler(st, certAuth, testEnrollToken, testGatewayURL, nil, slog.Default())
	csr, key := genGatewayCSR(t)
	resp, err := h.EnrollGateway(t.Context(), connect.NewRequest(&pm.EnrollGatewayRequest{
		Token:    testEnrollToken,
		Hostname: testGatewayHost,
		Csr:      csr,
	}))
	require.NoError(t, err)
	id, err := ca.DeviceIDFromPEM(resp.Msg.Certificate)
	require.NoError(t, err)
	return id, resp.Msg.Certificate, key
}

func mustParseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	c, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return c
}

func TestRenewGatewayCertificate_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	gatewayID, certPEM, key := enrollGatewayWithKey(t, st, certAuth)

	crlStore := testCRLStore(t)
	ih := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	ih.SetGatewayRenewal(certAuth, crlStore)

	peerCert := mustParseCert(t, certPEM)
	oldFP := ca.FingerprintFromCert(peerCert)
	ctx := mtls.ContextWithPeerCert(t.Context(), peerCert)

	resp, err := ih.RenewGatewayCertificate(ctx, connect.NewRequest(&pm.RenewGatewayCertificateRequest{
		Csr: csrForGatewayKey(t, key),
	}))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Msg.Certificate)
	require.NotNil(t, resp.Msg.NotAfter)

	// Same gateway_id, new fingerprint.
	newID, err := ca.DeviceIDFromPEM(resp.Msg.Certificate)
	require.NoError(t, err)
	assert.Equal(t, gatewayID, newID, "renewal keeps the same gateway_id")
	newFP, err := ca.FingerprintFromPEM(resp.Msg.Certificate)
	require.NoError(t, err)
	assert.NotEqual(t, oldFP, newFP)

	// The renewed cert preserves the authoritative DNS SAN — the name agent TLS
	// verification matches (D4: renewal must carry it forward, not drop it).
	renewed := mustParseCert(t, resp.Msg.Certificate)
	assert.Equal(t, []string{testGatewayHost}, renewed.DNSNames,
		"renewal must preserve the enrolled DNS SAN")

	// Old fingerprint revoked; projection advanced to the new one.
	active, err := crlStore.LoadActive(t.Context())
	require.NoError(t, err)
	assert.Contains(t, active, oldFP, "the superseded cert must be revoked on renewal")

	row, err := st.Queries().GetGatewayFingerprint(t.Context(), gatewayID)
	require.NoError(t, err)
	assert.Equal(t, newFP, row.Fingerprint, "projection fingerprint must advance to the renewed cert")
}

// TestRenewGatewayCertificate_RejectsNonCanonicalDNSSAN pins spec 31 D4: a
// current cert whose SAN set is not canonical — here, no DNS SAN at all (a
// pre-D1 identity) — must be REJECTED, not warn-and-renewed into a cert agents
// cannot verify. The gateway is expected to re-enroll (ephemeral-per-boot).
func TestRenewGatewayCertificate_RejectsNonCanonicalDNSSAN(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)

	// Issue a gateway cert with NO DNS SAN (empty hostname), reproducing a
	// pre-DNS-SAN-fix identity that the enrollment path would no longer mint.
	csr, key := genGatewayCSR(t)
	gatewayID := ulid.Make().String()
	issued, err := certAuth.IssueGatewayCertificateFromCSR(gatewayID, csr, "")
	require.NoError(t, err)
	peerCert := mustParseCert(t, issued.CertPEM)
	require.Empty(t, peerCert.DNSNames, "precondition: the current cert has no DNS SAN")

	ih := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	ih.SetGatewayRenewal(certAuth, testCRLStore(t))
	ctx := mtls.ContextWithPeerCert(t.Context(), peerCert)

	// Proof-of-possession would pass (same key), so a rejection here proves the
	// D4 canonical-SAN gate fired, not an unrelated denial.
	_, err = ih.RenewGatewayCertificate(ctx, connect.NewRequest(&pm.RenewGatewayCertificateRequest{
		Csr: csrForGatewayKey(t, key),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err),
		"a non-canonical DNS SAN must be rejected FailedPrecondition, not renewed")
}

func TestRenewGatewayCertificate_ProofOfPossessionFails(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	_, certPEM, _ := enrollGatewayWithKey(t, st, certAuth)

	crlStore := testCRLStore(t)
	ih := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	ih.SetGatewayRenewal(certAuth, crlStore)

	ctx := mtls.ContextWithPeerCert(t.Context(), mustParseCert(t, certPEM))
	// A renewal CSR with a DIFFERENT key — the renewer does not possess the
	// current cert's key.
	otherCSR, _ := genGatewayCSR(t)
	_, err := ih.RenewGatewayCertificate(ctx, connect.NewRequest(&pm.RenewGatewayCertificateRequest{
		Csr: otherCSR,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestRenewGatewayCertificate_NoPeerCertRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	ih := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	ih.SetGatewayRenewal(certAuth, testCRLStore(t))

	csr, _ := genGatewayCSR(t)
	// No peer cert injected — the listener middleware was not wired.
	_, err := ih.RenewGatewayCertificate(t.Context(), connect.NewRequest(&pm.RenewGatewayCertificateRequest{
		Csr: csr,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestRenewGatewayCertificate_NonGatewayPeerRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	certAuth := newTestCA(t)
	ih := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	ih.SetGatewayRenewal(certAuth, testCRLStore(t))

	// Present an AGENT-class cert as the peer — renewal must refuse a non-gateway.
	agentCertPEM, _, _ := issueTestDeviceCert(t, certAuth, testutil.NewID())
	ctx := mtls.ContextWithPeerCert(t.Context(), mustParseCert(t, agentCertPEM))

	csr, _ := genGatewayCSR(t)
	_, err := ih.RenewGatewayCertificate(ctx, connect.NewRequest(&pm.RenewGatewayCertificateRequest{
		Csr: csr,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}
