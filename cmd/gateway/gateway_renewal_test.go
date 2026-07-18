package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/gwenroll"
	"github.com/manchtools/power-manage/server/internal/mtls"
)

// expiredGatewayIdentity builds a minimal Identity whose cert is already past
// its NotAfter, so runGatewayCertRenewal attempts renewal immediately (wait=0).
// The loop only reads CertPEM (for expiry) and GatewayID on the failure path.
func expiredGatewayIdentity(t *testing.T) *gwenroll.Identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ulid.Make().String()},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour), // already expired → renew now
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &gwenroll.Identity{GatewayID: tmpl.Subject.CommonName, CertPEM: certPEM}
}

// TestRunGatewayCertRenewal_HaltsOnSelfRevocation pins spec 31 D8: when renewal
// is rejected PermissionDenied repeatedly (the gateway's own cert was revoked),
// the loop stops retrying forever and RETURNS so the supervisor can restart and
// re-enroll. Without the halt the loop retries indefinitely and this returns via
// the 5s timeout instead.
func TestRunGatewayCertRenewal_HaltsOnSelfRevocation(t *testing.T) {
	prevBackoff := renewalRetryBackoff
	renewalRetryBackoff = time.Millisecond // shrink the retry so the streak accrues fast
	t.Cleanup(func() { renewalRetryBackoff = prevBackoff })

	var calls atomic.Int64
	prevRenew := renewGatewayCert
	t.Cleanup(func() { renewGatewayCert = prevRenew })
	// Always report PermissionDenied — what control returns to a revoked gateway.
	renewGatewayCert = func(context.Context, pmv1connect.InternalServiceClient, *gwenroll.Identity) (time.Time, error) {
		calls.Add(1)
		return time.Time{}, connect.NewError(connect.CodePermissionDenied, errors.New("client certificate revoked"))
	}

	id := expiredGatewayIdentity(t)
	rotator := mtls.NewCertRotator(id.TLSCert)

	done := make(chan struct{})
	go func() {
		runGatewayCertRenewal(context.Background(), nil, id, rotator, slog.Default())
		close(done)
	}()

	select {
	case <-done:
		require.GreaterOrEqual(t, int(calls.Load()), selfRevocationHaltThreshold,
			"the loop must observe a PermissionDenied streak before halting")
	case <-time.After(5 * time.Second):
		t.Fatal("renewal loop did not halt on repeated self-revocation (retried forever)")
	}
}
