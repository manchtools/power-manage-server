package ca_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/mtls"
)

// The CSR the agent actually sends comes from the SDK, and every other test in
// this package hand-builds one instead. Both suites stayed green while the SDK
// emitted a key type the CA refuses, so enrolment and renewal were dead in every
// shipping configuration. These two tests are the only place where the real
// producer meets the real consumer; they must never be replaced by a local
// fixture.

// The device id is minted by the control server, so it is deliberately not the
// hostname the agent puts in the CSR — an issued leaf carrying the CSR's CN
// would mean the agent chose its own identity.
const (
	interopHostname = "workstation-17.lan"
	interopDeviceID = "01JQK8P3ZBQ0FN2W6TXY4RC9DA"
)

func TestIssueCertificateFromCSR_AcceptsSDKEnrolmentCSR(t *testing.T) {
	caCertPEM, caKeyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(caCertPEM, caKeyPEM, 24*time.Hour)
	require.NoError(t, err)

	csrPEM, keyPEM, err := sdkcrypto.GenerateCSR(interopHostname)
	require.NoError(t, err)

	issued, err := c.IssueCertificateFromCSR(interopDeviceID, csrPEM)
	require.NoError(t, err, "the control CA must accept the CSR the SDK actually produces")

	assertAgentLeaf(t, c, issued, keyPEM)
}

func TestIssueCertificateFromCSR_AcceptsSDKRenewalCSR(t *testing.T) {
	caCertPEM, caKeyPEM := generateTestCA(t)
	c, err := ca.NewFromPEM(caCertPEM, caKeyPEM, 24*time.Hour)
	require.NoError(t, err)

	enrolCSR, keyPEM, err := sdkcrypto.GenerateCSR(interopHostname)
	require.NoError(t, err)
	enrolled, err := c.IssueCertificateFromCSR(interopDeviceID, enrolCSR)
	require.NoError(t, err)

	renewalCSR, err := sdkcrypto.GenerateCSRFromKey(interopHostname, keyPEM)
	require.NoError(t, err)

	// Renewal reuses the enrolment key, so the same key file must satisfy the
	// proof-of-possession gate the renewal handler applies before issuing.
	require.NoError(t, ca.AssertCSRMatchesCertKey(enrolled.CertPEM, renewalCSR))

	renewed, err := c.IssueCertificateFromCSR(interopDeviceID, renewalCSR)
	require.NoError(t, err, "the control CA must accept the renewal CSR the SDK actually produces")

	assertAgentLeaf(t, c, renewed, keyPEM)
}

// assertAgentLeaf pins the three properties §12.5 depends on for an issued agent
// certificate, plus that the agent can actually use it with the key it kept.
func assertAgentLeaf(t *testing.T, c *ca.CA, issued *ca.Certificate, keyPEM []byte) {
	t.Helper()

	block, _ := pem.Decode(issued.CertPEM)
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.Equal(t, interopDeviceID, parsed.Subject.CommonName, "CN must be the server-minted device id")
	assert.Equal(t, interopDeviceID, parsed.Subject.SerialNumber)
	assert.NotEqual(t, interopHostname, parsed.Subject.CommonName, "the CSR's CN must never become the identity")

	require.Len(t, parsed.URIs, 1, "an issued agent cert must carry exactly one URI SAN")
	assert.Equal(t, "spiffe://power-manage/agent", parsed.URIs[0].String())
	class, err := mtls.PeerClassFromCert(parsed)
	require.NoError(t, err)
	assert.Equal(t, mtls.PeerClassAgent, class)

	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, parsed.ExtKeyUsage,
		"an agent cert must be client-auth only")

	verified, err := c.VerifyCertificate(issued.CertPEM)
	require.NoError(t, err)
	assert.Equal(t, interopDeviceID, verified)

	// X509KeyPair is format-agnostic and pairs the leaf with the key the SDK
	// returned, so it proves the agent can present this certificate rather than
	// merely that the CA signed something.
	_, err = tls.X509KeyPair(issued.CertPEM, keyPEM)
	require.NoError(t, err, "the SDK's key must load together with the issued leaf")
}
