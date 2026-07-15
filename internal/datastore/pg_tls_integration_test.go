package datastore_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/datastore"
)

// buildTestCA constructs the REAL internal/ca.CA the system uses (the spec-31
// trust root spec 32 reuses for datastore mTLS), so these integration tests
// exercise operationally-issued certs rather than a throwaway PKI.
func buildTestCA(t *testing.T) *ca.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Power Manage Internal CA", Organization: []string{"power-manage-test"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("ca key marshal: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	certAuth, err := ca.NewFromPEM(certPEM, keyPEM, 24*time.Hour)
	if err != nil {
		t.Fatalf("ca.NewFromPEM: %v", err)
	}
	return certAuth
}

// genKeyCSR generates an EC keypair and a plain CSR (no SANs — the CA
// authoritatively stamps SANs) with the given CN.
func genKeyCSR(t *testing.T, cn string) (keyPEM, csrPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// caIssuedPKI issues, from the real CA, a datastore SERVER cert (ServerAuth +
// DNS:localhost, via the gateway issuance path — the one that stamps ServerAuth
// EKU + a server-chosen DNS SAN) and a component CLIENT cert (ClientAuth,
// CN=clientRole, via the agent issuance path). This is the same CA machinery
// setup.sh uses to mint the operational datastore/component certs.
func caIssuedPKI(t *testing.T, certAuth *ca.CA, clientRole string) (caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM []byte) {
	t.Helper()
	srvKeyPEM, srvCSR := genKeyCSR(t, "datastore-server")
	srvCert, err := certAuth.IssueGatewayCertificateFromCSR(ulid.Make().String(), srvCSR, "localhost")
	if err != nil {
		t.Fatalf("issue datastore server cert: %v", err)
	}
	cliKeyPEM, cliCSR := genKeyCSR(t, clientRole)
	cliCert, err := certAuth.IssueCertificateFromCSR(clientRole, cliCSR)
	if err != nil {
		t.Fatalf("issue component client cert: %v", err)
	}
	return certAuth.CACertPEM(), srvCert.CertPEM, srvKeyPEM, cliCert.CertPEM, cliKeyPEM
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// TestPostgresMutualTLS_Integration proves the spec-32 Postgres posture on a
// real container using CERTS ISSUED BY THE REAL CA: hostssl + cert auth accepts
// a valid client cert (sslmode=verify-full), and a plaintext (sslmode=disable)
// connection is refused.
func TestPostgresMutualTLS_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (real Postgres container)")
	}
	const role = "pmtls"
	certAuth := buildTestCA(t)
	caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM := caIssuedPKI(t, certAuth, role)

	dir := t.TempDir()
	postgresqlConf := "listen_addresses = '*'\n" +
		"ssl = on\n" +
		"ssl_cert_file = '/certs/server.crt'\n" +
		"ssl_key_file = '/certs/server.key'\n" +
		"ssl_ca_file = '/certs/ca.crt'\n" +
		"hba_file = '/certs/pg_hba.conf'\n"
	pgHBA := "local all all trust\n" +
		"hostssl all all 0.0.0.0/0 cert clientcert=verify-full\n" +
		"hostssl all all ::/0 cert clientcert=verify-full\n"

	// The server key is mounted root-owned; postgres (uid 70) can't read a
	// root-owned 0600 file, and 0644 makes PG refuse to start. Chown it to
	// postgres before starting the server via an entrypoint wrapper.
	tlsEntrypoint := testcontainers.CustomizeRequestOption(func(req *testcontainers.GenericContainerRequest) error {
		req.Entrypoint = []string{"sh", "-c",
			"chown postgres /certs/server.key && chmod 0600 /certs/server.key && " +
				"exec docker-entrypoint.sh postgres -c config_file=/etc/postgresql.conf"}
		req.Cmd = nil
		return nil
	})

	ctx := context.Background()
	container, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase(role),
		postgres.WithUsername(role), // role name == client-cert CN (cert auth maps CN→role)
		postgres.WithPassword("unused-cert-auth"),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{Reader: bytes.NewReader([]byte(postgresqlConf)), ContainerFilePath: "/etc/postgresql.conf", FileMode: 0o644},
			testcontainers.ContainerFile{Reader: bytes.NewReader(srvCertPEM), ContainerFilePath: "/certs/server.crt", FileMode: 0o644},
			testcontainers.ContainerFile{Reader: bytes.NewReader(srvKeyPEM), ContainerFilePath: "/certs/server.key", FileMode: 0o600},
			testcontainers.ContainerFile{Reader: bytes.NewReader(caPEM), ContainerFilePath: "/certs/ca.crt", FileMode: 0o644},
			testcontainers.ContainerFile{Reader: bytes.NewReader([]byte(pgHBA)), ContainerFilePath: "/certs/pg_hba.conf", FileMode: 0o644},
		),
		tlsEntrypoint,
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		t.Fatalf("start tls postgres: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	// Connect via "localhost" so verify-full matches the CA-stamped DNS:localhost SAN.
	const host = "localhost"

	caFile := writeFile(t, dir, "client-ca.crt", caPEM)
	cliCertFile := writeFile(t, dir, "client.crt", cliCertPEM)
	cliKeyFile := writeFile(t, dir, "client.key", cliKeyPEM)

	verifyFullDSN := fmt.Sprintf(
		"postgres://%s@%s:%s/%s?sslmode=verify-full&sslrootcert=%s&sslcert=%s&sslkey=%s",
		role, host, port.Port(), role, caFile, cliCertFile, cliKeyFile)

	if err := datastore.RequirePostgresTLS(verifyFullDSN); err != nil {
		t.Errorf("RequirePostgresTLS rejected a valid verify-full DSN: %v", err)
	}

	connCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(connCtx, verifyFullDSN)
	if err != nil {
		t.Fatalf("mutual-TLS connect (CA-issued certs) failed: %v", err)
	}
	var one int
	if err := conn.QueryRow(connCtx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("SELECT 1 over mTLS: got %d, err %v", one, err)
	}
	_ = conn.Close(connCtx)

	disableDSN := fmt.Sprintf("postgres://%s:x@%s:%s/%s?sslmode=disable", role, host, port.Port(), role)
	if c, err := pgx.Connect(connCtx, disableDSN); err == nil {
		_ = c.Close(connCtx)
		t.Error("a plaintext connection must be refused against a hostssl-only Postgres")
	}
}
