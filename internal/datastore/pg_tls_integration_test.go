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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/manchtools/power-manage/server/internal/datastore"
)

// mkCert issues a cert from the given template signed by parent/parentKey (or
// self-signed when parent is nil), returning the cert PEM and a PEM-encoded
// EC private key.
func mkCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (certPEM, keyPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	signer, signerKey := parent, parentKey
	if signer == nil {
		signer, signerKey = tmpl, key // self-signed
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), key
}

// pgTLSPKI builds a CA plus a server cert (SAN 127.0.0.1/::1/localhost) and a
// client cert whose CN maps to the DB role.
func pgTLSPKI(t *testing.T, clientCN string) (caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM []byte) {
	t.Helper()
	notBefore := time.Unix(0, 0)
	notAfter := time.Now().Add(time.Hour)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pm-test-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caPEM, _, caKey := mkCert(t, caTmpl, nil, nil)
	caCert, _ := x509.ParseCertificate(pemDER(caPEM))

	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pg-server"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	srvCertPEM, srvKeyPEM, _ = mkCert(t, srvTmpl, caCert, caKey)

	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: clientCN},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliCertPEM, cliKeyPEM, _ = mkCert(t, cliTmpl, caCert, caKey)
	return caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM
}

func pemDER(p []byte) []byte { b, _ := pem.Decode(p); return b.Bytes }

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// TestPostgresMutualTLS_Integration proves the spec-32 Postgres posture on a
// real container: hostssl + cert auth accepts a valid client cert (sslmode=
// verify-full), and a plaintext (sslmode=disable) connection is refused.
func TestPostgresMutualTLS_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (real Postgres container)")
	}
	const role = "pmtls"
	caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM := pgTLSPKI(t, role)

	dir := t.TempDir()
	postgresqlConf := "listen_addresses = '*'\n" +
		"ssl = on\n" +
		"ssl_cert_file = '/certs/server.crt'\n" +
		"ssl_key_file = '/certs/server.key'\n" +
		"ssl_ca_file = '/certs/ca.crt'\n" +
		"hba_file = '/certs/pg_hba.conf'\n"
	// local (unix socket) trust so the entrypoint can initdb/create the role;
	// TCP requires SSL + a CA-signed client cert whose CN maps to the DB user.
	pgHBA := "local all all trust\n" +
		"hostssl all all 0.0.0.0/0 cert clientcert=verify-full\n" +
		"hostssl all all ::/0 cert clientcert=verify-full\n"

	// The server key is mounted root-owned; postgres (uid 70) can't read a
	// root-owned 0600 file, and 0644 makes PG refuse to start. Chown it to
	// postgres before starting the server (the classic PG-in-a-container TLS
	// hurdle) via an entrypoint wrapper, then exec the normal entrypoint.
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

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	caFile := writeFile(t, dir, "client-ca.crt", caPEM)
	cliCertFile := writeFile(t, dir, "client.crt", cliCertPEM)
	cliKeyFile := writeFile(t, dir, "client.key", cliKeyPEM)

	verifyFullDSN := fmt.Sprintf(
		"postgres://%s@%s:%s/%s?sslmode=verify-full&sslrootcert=%s&sslcert=%s&sslkey=%s",
		role, host, port.Port(), role, caFile, cliCertFile, cliKeyFile)

	// The DSN validator accepts it.
	if err := datastore.RequirePostgresTLS(verifyFullDSN); err != nil {
		t.Errorf("RequirePostgresTLS rejected a valid verify-full DSN: %v", err)
	}

	// Mutual TLS connects.
	connCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(connCtx, verifyFullDSN)
	if err != nil {
		t.Fatalf("mutual-TLS connect failed: %v", err)
	}
	var one int
	if err := conn.QueryRow(connCtx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("SELECT 1 over mTLS: got %d, err %v", one, err)
	}
	_ = conn.Close(connCtx)

	// A plaintext (sslmode=disable) connection is refused by the hostssl-only hba.
	disableDSN := fmt.Sprintf("postgres://%s:x@%s:%s/%s?sslmode=disable", role, host, port.Port(), role)
	if c, err := pgx.Connect(connCtx, disableDSN); err == nil {
		_ = c.Close(connCtx)
		t.Error("a plaintext connection must be refused against a hostssl-only Postgres")
	}
}
