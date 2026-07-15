package datastore_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/manchtools/power-manage/server/internal/datastore"
)

// TestValkeyMutualTLS_AndACL_Integration proves the spec-32 Valkey posture on a
// real valkey-bundle container: the plaintext port is disabled (port 0) and
// tls-auth-clients requires a client cert; a per-service ACL user authenticates
// over that mTLS transport and a scoped user is confined to its namespace and
// denied destructive commands.
func TestValkeyMutualTLS_AndACL_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (real Valkey container)")
	}
	certAuth := buildTestCA(t)
	caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM := caIssuedPKI(t, certAuth, "valkey-client")

	// port 0 disables plaintext; tls-port + tls-auth-clients yes require a
	// CA-signed client cert. Two ACL users: pmfull (connectivity) and pmscoped
	// (confined to app:*, denied @dangerous).
	valkeyConf := "port 0\n" +
		"tls-port 6379\n" +
		"tls-cert-file /certs/server.crt\n" +
		"tls-key-file /certs/server.key\n" +
		"tls-ca-cert-file /certs/ca.crt\n" +
		"tls-auth-clients yes\n" +
		"save \"\"\n" +
		"user default off\n" +
		"user pmfull on >fullpw ~* +@all\n" +
		"user pmscoped on >scopedpw ~app:* +@read +@write +@connection -@dangerous\n"

	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "valkey/valkey-bundle:9.1.0",
			ExposedPorts: []string{"6379/tcp"},
			Cmd:          []string{"valkey-server", "/etc/valkey/valkey.conf"},
			Files: []testcontainers.ContainerFile{
				{Reader: bytes.NewReader([]byte(valkeyConf)), ContainerFilePath: "/etc/valkey/valkey.conf", FileMode: 0o644},
				{Reader: bytes.NewReader(srvCertPEM), ContainerFilePath: "/certs/server.crt", FileMode: 0o644},
				{Reader: bytes.NewReader(srvKeyPEM), ContainerFilePath: "/certs/server.key", FileMode: 0o644},
				{Reader: bytes.NewReader(caPEM), ContainerFilePath: "/certs/ca.crt", FileMode: 0o644},
			},
			// Even with the plaintext port off, valkey logs "Ready to accept
			// connections tls" — the substring wait still fires.
			WaitingFor: wait.ForLog("Ready to accept connections").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start tls valkey: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	// Connect via "localhost" so the CA-stamped DNS:localhost SAN matches.
	addr := fmt.Sprintf("localhost:%s", port.Port())

	clientTLS, err := datastore.ValkeyClientTLS(cliCertPEM, cliKeyPEM, caPEM)
	if err != nil {
		t.Fatalf("ValkeyClientTLS: %v", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// 1) mTLS + ACL user connects and works.
	full := redis.NewClient(&redis.Options{Addr: addr, Username: "pmfull", Password: "fullpw", Protocol: 2, TLSConfig: clientTLS})
	defer full.Close()
	if err := full.Ping(cctx).Err(); err != nil {
		t.Fatalf("mTLS+ACL ping failed: %v", err)
	}

	// 2) Same CA trust but NO client cert → refused (tls-auth-clients yes).
	noCertTLS := &tls.Config{RootCAs: clientTLS.RootCAs, MinVersion: tls.VersionTLS13}
	noCert := redis.NewClient(&redis.Options{Addr: addr, Username: "pmfull", Password: "fullpw", Protocol: 2, TLSConfig: noCertTLS})
	defer noCert.Close()
	if err := noCert.Ping(cctx).Err(); err == nil {
		t.Error("a TLS connection without a client cert must be refused under tls-auth-clients yes")
	}

	// 3) ACL enforcement: pmscoped is confined to app:* and denied @dangerous.
	scoped := redis.NewClient(&redis.Options{Addr: addr, Username: "pmscoped", Password: "scopedpw", Protocol: 2, TLSConfig: clientTLS})
	defer scoped.Close()
	if err := scoped.Set(cctx, "app:k", "v", 0).Err(); err != nil {
		t.Errorf("pmscoped must write its own app:* namespace: %v", err)
	}
	if err := scoped.Get(cctx, "other:k").Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("pmscoped must be denied a key outside app:* with NOPERM, got: %v", err)
	}
	if err := scoped.FlushAll(cctx).Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("pmscoped must be denied FLUSHALL (@dangerous) with NOPERM, got: %v", err)
	}
}
