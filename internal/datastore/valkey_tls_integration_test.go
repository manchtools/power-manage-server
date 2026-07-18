package datastore_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os"
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

// templateACLUsers renders the real per-service ACL `user` lines from the deploy
// template with test passwords substituted. Reading the live template (rather
// than hardcoding grants) keeps the confinement test tracking production: a
// widened grant in valkey.conf.template surfaces here.
func templateACLUsers(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/valkey.conf.template")
	if err != nil {
		t.Fatalf("read valkey.conf.template: %v", err)
	}
	repl := strings.NewReplacer(
		"__VALKEY_CONTROL_PASSWORD__", "ctlpw",
		"__VALKEY_GATEWAY_PASSWORD__", "gwpw",
		"__VALKEY_INDEXER_PASSWORD__", "ixpw",
		"__VALKEY_TRAEFIK_PASSWORD__", "trfpw",
	)
	var b strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "user ") {
			b.WriteString(repl.Replace(line))
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		t.Fatal("no ACL user lines found in valkey.conf.template (matches-zero guard)")
	}
	return b.String()
}

// TestValkeyProductionACL_NamespaceConfinement_Integration exercises the actual
// per-service ACL users from valkey.conf.template (spec 32 AC 4), not a synthetic
// stand-in. It proves the two confinement invariants the 2026-07-18 audit found
// broken:
//
//   - pm-gateway may READ the CRL but must NOT write it (a compromised gateway
//     ZREM-ing its own fingerprint would defeat revocation fleet-wide).
//   - pm-indexer is confined to its search namespaces and cannot reach
//     traefik/pm:gateway/pm:crl (a full-keyspace grant re-opens the same blast
//     radius the spec exists to close).
func TestValkeyProductionACL_NamespaceConfinement_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (real Valkey container)")
	}
	certAuth := buildTestCA(t)
	caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM := caIssuedPKI(t, certAuth, "valkey-client")

	valkeyConf := "port 0\n" +
		"tls-port 6379\n" +
		"tls-cert-file /certs/server.crt\n" +
		"tls-key-file /certs/server.key\n" +
		"tls-ca-cert-file /certs/ca.crt\n" +
		"tls-auth-clients yes\n" +
		"save \"\"\n" +
		templateACLUsers(t)

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
	addr := fmt.Sprintf("localhost:%s", port.Port())

	clientTLS, err := datastore.ValkeyClientTLS(cliCertPEM, cliKeyPEM, caPEM)
	if err != nil {
		t.Fatalf("ValkeyClientTLS: %v", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// pm-gateway: reads the CRL and writes its own namespaces, but never writes
	// the CRL (A1 — revocation-defeat guard).
	gw := redis.NewClient(&redis.Options{Addr: addr, Username: "pm-gateway", Password: "gwpw", Protocol: 2, TLSConfig: clientTLS})
	defer gw.Close()
	if err := gw.ZRange(cctx, "pm:crl:revoked", 0, -1).Err(); err != nil {
		t.Errorf("pm-gateway must be able to READ pm:crl:revoked: %v", err)
	}
	if err := gw.Set(cctx, "pm:gateway:probe", "v", 0).Err(); err != nil {
		t.Errorf("pm-gateway must write its own pm:gateway:* namespace: %v", err)
	}
	if err := gw.ZAdd(cctx, "pm:crl:revoked", redis.Z{Score: 1, Member: "fp"}).Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("pm-gateway must be denied ZADD pm:crl:revoked with NOPERM (spec 32 A1), got: %v", err)
	}
	if err := gw.ZRem(cctx, "pm:crl:revoked", "fp").Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("pm-gateway must be denied ZREM pm:crl:revoked with NOPERM (spec 32 A1), got: %v", err)
	}

	// pm-indexer: confined to its search namespaces; cannot reach other keyspaces
	// (A2 — the ~* grant re-opens the full blast radius).
	ix := redis.NewClient(&redis.Options{Addr: addr, Username: "pm-indexer", Password: "ixpw", Protocol: 2, TLSConfig: clientTLS})
	defer ix.Close()
	if err := ix.Set(cctx, "idx:probe", "v", 0).Err(); err != nil {
		t.Errorf("pm-indexer must write its own idx:* namespace: %v", err)
	}
	if err := ix.Set(cctx, "search:device:probe", "v", 0).Err(); err != nil {
		t.Errorf("pm-indexer must write its own search:* namespace: %v", err)
	}
	for _, k := range []string{"traefik/probe", "pm:gateway:probe", "pm:device:probe"} {
		if err := ix.Set(cctx, k, "v", 0).Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
			t.Errorf("pm-indexer must be denied write to %q with NOPERM (spec 32 A2), got: %v", k, err)
		}
	}
	if err := ix.ZAdd(cctx, "pm:crl:revoked", redis.Z{Score: 1, Member: "fp"}).Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("pm-indexer must be denied ZADD pm:crl:revoked with NOPERM (spec 32 A2), got: %v", err)
	}
}
