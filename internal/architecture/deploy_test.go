package architecture_test

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDeploymentIsTheTwoServiceTarget(t *testing.T) {
	root := repositoryRoot(t)
	compose := readDeploymentFile(t, root, "compose.yml")

	services := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(compose))
	inServices := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "services:" {
			inServices = true
			continue
		}
		if inServices && line != "" && line[0] != ' ' {
			break
		}
		if inServices && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(line, ":") {
			services[strings.TrimSuffix(strings.TrimSpace(line), ":")] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan compose services: %v", err)
	}
	want := map[string]struct{}{"traefik": {}, "control": {}}
	if len(services) != len(want) {
		t.Fatalf("deployment services = %v; want exactly %v", services, want)
	}
	for service := range want {
		if _, exists := services[service]; !exists {
			t.Errorf("deployment is missing %s", service)
		}
	}

	for _, forbidden := range []string{
		"/var/run/docker.sock",
		"providers.docker",
		"valkey",
		"asynq",
		"indexer",
		"postgres",
	} {
		if strings.Contains(strings.ToLower(compose), forbidden) {
			t.Errorf("compose contains abolished runtime %q", forbidden)
		}
	}
	if !strings.Contains(compose, "internal: true") {
		t.Error("agent proxy network is not isolated")
	}
	if strings.Contains(compose, `http://127.0.0.1:8081/ready`) ||
		!strings.Contains(compose, `https://127.0.0.1:8081/ready`) {
		t.Error("control healthcheck must use its TLS public listener")
	}

	routes := readDeploymentFile(t, root, filepath.Join("traefik", "dynamic", "routes.yml"))
	for _, required := range []string{
		"passthrough: true", "proxyProtocol:", "version: 2", "172.30.0.3:8082",
		"https://control:8081", "serversTransport: control-tls", "serverName: control",
		"rootCAs:", "/run/certs/ca-trust-bundle.crt", "minVersion: VersionTLS13", "maxVersion: VersionTLS13",
	} {
		if !strings.Contains(routes, required) {
			t.Errorf("static route configuration is missing %q", required)
		}
	}
	if strings.Contains(routes, "url: http://") {
		t.Error("Traefik backend route must not use plaintext HTTP")
	}

	traefik := readDeploymentFile(t, root, filepath.Join("traefik", "traefik.yml"))
	for _, required := range []string{"format: json", "RequestPath: drop", "RequestLine: drop"} {
		if !strings.Contains(traefik, required) {
			t.Errorf("Traefik access-log configuration is missing %q", required)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readDeploymentFile(t *testing.T, root, path string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(root, "deploy", path))
	if err != nil {
		t.Fatalf("read deploy/%s: %v", path, err)
	}
	return string(contents)
}
