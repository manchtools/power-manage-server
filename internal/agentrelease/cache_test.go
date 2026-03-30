package agentrelease

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCache_GetUpdateInfo_NoData(t *testing.T) {
	// A cache with no fetched data returns empty strings.
	c := &Cache{
		owner:  "test",
		repo:   "test",
		client: http.DefaultClient,
	}

	version, url, checksum := c.GetUpdateInfo("1.0.0", "amd64")
	if version != "" || url != "" || checksum != "" {
		t.Fatalf("expected empty strings, got version=%q url=%q checksum=%q", version, url, checksum)
	}
}

func TestCache_GetUpdateInfo_SameVersion(t *testing.T) {
	c := &Cache{
		owner:  "test",
		repo:   "test",
		client: http.DefaultClient,
		latest: &releaseInfo{
			version:   "2026.04.1",
			urls:      map[string]string{"amd64": "https://example.com/agent-amd64"},
			checksums: map[string]string{"amd64": "abc123"},
		},
	}

	version, url, checksum := c.GetUpdateInfo("2026.04.1", "amd64")
	if version != "" || url != "" || checksum != "" {
		t.Fatalf("expected empty strings for same version, got version=%q url=%q checksum=%q", version, url, checksum)
	}
}

func TestCache_GetUpdateInfo_DifferentVersion(t *testing.T) {
	c := &Cache{
		owner:  "test",
		repo:   "test",
		client: http.DefaultClient,
		latest: &releaseInfo{
			version:   "2026.04.2",
			urls:      map[string]string{"amd64": "https://example.com/agent-amd64", "arm64": "https://example.com/agent-arm64"},
			checksums: map[string]string{"amd64": "abc123", "arm64": "def456"},
		},
	}

	version, url, checksum := c.GetUpdateInfo("2026.04.1", "amd64")
	if version != "2026.04.2" {
		t.Fatalf("version: got %q, want %q", version, "2026.04.2")
	}
	if url != "https://example.com/agent-amd64" {
		t.Fatalf("url: got %q, want %q", url, "https://example.com/agent-amd64")
	}
	if checksum != "abc123" {
		t.Fatalf("checksum: got %q, want %q", checksum, "abc123")
	}
}

func TestCache_GetUpdateInfo_UnknownArch(t *testing.T) {
	c := &Cache{
		owner:  "test",
		repo:   "test",
		client: http.DefaultClient,
		latest: &releaseInfo{
			version:   "2026.04.2",
			urls:      map[string]string{"amd64": "https://example.com/agent-amd64"},
			checksums: map[string]string{"amd64": "abc123"},
		},
	}

	version, url, checksum := c.GetUpdateInfo("2026.04.1", "riscv64")
	if version != "" || url != "" || checksum != "" {
		t.Fatalf("expected empty strings for unknown arch, got version=%q url=%q checksum=%q", version, url, checksum)
	}
}

func TestCache_FetchLatest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/test/agent/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("missing Accept header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"tag_name": "v2026.04.3",
			"assets": [
				{
					"name": "power-manage-agent-linux-amd64",
					"browser_download_url": "https://github.com/test/agent/releases/download/v2026.04.3/power-manage-agent-linux-amd64"
				},
				{
					"name": "power-manage-agent-linux-arm64",
					"browser_download_url": "https://github.com/test/agent/releases/download/v2026.04.3/power-manage-agent-linux-arm64"
				},
				{
					"name": "SHA256SUMS",
					"browser_download_url": "https://github.com/test/agent/releases/download/v2026.04.3/SHA256SUMS"
				}
			]
		}`))
	})
	mux.HandleFunc("/test/agent/releases/download/v2026.04.3/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("aabbccdd  power-manage-agent-linux-amd64\n11223344  power-manage-agent-linux-arm64\n"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	c := &Cache{
		owner:  "test",
		repo:   "agent",
		client: server.Client(),
	}

	// Override the API URL by monkey-patching fetchLatest via poll.
	// Since fetchLatest builds the URL from c.owner/c.repo, we need to override the transport.
	// Instead, test fetchLatest directly by using a custom client that rewrites the URL.
	c.client = &http.Client{
		Transport: &rewriteTransport{
			base:    server.Client().Transport,
			baseURL: server.URL,
		},
	}

	info, err := c.fetchLatest(context.Background())
	if err != nil {
		t.Fatalf("fetchLatest: %v", err)
	}

	if info.version != "2026.04.3" {
		t.Fatalf("version: got %q, want %q", info.version, "2026.04.3")
	}

	if len(info.urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d", len(info.urls))
	}

	if _, ok := info.urls["amd64"]; !ok {
		t.Fatal("missing amd64 URL")
	}
	if _, ok := info.urls["arm64"]; !ok {
		t.Fatal("missing arm64 URL")
	}

	if info.checksums["amd64"] != "aabbccdd" {
		t.Fatalf("amd64 checksum: got %q, want %q", info.checksums["amd64"], "aabbccdd")
	}
	if info.checksums["arm64"] != "11223344" {
		t.Fatalf("arm64 checksum: got %q, want %q", info.checksums["arm64"], "11223344")
	}
}

func TestCache_FetchLatest_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("rate limited"))
	}))
	defer server.Close()

	c := &Cache{
		owner: "test",
		repo:  "agent",
		client: &http.Client{
			Transport: &rewriteTransport{
				base:    server.Client().Transport,
				baseURL: server.URL,
			},
		},
	}

	_, err := c.fetchLatest(context.Background())
	if err == nil {
		t.Fatal("expected error for API 403")
	}
}

func TestCache_FetchChecksums(t *testing.T) {
	checksumContent := `aabbccddee  power-manage-agent-linux-amd64
1122334455  power-manage-agent-linux-arm64
ffee998877  some-other-file
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksumContent))
	}))
	defer server.Close()

	c := &Cache{client: server.Client()}

	checksums, err := c.fetchChecksums(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("fetchChecksums: %v", err)
	}

	if len(checksums) != 2 {
		t.Fatalf("expected 2 checksums (only agent assets), got %d", len(checksums))
	}

	if checksums["amd64"] != "aabbccddee" {
		t.Fatalf("amd64 checksum: got %q, want %q", checksums["amd64"], "aabbccddee")
	}
	if checksums["arm64"] != "1122334455" {
		t.Fatalf("arm64 checksum: got %q, want %q", checksums["arm64"], "1122334455")
	}
}

func TestWithRepo(t *testing.T) {
	c := &Cache{owner: "default", repo: "default"}
	WithRepo("custom-owner", "custom-repo")(c)

	if c.owner != "custom-owner" || c.repo != "custom-repo" {
		t.Fatalf("WithRepo: got owner=%q repo=%q", c.owner, c.repo)
	}
}

// rewriteTransport rewrites all request URLs to point at the test server.
type rewriteTransport struct {
	base    http.RoundTripper
	baseURL string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	req.URL.Host = t.baseURL[len("http://"):]
	transport := t.base
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}
