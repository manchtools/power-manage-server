// Package agentrelease polls GitHub Releases for the latest agent binary
// and provides update information to connected agents.
package agentrelease

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultOwner = "MANCHTOOLS"
	defaultRepo  = "power-manage-agent"
	pollInterval = 5 * time.Minute

	// assetPrefix is the common prefix for agent binary assets.
	assetPrefix = "power-manage-agent-linux-"
	// checksumAsset is the name of the SHA256 checksums file.
	checksumAsset = "SHA256SUMS"
)

// releaseInfo holds the parsed latest release data.
type releaseInfo struct {
	version   string            // e.g. "2026.04.1" (without leading 'v')
	urls      map[string]string // arch -> download URL
	checksums map[string]string // arch -> SHA256 hex digest
}

// Cache periodically fetches the latest GitHub release for the agent
// and caches the version, download URLs, and checksums.
type Cache struct {
	mu      sync.RWMutex
	latest  *releaseInfo
	owner   string
	repo    string
	client  *http.Client
}

// Option configures a Cache.
type Option func(*Cache)

// WithRepo overrides the default GitHub owner/repo.
func WithRepo(owner, repo string) Option {
	return func(c *Cache) {
		c.owner = owner
		c.repo = repo
	}
}

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Cache) {
		c.client = client
	}
}

// NewCache creates a new release cache and starts background polling.
// The polling goroutine stops when ctx is canceled.
func NewCache(ctx context.Context, opts ...Option) *Cache {
	c := &Cache{
		owner: defaultOwner,
		repo:  defaultRepo,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}

	// Perform an initial fetch before returning so the cache is warm.
	c.poll(ctx)

	go c.run(ctx)
	return c
}

// GetUpdateInfo returns update information for the given architecture.
// If the agent is already on the latest version (or no release data is
// available), all return values are empty strings.
func (c *Cache) GetUpdateInfo(currentVersion, arch string) (version, url, checksum string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.latest == nil {
		return "", "", ""
	}

	if currentVersion == c.latest.version {
		return "", "", ""
	}

	u, ok := c.latest.urls[arch]
	if !ok {
		return "", "", ""
	}

	return c.latest.version, u, c.latest.checksums[arch]
}

// run is the background polling loop.
func (c *Cache) run(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.poll(ctx)
		}
	}
}

// poll fetches the latest release from GitHub and updates the cache.
func (c *Cache) poll(ctx context.Context) {
	info, err := c.fetchLatest(ctx)
	if err != nil {
		slog.Error("failed to fetch latest agent release", "error", err)
		return
	}

	c.mu.Lock()
	c.latest = info
	c.mu.Unlock()

	slog.Info("agent release cache updated", "version", info.version, "architectures", len(info.urls))
}

// githubRelease is the subset of the GitHub Releases API response we need.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// githubAsset represents a single release asset.
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// fetchLatest fetches and parses the latest release from the GitHub API.
func (c *Cache) fetchLatest(ctx context.Context) (*releaseInfo, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", c.owner, c.repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}

	version := strings.TrimPrefix(release.TagName, "v")

	urls := make(map[string]string)
	var checksumURL string

	for _, asset := range release.Assets {
		switch {
		case strings.HasPrefix(asset.Name, assetPrefix):
			arch := strings.TrimPrefix(asset.Name, assetPrefix)
			urls[arch] = asset.BrowserDownloadURL
		case asset.Name == checksumAsset:
			checksumURL = asset.BrowserDownloadURL
		}
	}

	checksums := make(map[string]string)
	if checksumURL != "" {
		checksums, err = c.fetchChecksums(ctx, checksumURL)
		if err != nil {
			slog.Warn("failed to fetch SHA256SUMS, continuing without checksums", "error", err)
		}
	}

	return &releaseInfo{
		version:   version,
		urls:      urls,
		checksums: checksums,
	}, nil
}

// fetchChecksums downloads and parses the SHA256SUMS file.
// Each line has the format: "<hex-digest>  <filename>".
func (c *Cache) fetchChecksums(ctx context.Context, url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch checksums: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("checksum download returned %d: %s", resp.StatusCode, string(body))
	}

	checksums := make(map[string]string)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: "<hash>  <filename>" (two spaces between hash and filename)
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		hash, filename := parts[0], parts[1]
		if strings.HasPrefix(filename, assetPrefix) {
			arch := strings.TrimPrefix(filename, assetPrefix)
			checksums[arch] = hash
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read checksums: %w", err)
	}

	return checksums, nil
}
