package store_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Creation provenance is write-once. The audited store exposes generated
// queries as its only mutation surface, so proving that no query can update the
// column makes the invariant structural rather than a handler convention.
func TestUserProvisioningSource_HasNoUpdateQuery(t *testing.T) {
	entries, err := os.ReadDir("queries")
	require.NoError(t, err)
	require.NotEmpty(t, entries, "matches-zero guard: no SQL query files were found")

	updateSource := regexp.MustCompile(`(?is)update\s+(?:public\.)?users\s+set[^;]*provisioning_source`)
	var declarations, mutations int
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("queries", entry.Name()))
		require.NoError(t, err)
		declarations += strings.Count(string(raw), "provisioning_source")
		if updateSource.Match(raw) {
			mutations++
		}
	}
	require.Positive(t, declarations, "matches-zero guard: no query declares provisioning_source")
	assert.Zero(t, mutations, "provisioning_source must never be updated after user creation")
}

func TestUserProvisioningSource_RejectsUnknownValues(t *testing.T) {
	_, pool := setupSQLite(t)

	err := execFails(t, pool,
		`INSERT INTO users (id, email, provisioning_source) VALUES ($1, $2, 'manual')`,
		newID(), "manual@example.test")
	assert.Contains(t, err.Error(), "provisioning_source IN ('scim', 'oidc_jit')")
}
