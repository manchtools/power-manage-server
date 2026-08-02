package backupstatus

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadReportsMissingFreshAndStaleBackups(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()

	missing, err := Read(directory, now, 26*time.Hour)
	require.NoError(t, err)
	assert.True(t, missing.Stale)
	assert.Nil(t, missing.LastSuccessfulBackup)

	writeFixture(t, directory, now.Add(-time.Hour), "postgres-fresh.dump")
	fresh, err := Read(directory, now, 26*time.Hour)
	require.NoError(t, err)
	assert.False(t, fresh.Stale)
	require.NotNil(t, fresh.LagSeconds)
	assert.Equal(t, int64(time.Hour/time.Second), *fresh.LagSeconds)

	writeFixture(t, directory, now.Add(-27*time.Hour), "postgres-stale.dump")
	stale, err := Read(directory, now, 26*time.Hour)
	require.NoError(t, err)
	assert.True(t, stale.Stale)
}

func TestReadRejectsUntrustedStatusFiles(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	for name, document := range map[string]string{
		"unknown field": `{"version":1,"unknown":true}`,
		"path traversal": fmt.Sprintf(`{"version":1,"completed_at":%q,"artifact":"../dump","size_bytes":1,"sha256":%q}`,
			now.Format(time.RFC3339), strings.Repeat("0", 64)),
		"future completion": fmt.Sprintf(`{"version":1,"completed_at":%q,"artifact":"dump","size_bytes":1,"sha256":%q}`,
			now.Add(time.Hour).Format(time.RFC3339), strings.Repeat("0", 64)),
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(directory, StatusFilename), []byte(document), 0o600))
			_, err := Read(directory, now, 26*time.Hour)
			assert.Error(t, err)
		})
	}
}

func writeFixture(t *testing.T, directory string, completedAt time.Time, artifact string) {
	t.Helper()
	contents := []byte("verified postgres dump")
	require.NoError(t, os.WriteFile(filepath.Join(directory, artifact), contents, 0o600))
	document := fmt.Sprintf(
		`{"version":1,"completed_at":%q,"artifact":%q,"size_bytes":%d,"sha256":%q}`,
		completedAt.Format(time.RFC3339), artifact, len(contents), strings.Repeat("0", 64),
	)
	require.NoError(t, os.WriteFile(filepath.Join(directory, StatusFilename), []byte(document), 0o600))
}
