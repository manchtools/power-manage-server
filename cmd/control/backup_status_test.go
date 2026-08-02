package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/backupstatus"
)

func TestRunBackupStatusReportsLagWithoutAffectingReadiness(t *testing.T) {
	t.Parallel()
	var output, diagnostics bytes.Buffer
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	exitCode := runBackupStatus(&output, &diagnostics, &Config{
		BackupPath: t.TempDir(), BackupMaxLag: 26 * time.Hour,
	}, func() time.Time { return now })
	assert.Equal(t, 1, exitCode)

	var status backupstatus.Status
	require.NoError(t, json.Unmarshal(output.Bytes(), &status))
	assert.True(t, status.Stale)
	assert.Nil(t, status.LastSuccessfulBackup)
	assert.Empty(t, diagnostics.String(), "a missing first backup is stale, not a malformed status file")
}

func TestRunBackupStatusDiagnosesMalformedMarker(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, backupstatus.StatusFilename), []byte(`{}`), 0o600))
	var output, diagnostics bytes.Buffer

	exitCode := runBackupStatus(&output, &diagnostics, &Config{
		BackupPath: directory, BackupMaxLag: 26 * time.Hour,
	}, time.Now)
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, diagnostics.String(), "backup-status:")
}
