package main

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The store layer carries the behavioral coverage for the rebuild
// subcommand (cascade expansion, unknown targets, skip counters — see
// internal/store/rebuild_cascade_test.go). These tests pin the CLI
// shell around it: exit codes for the no-database paths.

func TestRunRebuildProjections_NoDatabaseURLIsCouldNotRun(t *testing.T) {
	t.Setenv("CONTROL_DATABASE_URL", "")
	code := runRebuildProjections([]string{"--env-file", "/nonexistent/never.env"})
	assert.Equal(t, 2, code, "missing CONTROL_DATABASE_URL must exit 2 (could not run)")
}

func TestRunRebuildProjections_HelpIsSuccess(t *testing.T) {
	code := runRebuildProjections([]string{"-h"})
	assert.Equal(t, 0, code, "-h is a successful help request, not a failure")
}

func TestRunRebuildProjections_ArchiveDirWithTargetsIsCouldNotRun(t *testing.T) {
	t.Setenv("CONTROL_DATABASE_URL", "")

	// Capture stderr: exit 2 is shared with env/config failures, so the
	// assertion must prove THIS guard fired, not a missing database URL.
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	code := runRebuildProjections([]string{"--env-file", "/nonexistent/never.env", "--archive-dir", "/tmp/x", "users"})
	os.Stderr = orig
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Equal(t, 2, code, "--archive-dir restores every projection; combining it with target selection must exit 2")
	assert.Contains(t, string(out), "target selection is not supported",
		"the exit must come from the archive-target guard, not an unrelated config failure")
}
