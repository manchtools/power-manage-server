package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
