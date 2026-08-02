package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type readinessStoreStub struct{ err error }

func (s readinessStoreStub) Ping(context.Context) error { return s.err }

type revocationCheckerStub struct{ err error }

func (s revocationCheckerStub) IsRevoked(context.Context, string) (bool, error) {
	return false, s.err
}

func TestCheckReadinessChecksDatabaseRevocationAndArtifactPath(t *testing.T) {
	artifactPath := t.TempDir()
	require.NoError(t, checkReadiness(context.Background(), readinessStoreStub{}, revocationCheckerStub{}, artifactPath))

	assert.ErrorContains(t,
		checkReadiness(context.Background(), readinessStoreStub{err: errors.New("down")}, revocationCheckerStub{}, artifactPath),
		"database")
	assert.ErrorContains(t,
		checkReadiness(context.Background(), readinessStoreStub{}, revocationCheckerStub{err: errors.New("denied")}, artifactPath),
		"revocation")

	file := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	assert.ErrorContains(t,
		checkReadiness(context.Background(), readinessStoreStub{}, revocationCheckerStub{}, file),
		"artifact path")
}
