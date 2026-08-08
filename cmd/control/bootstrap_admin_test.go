package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/identity"
)

func TestWriteBootstrapAdminOutput_RawTokenIsPipeSafe(t *testing.T) {
	issued := identity.BootstrapToken{
		Token:     "one-use-secret",
		URL:       "https://control.example/setup#token=one-use-secret",
		ExpiresAt: time.Date(2026, 8, 8, 18, 0, 0, 0, time.UTC),
	}
	var output bytes.Buffer
	require.NoError(t, writeBootstrapAdminOutput(&output, issued, true))
	assert.Equal(t, "one-use-secret\n", output.String())
}

func TestWriteBootstrapAdminOutput_DefaultRemainsHumanReadable(t *testing.T) {
	issued := identity.BootstrapToken{
		Token:     "one-use-secret",
		URL:       "https://control.example/setup#token=one-use-secret",
		ExpiresAt: time.Date(2026, 8, 8, 18, 0, 0, 0, time.UTC),
	}
	var output bytes.Buffer
	require.NoError(t, writeBootstrapAdminOutput(&output, issued, false))
	assert.Contains(t, output.String(), "Bootstrap setup URL")
	assert.Contains(t, output.String(), issued.URL)
}
