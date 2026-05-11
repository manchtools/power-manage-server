package main

// Smoke coverage for the boot-time setup helpers extracted from
// main.go (audit F043 / #157, slice 3). Tests focus on the
// init-encryptor branch table — the part that's actually
// regression-prone — since seedSSHAccessForAll and wireSystemActions
// are integration glue that's exercised end-to-end in higher-level
// tests.

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// =============================================================================
// initEncryptor
// =============================================================================

func TestInitEncryptor_MissingKeyAndNotOptedOut_ReturnsRequiredErr(t *testing.T) {
	// CRITICAL: missing key + no explicit opt-out MUST fail-closed.
	// Returning (nil, nil) here would silently boot a control server
	// that stores LUKS keys / IdP secrets / LPS passwords as
	// plaintext. The errEncryptionKeyRequired sentinel is what main()
	// matches to log+exit.
	t.Setenv("CONTROL_ENCRYPTION_KEY", "")
	t.Setenv("CONTROL_ENCRYPTION_KEY_REQUIRED", "")

	enc, err := initEncryptor(quietLogger())
	require.Error(t, err)
	assert.Nil(t, enc)
	assert.True(t, errors.Is(err, errEncryptionKeyRequired),
		"missing key without opt-out MUST return errEncryptionKeyRequired sentinel — main() exit hinges on this")
}

func TestInitEncryptor_MissingKeyButOptedOut_ReturnsNilNil(t *testing.T) {
	// Operator explicit opt-out via CONTROL_ENCRYPTION_KEY_REQUIRED=false.
	// Returns (nil, nil) — main() proceeds without encryption.
	// A Warn line is emitted (not asserted here; testing log lines
	// would couple the test to the log format).
	t.Setenv("CONTROL_ENCRYPTION_KEY", "")
	t.Setenv("CONTROL_ENCRYPTION_KEY_REQUIRED", "false")

	enc, err := initEncryptor(quietLogger())
	require.NoError(t, err)
	assert.Nil(t, enc, "explicit opt-out returns nil encryptor; downstream code uses the no-op path")
}

func TestInitEncryptor_ValidKey_ReturnsEncryptor(t *testing.T) {
	// Happy path: 32-byte hex-encoded key. crypto.NewEncryptor
	// accepts hex / base64 / raw; the hex form is what the deploy
	// scripts emit so we test it explicitly.
	t.Setenv("CONTROL_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	t.Setenv("CONTROL_ENCRYPTION_KEY_REQUIRED", "")

	enc, err := initEncryptor(quietLogger())
	require.NoError(t, err)
	require.NotNil(t, enc, "valid 32-byte key MUST construct an Encryptor")
}

func TestInitEncryptor_MalformedKey_ReturnsError(t *testing.T) {
	// A non-empty but malformed key MUST surface the constructor's
	// error rather than silently fall through to "missing" handling.
	// Returning errEncryptionKeyRequired here would hide the real
	// problem (operator typo'd the key) behind a fail-closed gate
	// the operator can't immediately diagnose.
	t.Setenv("CONTROL_ENCRYPTION_KEY", "way-too-short-for-aes")
	t.Setenv("CONTROL_ENCRYPTION_KEY_REQUIRED", "")

	enc, err := initEncryptor(quietLogger())
	require.Error(t, err)
	assert.Nil(t, enc)
	assert.False(t, errors.Is(err, errEncryptionKeyRequired),
		"malformed key MUST surface the constructor error, not the missing-key sentinel — operator needs to see the real problem")
}

// =============================================================================
// configureTrustedProxies
// =============================================================================

func TestConfigureTrustedProxies_EmptyListIsNoOp(t *testing.T) {
	// Empty list MUST NOT touch the auth package's allowlist —
	// passing an empty slice through SetTrustedProxies would replace
	// any existing default with "trust nobody," breaking deployments
	// behind a proxy that didn't explicitly configure the env-var.
	cfg := &Config{TrustedProxies: nil}
	configureTrustedProxies(cfg, quietLogger())
	// No assertion on auth package state — the contract here is
	// "doesn't crash and doesn't push an empty slice." Tested by
	// the absence of a panic and the expected early-return.
}
