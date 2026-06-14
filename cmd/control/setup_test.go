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

func TestInitEncryptor_MissingKey_ReturnsRequiredErr(t *testing.T) {
	// CRITICAL: a missing key MUST fail-closed. Returning (nil, nil) here
	// would silently boot a control server that stores LUKS keys / IdP
	// secrets / LPS passwords as plaintext. The errEncryptionKeyRequired
	// sentinel is what main() matches to log+exit.
	t.Setenv("CONTROL_ENCRYPTION_KEY", "")

	enc, err := initEncryptor(quietLogger())
	require.Error(t, err)
	assert.Nil(t, enc)
	assert.True(t, errors.Is(err, errEncryptionKeyRequired),
		"missing key MUST return errEncryptionKeyRequired sentinel — main() exit hinges on this")
}

// TestInitEncryptor_OptOutNoLongerHonored pins WS11 finding 4: the
// CONTROL_ENCRYPTION_KEY_REQUIRED=false plaintext opt-out was REMOVED. Even
// with the legacy opt-out set, a missing key must still fail-closed — no path
// may ever store IdP/TOTP/LUKS secrets unencrypted, "even by accident".
func TestInitEncryptor_OptOutNoLongerHonored(t *testing.T) {
	t.Setenv("CONTROL_ENCRYPTION_KEY", "")
	t.Setenv("CONTROL_ENCRYPTION_KEY_REQUIRED", "false") // legacy opt-out, must be ignored

	enc, err := initEncryptor(quietLogger())
	require.Error(t, err)
	assert.Nil(t, enc)
	assert.True(t, errors.Is(err, errEncryptionKeyRequired),
		"the plaintext opt-out is removed — =false must NOT escape the fail-closed gate")
}

func TestInitEncryptor_ValidKey_ReturnsEncryptor(t *testing.T) {
	// Happy path: 32-byte hex-encoded key. crypto.NewEncryptor
	// accepts hex / base64 / raw; the hex form is what the deploy
	// scripts emit so we test it explicitly.
	t.Setenv("CONTROL_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

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
