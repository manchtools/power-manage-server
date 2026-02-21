package totp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateBackupCodes(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes()
	require.NoError(t, err)

	assert.Len(t, codes, BackupCodeCount)
	assert.Len(t, hashes, BackupCodeCount)

	// Each code should be 8 hex characters
	for _, code := range codes {
		assert.Len(t, code, BackupCodeLength*2)
	}

	// All codes should be unique
	seen := make(map[string]bool)
	for _, code := range codes {
		assert.False(t, seen[code], "duplicate backup code")
		seen[code] = true
	}
}

func TestVerifyBackupCode_Valid(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes()
	require.NoError(t, err)

	used := make([]bool, len(codes))

	// Verify each code matches its hash
	for i, code := range codes {
		idx := VerifyBackupCode(code, hashes, used)
		assert.Equal(t, i, idx)
	}
}

func TestVerifyBackupCode_Invalid(t *testing.T) {
	_, hashes, err := GenerateBackupCodes()
	require.NoError(t, err)

	used := make([]bool, len(hashes))

	idx := VerifyBackupCode("invalidcode", hashes, used)
	assert.Equal(t, -1, idx)
}

func TestVerifyBackupCode_AlreadyUsed(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes()
	require.NoError(t, err)

	used := make([]bool, len(codes))
	used[0] = true // Mark first code as used

	// First code should no longer work
	idx := VerifyBackupCode(codes[0], hashes, used)
	assert.Equal(t, -1, idx)

	// Second code should still work
	idx = VerifyBackupCode(codes[1], hashes, used)
	assert.Equal(t, 1, idx)
}

func TestVerifyBackupCode_AllUsed(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes()
	require.NoError(t, err)

	used := make([]bool, len(codes))
	for i := range used {
		used[i] = true
	}

	// No codes should work when all are used
	for _, code := range codes {
		idx := VerifyBackupCode(code, hashes, used)
		assert.Equal(t, -1, idx)
	}
}

func TestVerifyBackupCode_WithWhitespace(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes()
	require.NoError(t, err)

	used := make([]bool, len(codes))

	// Code with leading/trailing whitespace should still work
	idx := VerifyBackupCode("  "+codes[0]+"  ", hashes, used)
	assert.Equal(t, 0, idx)
}
