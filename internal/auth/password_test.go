package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("my-password")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, "my-password", hash)
}

func TestHashPassword_UniqueSalts(t *testing.T) {
	hash1, err := HashPassword("same-password")
	require.NoError(t, err)
	hash2, err := HashPassword("same-password")
	require.NoError(t, err)
	assert.NotEqual(t, hash1, hash2, "same password should produce different hashes due to salt")
}

func TestVerifyPassword_Correct(t *testing.T) {
	hash, err := HashPassword("my-password")
	require.NoError(t, err)
	assert.True(t, VerifyPassword("my-password", hash))
}

func TestVerifyPassword_Wrong(t *testing.T) {
	hash, err := HashPassword("my-password")
	require.NoError(t, err)
	assert.False(t, VerifyPassword("wrong-password", hash))
}

func TestVerifyPassword_EmptyPassword(t *testing.T) {
	hash, err := HashPassword("my-password")
	require.NoError(t, err)
	assert.False(t, VerifyPassword("", hash))
}

func TestDummyHash(t *testing.T) {
	assert.NotEmpty(t, DummyHash)
	// DummyHash should be a valid bcrypt hash that doesn't match real passwords
	assert.False(t, VerifyPassword("real-password", DummyHash))
}
