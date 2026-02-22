package totp

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey("TestIssuer", "user@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, key.Secret())
	assert.Contains(t, key.URL(), "otpauth://totp/")
	assert.Contains(t, key.URL(), "TestIssuer")
	assert.Contains(t, key.URL(), "user@example.com")
}

func TestGenerateKey_DefaultIssuer(t *testing.T) {
	key, err := GenerateKey("", "user@example.com")
	require.NoError(t, err)
	assert.Contains(t, key.URL(), DefaultIssuer)
}

func TestValidateCode_Valid(t *testing.T) {
	key, err := GenerateKey("Test", "user@example.com")
	require.NoError(t, err)

	// Generate a valid code
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	assert.True(t, ValidateCode(code, key.Secret()))
}

func TestValidateCode_Invalid(t *testing.T) {
	key, err := GenerateKey("Test", "user@example.com")
	require.NoError(t, err)

	assert.False(t, ValidateCode("000000", key.Secret()))
	assert.False(t, ValidateCode("123456", key.Secret()))
}

func TestValidateCode_WrongSecret(t *testing.T) {
	key1, err := GenerateKey("Test", "user1@example.com")
	require.NoError(t, err)
	key2, err := GenerateKey("Test", "user2@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(key1.Secret(), time.Now())
	require.NoError(t, err)

	// Code from key1 should not validate against key2
	assert.False(t, ValidateCode(code, key2.Secret()))
}
