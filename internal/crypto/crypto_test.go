package crypto_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
)

func testKey() string {
	// 32 bytes = 64 hex chars
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func differentKey() string {
	return "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
}

func TestNewEncryptor_Valid(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	assert.NotNil(t, enc)
}

func TestNewEncryptor_EmptyKey(t *testing.T) {
	enc, err := crypto.NewEncryptor("")
	require.NoError(t, err)
	assert.Nil(t, enc, "empty key should return nil (encryption disabled)")
}

func TestNewEncryptor_InvalidHex(t *testing.T) {
	_, err := crypto.NewEncryptor("not-hex")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid encryption key")
}

func TestNewEncryptor_WrongLength(t *testing.T) {
	// 16 bytes instead of 32
	shortKey := hex.EncodeToString(make([]byte, 16))
	_, err := crypto.NewEncryptor(shortKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be 32 bytes")
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	plaintext := "my secret passphrase"
	ciphertext, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ciphertext, "enc:v1:"))
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := enc.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecrypt_EmptyString(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	ciphertext, err := enc.Encrypt("")
	require.NoError(t, err)
	assert.Equal(t, "", ciphertext, "empty string should pass through unchanged")
}

func TestEncrypt_DifferentNonces(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	ct1, err := enc.Encrypt("same data")
	require.NoError(t, err)

	ct2, err := enc.Encrypt("same data")
	require.NoError(t, err)

	assert.NotEqual(t, ct1, ct2, "encrypting the same data should produce different ciphertexts due to random nonces")
}

func TestDecrypt_WrongKey(t *testing.T) {
	enc1, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	enc2, err := crypto.NewEncryptor(differentKey())
	require.NoError(t, err)

	ciphertext, err := enc1.Encrypt("secret")
	require.NoError(t, err)

	_, err = enc2.Decrypt(ciphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt")
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	ciphertext, err := enc.Encrypt("secret")
	require.NoError(t, err)

	// Tamper with the base64 data (flip some chars after the prefix)
	tampered := ciphertext[:len("enc:v1:")+5] + "XXXX" + ciphertext[len("enc:v1:")+9:]

	_, err = enc.Decrypt(tampered)
	assert.Error(t, err)
}

func TestDecrypt_PlaintextPassthrough(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	// Values without the enc:v1: prefix should be returned unchanged (pre-migration data)
	result, err := enc.Decrypt("plain text value")
	require.NoError(t, err)
	assert.Equal(t, "plain text value", result)
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	_, err = enc.Decrypt("enc:v1:not-valid-base64!!!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode ciphertext")
}

func TestDecrypt_TooShortCiphertext(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	// enc:v1: followed by a very short base64 value (less than nonce size)
	_, err = enc.Decrypt("enc:v1:AA==")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestNilEncryptor_Passthrough(t *testing.T) {
	// nil encryptor means encryption is disabled
	var enc *crypto.Encryptor

	ct, err := enc.Encrypt("hello")
	require.NoError(t, err)
	assert.Equal(t, "hello", ct)

	pt, err := enc.Decrypt("hello")
	require.NoError(t, err)
	assert.Equal(t, "hello", pt)
}
