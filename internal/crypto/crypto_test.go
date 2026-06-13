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

// WS5 #8 — AES-GCM AAD binds an at-rest secret to its row context.

func TestEncryptWithContext_AADBindsContext(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	aadA := crypto.SecretAAD("01HDEVICEA", "01HACTIONA", "luks")
	aadB := crypto.SecretAAD("01HDEVICEB", "01HACTIONA", "luks") // different device

	ct, err := enc.EncryptWithContext("super-secret", aadA)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ct, "enc:v2:"), "AAD-bound ciphertext uses the v2 prefix")

	// Correct AAD round-trips.
	pt, err := enc.DecryptWithContext(ct, aadA)
	require.NoError(t, err)
	assert.Equal(t, "super-secret", pt)

	// Wrong AAD (a different row context) must fail to open — the secret is
	// bound to its row and cannot be relocated.
	_, err = enc.DecryptWithContext(ct, aadB)
	require.Error(t, err, "a secret sealed for one context must not open under another")
}

func TestDecryptWithContext_ByteTamperedFails(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	aad := crypto.SecretAAD("01HDEV", "01HACT", "lps")

	ct, err := enc.EncryptWithContext("rotate-me", aad)
	require.NoError(t, err)

	// Flip a mid-string char of the base64 body — GCM integrity must reject.
	body := strings.TrimPrefix(ct, "enc:v2:")
	b := []byte(body)
	idx := len(b) / 2
	if b[idx] == 'A' {
		b[idx] = 'B'
	} else {
		b[idx] = 'A'
	}
	tampered := "enc:v2:" + string(b)
	_, err = enc.DecryptWithContext(tampered, aad)
	require.Error(t, err, "a byte-tampered ciphertext must fail GCM integrity")
}

func TestDecryptWithContext_LegacyV1StillDecrypts(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	// A legacy row was sealed with the nil-AAD Encrypt (enc:v1).
	legacy, err := enc.Encrypt("old-secret")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(legacy, "enc:v1:"))

	// DecryptWithContext must still open it (migration is non-breaking; no
	// backfill). The aad is ignored for v1 values.
	pt, err := enc.DecryptWithContext(legacy, crypto.SecretAAD("any", "any", "luks"))
	require.NoError(t, err)
	assert.Equal(t, "old-secret", pt)
}

func TestDecryptWithContext_PlaintextPassthrough(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	pt, err := enc.DecryptWithContext("not-encrypted", crypto.SecretAAD("d", "a", "luks"))
	require.NoError(t, err)
	assert.Equal(t, "not-encrypted", pt)
}

func TestDecryptWithContext_WrongKeyFails(t *testing.T) {
	encA, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	encB, err := crypto.NewEncryptor(differentKey())
	require.NoError(t, err)
	aad := crypto.SecretAAD("d", "a", "luks")

	ct, err := encA.EncryptWithContext("x", aad)
	require.NoError(t, err)
	_, err = encB.DecryptWithContext(ct, aad)
	require.Error(t, err, "a different key must not open the ciphertext")
}
