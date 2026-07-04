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

// Spec 20 / F-06: ONE at-rest format — AAD-bound AES-256-GCM under
// "enc:v1:". The nil-AAD Encrypt/Decrypt pair is gone; these tests pin
// the surviving contract.

func TestEncryptWithContext_SingleV1Prefix(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	ct, err := enc.EncryptWithContext("secret", crypto.RowAAD("01HROW", crypto.PurposeTOTPSecret))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ct, "enc:v1:"),
		"the single AAD-bound format carries the enc:v1 prefix, got %q", ct)
	assert.NotContains(t, ct, "enc:v2", "no second prefix exists anymore")
}

func TestEncryptWithContext_EmptyAADRefused(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	_, err = enc.EncryptWithContext("secret", nil)
	require.Error(t, err, "encrypting without an AAD context must be refused (F-06 anti-regression)")
	_, err = enc.EncryptWithContext("secret", []byte{})
	require.Error(t, err)
}

func TestEncryptWithContext_EmptyPlaintextPassthrough(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	ct, err := enc.EncryptWithContext("", crypto.RowAAD("01HROW", crypto.PurposeTOTPSecret))
	require.NoError(t, err)
	assert.Equal(t, "", ct, "empty secrets round-trip as empty, never as ciphertext")
}

func TestEncryptWithContext_DifferentNonces(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	aad := crypto.RowAAD("01HROW", crypto.PurposeIdPClientSecret)

	a, err := enc.EncryptWithContext("same-plaintext", aad)
	require.NoError(t, err)
	b, err := enc.EncryptWithContext("same-plaintext", aad)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "random nonces: identical plaintext must not produce identical ciphertext")
}

func TestEncryptWithContext_AADBindsContext(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	aadA := crypto.SecretAAD("01HDEVICEA", "01HACTIONA", "luks")
	aadB := crypto.SecretAAD("01HDEVICEB", "01HACTIONA", "luks") // different device

	ct, err := enc.EncryptWithContext("super-secret", aadA)
	require.NoError(t, err)

	// Correct AAD round-trips.
	pt, err := enc.DecryptWithContext(ct, aadA)
	require.NoError(t, err)
	assert.Equal(t, "super-secret", pt)

	// Wrong AAD (a different row context) must fail to open — the secret is
	// bound to its row and cannot be relocated.
	_, err = enc.DecryptWithContext(ct, aadB)
	require.Error(t, err, "a secret sealed for one context must not open under another")
}

func TestRowAAD_BindsRowAndPurpose(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	ct, err := enc.EncryptWithContext("client-secret", crypto.RowAAD("01HIDPA", crypto.PurposeIdPClientSecret))
	require.NoError(t, err)

	// Different owning row: cross-provider ciphertext swap must fail.
	_, err = enc.DecryptWithContext(ct, crypto.RowAAD("01HIDPB", crypto.PurposeIdPClientSecret))
	require.Error(t, err, "a ciphertext relocated to another provider row must not open")

	// Same row, different purpose: cross-purpose reuse must fail.
	_, err = enc.DecryptWithContext(ct, crypto.RowAAD("01HIDPA", crypto.PurposeTOTPSecret))
	require.Error(t, err, "a ciphertext reused under another purpose must not open")
}

func TestDecryptWithContext_ByteTamperedFails(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	aad := crypto.SecretAAD("01HDEV", "01HACT", "lps")

	ct, err := enc.EncryptWithContext("rotate-me", aad)
	require.NoError(t, err)

	// Flip a mid-string char of the base64 body — GCM integrity must reject.
	body := strings.TrimPrefix(ct, "enc:v1:")
	b := []byte(body)
	idx := len(b) / 2
	if b[idx] == 'A' {
		b[idx] = 'B'
	} else {
		b[idx] = 'A'
	}
	tampered := "enc:v1:" + string(b)
	_, err = enc.DecryptWithContext(tampered, aad)
	require.Error(t, err, "a byte-tampered ciphertext must fail GCM integrity")
}

// Spec 20 AC 5: the legacy formats are GONE. A pre-rename "enc:v2" blob
// (or any other enc:* tag) errors loudly instead of being mis-read —
// the beta Path-A migration is a reprovision.
func TestDecryptWithContext_RetiredFormatsFailLoudly(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	aad := crypto.RowAAD("01HROW", crypto.PurposeTOTPSecret)

	for _, legacy := range []string{
		"enc:v2:QUFBQUFBQUFBQUFBQUFBQQ==", // pre-rename AAD format tag
		"enc:v3:whatever",                 // unknown future tag
	} {
		_, err := enc.DecryptWithContext(legacy, aad)
		require.Error(t, err, "retired/unknown format %q must fail loudly, never pass through", legacy)
		assert.NotContains(t, err.Error(), "QUFBQUFB", "the error must not echo ciphertext bytes")
	}
}

// An OLD nil-AAD blob carried the same "enc:v1:" tag. Post-spec-20 it
// parses as the AAD-bound format and fails GCM authentication (the seal
// used no AAD) — erroring loudly rather than silently mis-decrypting,
// which is the documented reprovision-required behavior. Sealing under
// one AAD and opening under another is the same failure class (AAD
// mismatch at Open), since the nil-AAD seal path no longer exists to
// construct a true legacy blob.
func TestDecryptWithContext_LegacyNilAADv1FailsAuth(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	ct, err := enc.EncryptWithContext("old-secret", []byte("legacy-nil-aad-stand-in"))
	require.NoError(t, err)
	_, err = enc.DecryptWithContext(ct, crypto.RowAAD("01HROW", crypto.PurposeTOTPSecret))
	require.Error(t, err)
}

func TestDecryptWithContext_PlaintextPassthrough(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	pt, err := enc.DecryptWithContext("not-encrypted", crypto.SecretAAD("d", "a", "luks"))
	require.NoError(t, err)
	assert.Equal(t, "not-encrypted", pt)

	empty, err := enc.DecryptWithContext("", crypto.RowAAD("r", crypto.PurposeTOTPSecret))
	require.NoError(t, err)
	assert.Equal(t, "", empty, "the empty string round-trips (mirrors EncryptWithContext's empty passthrough)")
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

func TestDecryptWithContext_TooShortCiphertext(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	_, err = enc.DecryptWithContext("enc:v1:QQ==", crypto.RowAAD("r", crypto.PurposeTOTPSecret))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDecryptWithContext_InvalidBase64(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	_, err = enc.DecryptWithContext("enc:v1:!!!not-base64!!!", crypto.RowAAD("r", crypto.PurposeTOTPSecret))
	require.Error(t, err)
}

func TestNilEncryptor_Passthrough(t *testing.T) {
	// nil encryptor means encryption is disabled (test setups only —
	// production boot requires the key since WS11).
	var enc *crypto.Encryptor

	ct, err := enc.EncryptWithContext("hello", crypto.RowAAD("r", crypto.PurposeTOTPSecret))
	require.NoError(t, err)
	assert.Equal(t, "hello", ct)

	pt, err := enc.DecryptWithContext("hello", crypto.RowAAD("r", crypto.PurposeTOTPSecret))
	require.NoError(t, err)
	assert.Equal(t, "hello", pt)
}
