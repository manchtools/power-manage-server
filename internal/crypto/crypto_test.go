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
	require.Error(t, err)
	assert.Nil(t, enc)
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

// At-rest secrets use one AAD-bound AES-256-GCM format under "enc:v1:".

func TestEncryptWithContext_SingleV1Prefix(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	ct, err := enc.EncryptWithContext("secret", crypto.RowAAD("01HROW", crypto.PurposeIdPClientSecret))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ct, "enc:v1:"),
		"the single AAD-bound format carries the enc:v1 prefix, got %q", ct)
	assert.NotContains(t, ct, "enc:v2", "no second prefix exists anymore")
}

func TestEncryptWithContext_EmptyAADRefused(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	_, err = enc.EncryptWithContext("secret", nil)
	require.Error(t, err, "encrypting without an AAD context must be refused")
	_, err = enc.EncryptWithContext("secret", []byte{})
	require.Error(t, err)
}

func TestEncryptWithContext_EmptyPlaintext(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	ct, err := enc.EncryptWithContext("", crypto.RowAAD("01HROW", crypto.PurposeIdPClientSecret))
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
	_, err = enc.DecryptWithContext(ct, crypto.RowAAD("01HIDPA", "different-purpose"))
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

// Unknown ciphertext formats fail closed instead of being misread.
func TestDecryptWithContext_RetiredFormatsFailLoudly(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	aad := crypto.RowAAD("01HROW", crypto.PurposeIdPClientSecret)

	for _, legacy := range []string{
		"enc:v2:QUFBQUFBQUFBQUFBQUFBQQ==", // pre-rename AAD format tag
		"enc:v3:whatever",                 // unknown future tag
	} {
		_, err := enc.DecryptWithContext(legacy, aad)
		require.Error(t, err, "retired/unknown format %q must fail loudly, never pass through", legacy)
		assert.NotContains(t, err.Error(), "QUFBQUFB", "the error must not echo ciphertext bytes")
	}
}

// A ciphertext created for a different context fails authentication.
func TestDecryptWithContext_WrongAADFailsAuth(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	ct, err := enc.EncryptWithContext("old-secret", []byte("legacy-nil-aad-stand-in"))
	require.NoError(t, err)
	_, err = enc.DecryptWithContext(ct, crypto.RowAAD("01HROW", crypto.PurposeIdPClientSecret))
	require.Error(t, err)
}

func TestDecryptWithContext_PlaintextRejected(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	_, err = enc.DecryptWithContext("not-encrypted", crypto.SecretAAD("d", "a", "luks"))
	require.Error(t, err)

	empty, err := enc.DecryptWithContext("", crypto.RowAAD("r", crypto.PurposeIdPClientSecret))
	require.NoError(t, err)
	assert.Equal(t, "", empty)
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
	_, err = enc.DecryptWithContext("enc:v1:QQ==", crypto.RowAAD("r", crypto.PurposeIdPClientSecret))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDecryptWithContext_InvalidBase64(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	_, err = enc.DecryptWithContext("enc:v1:!!!not-base64!!!", crypto.RowAAD("r", crypto.PurposeIdPClientSecret))
	require.Error(t, err)
}

// At-rest AAD keeps LUKS and LPS domains separate for the same device/action.
// Transport sealing independently binds direction, message, field, and device.
func TestDecryptWithContext_LuksBlobDoesNotOpenUnderTheLpsDomain(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	const deviceID = "01HDEVICEA"
	const actionID = "01HACTIONA"
	const passphrase = "a-real-luks-passphrase"

	ct, err := enc.EncryptWithContext(passphrase, crypto.SecretAAD(deviceID, actionID, "luks"))
	require.NoError(t, err)

	// Positive control: the LUKS domain still opens it. Without this the
	// negative below would also pass for a ciphertext that opens under NO
	// domain at all.
	pt, err := enc.DecryptWithContext(ct, crypto.SecretAAD(deviceID, actionID, "luks"))
	require.NoError(t, err)
	require.Equal(t, passphrase, pt)

	// Same device, same action, wrong domain — the whole of the separation.
	_, err = enc.DecryptWithContext(ct, crypto.SecretAAD(deviceID, actionID, "lps"))
	require.Error(t, err, "a LUKS passphrase must not open under the LPS domain tag")
}

func TestDecryptWithContext_LpsBlobDoesNotOpenUnderTheLuksDomain(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	const deviceID = "01HDEVICEA"
	const actionID = "01HACTIONA"
	const password = "a-real-lps-password"

	ct, err := enc.EncryptWithContext(password, crypto.SecretAAD(deviceID, actionID, "lps"))
	require.NoError(t, err)

	pt, err := enc.DecryptWithContext(ct, crypto.SecretAAD(deviceID, actionID, "lps"))
	require.NoError(t, err)
	require.Equal(t, password, pt)

	_, err = enc.DecryptWithContext(ct, crypto.SecretAAD(deviceID, actionID, "luks"))
	require.Error(t, err,
		"an LPS password must not open under the LUKS domain tag — a rotated account password surfacing as a "+
			"disk passphrase is the same confusion in the other direction")
}

func TestNilEncryptor_FailsClosed(t *testing.T) {
	var enc *crypto.Encryptor

	_, err := enc.EncryptWithContext("hello", crypto.RowAAD("r", crypto.PurposeIdPClientSecret))
	require.Error(t, err)
	_, err = enc.DecryptWithContext("hello", crypto.RowAAD("r", crypto.PurposeIdPClientSecret))
	require.Error(t, err)
}
