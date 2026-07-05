package crypto_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
)

// Spec 19 stage A — per-user PII envelope encryption. A random 32-byte
// DEK per user, KEK-wrapped at rest; PII fields (tagged pii:"true" on
// the typed payload structs) are sealed under the subject user's DEK
// with an AAD binding user + field, so ciphertext cannot be relocated
// across users or across fields.

const userA = "01JUSERAAAAAAAAAAAAAAAAAAA"
const userB = "01JUSERBBBBBBBBBBBBBBBBBBB"

func newKEK(t *testing.T) *crypto.Encryptor {
	t.Helper()
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)
	return enc
}

func TestGenerateWrappedDEK_RoundTrip(t *testing.T) {
	kek := newKEK(t)

	wrapped, err := crypto.GenerateWrappedDEK(kek, userA)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(wrapped, "enc:v1:"),
		"the wrapped DEK is stored in the single AAD-bound at-rest format")

	dek, err := crypto.UnwrapDEK(kek, userA, wrapped)
	require.NoError(t, err)
	require.NotNil(t, dek)

	// The wrap is bound to the owning user: another user's id must not
	// unwrap it (a swapped user_encryption_keys row must not decrypt).
	_, err = crypto.UnwrapDEK(kek, userB, wrapped)
	require.Error(t, err, "a DEK wrapped for one user must not unwrap under another")
}

func TestGenerateWrappedDEK_Unique(t *testing.T) {
	kek := newKEK(t)
	w1, err := crypto.GenerateWrappedDEK(kek, userA)
	require.NoError(t, err)
	w2, err := crypto.GenerateWrappedDEK(kek, userA)
	require.NoError(t, err)
	assert.NotEqual(t, w1, w2, "every mint must produce fresh random key material")
}

func TestGenerateWrappedDEK_NilKEKRefused(t *testing.T) {
	_, err := crypto.GenerateWrappedDEK(nil, userA)
	require.Error(t, err,
		"minting a DEK without a KEK would persist unprotected key material — fail closed")
}

func TestDEK_SealOpenField(t *testing.T) {
	kek := newKEK(t)
	wrapped, err := crypto.GenerateWrappedDEK(kek, userA)
	require.NoError(t, err)
	dek, err := crypto.UnwrapDEK(kek, userA, wrapped)
	require.NoError(t, err)

	ct, err := dek.SealField("alice@example.com", "email")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ct, "pii:v1:"),
		"sealed PII carries its own distinct prefix so projectors can tell ciphertext from legacy plaintext")
	assert.NotContains(t, ct, "alice", "plaintext must not survive into the sealed form")

	pt, err := dek.OpenField(ct, "email")
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", pt)

	// Field binding: the same user's ciphertext must not open under a
	// different field name (no cross-field relocation).
	_, err = dek.OpenField(ct, "display_name")
	require.Error(t, err, "PII sealed for one field must not open as another")
}

func TestDEK_CrossUserIsolation(t *testing.T) {
	kek := newKEK(t)
	wa, err := crypto.GenerateWrappedDEK(kek, userA)
	require.NoError(t, err)
	wb, err := crypto.GenerateWrappedDEK(kek, userB)
	require.NoError(t, err)
	dekA, err := crypto.UnwrapDEK(kek, userA, wa)
	require.NoError(t, err)
	dekB, err := crypto.UnwrapDEK(kek, userB, wb)
	require.NoError(t, err)

	ct, err := dekA.SealField("alice@example.com", "email")
	require.NoError(t, err)
	_, err = dekB.OpenField(ct, "email")
	require.Error(t, err, "one user's PII must not open under another user's DEK")
}

func TestDEK_EmptyFieldPassthrough(t *testing.T) {
	kek := newKEK(t)
	wrapped, err := crypto.GenerateWrappedDEK(kek, userA)
	require.NoError(t, err)
	dek, err := crypto.UnwrapDEK(kek, userA, wrapped)
	require.NoError(t, err)

	ct, err := dek.SealField("", "email")
	require.NoError(t, err)
	assert.Equal(t, "", ct, "empty optional PII fields stay empty (omitempty wire compat)")

	pt, err := dek.OpenField("", "email")
	require.NoError(t, err)
	assert.Equal(t, "", pt)
}

func TestDEK_OpenLegacyPlaintextPassthrough(t *testing.T) {
	// Events appended BEFORE envelope encryption carry plaintext PII.
	// The projector must keep decoding them (beta stance documents no
	// backfill for the test env), so a non-pii-prefixed value passes
	// through unchanged.
	kek := newKEK(t)
	wrapped, err := crypto.GenerateWrappedDEK(kek, userA)
	require.NoError(t, err)
	dek, err := crypto.UnwrapDEK(kek, userA, wrapped)
	require.NoError(t, err)

	pt, err := dek.OpenField("legacy-plain@example.com", "email")
	require.NoError(t, err)
	assert.Equal(t, "legacy-plain@example.com", pt)
}

func TestDEK_TamperedFieldFails(t *testing.T) {
	kek := newKEK(t)
	wrapped, err := crypto.GenerateWrappedDEK(kek, userA)
	require.NoError(t, err)
	dek, err := crypto.UnwrapDEK(kek, userA, wrapped)
	require.NoError(t, err)

	ct, err := dek.SealField("alice@example.com", "email")
	require.NoError(t, err)
	body := strings.TrimPrefix(ct, "pii:v1:")
	b := []byte(body)
	if b[len(b)/2] == 'A' {
		b[len(b)/2] = 'B'
	} else {
		b[len(b)/2] = 'A'
	}
	_, err = dek.OpenField("pii:v1:"+string(b), "email")
	require.Error(t, err)
}

func TestUnwrapDEK_CorruptWrapFails(t *testing.T) {
	kek := newKEK(t)
	// A present-but-unwrappable DEK row (wrong KEK / bit rot) is a FAULT,
	// not the graceful erased state (spec 19 AC 10) — it must error.
	_, err := crypto.UnwrapDEK(kek, userA, "enc:v1:Y29ycnVwdGVkY29ycnVwdGVk")
	require.Error(t, err)

	otherKEK, err2 := crypto.NewEncryptor(differentKey())
	require.NoError(t, err2)
	wrapped, err2 := crypto.GenerateWrappedDEK(otherKEK, userA)
	require.NoError(t, err2)
	_, err = crypto.UnwrapDEK(kek, userA, wrapped)
	require.Error(t, err, "a DEK wrapped under a different KEK must not unwrap")
}
