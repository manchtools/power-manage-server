package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
)

// TestSecretAADForRow_BindsImmutableRowID proves the at-rest AAD binds the
// per-row discriminator, which is the row's immutable ULID primary key. LPS and
// LUKS keep multiple rotation rows per (device, action, username|device_path):
// the current row plus its history. Each row seals under its OWN row id, so a
// ciphertext sealed for one row cannot be relocated onto a sibling row — even a
// later rotation of the SAME username — and opened under its context. The
// positive controls confirm the very same row still opens.
func TestSecretAADForRow_BindsImmutableRowID(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	const (
		deviceID = "01HDEVICEA"
		actionID = "01HACTIONA"
	)

	t.Run("a ciphertext opens only under its own row id", func(t *testing.T) {
		const rowID = "01HROWCURRENT"
		const secret = "administrator-password"
		ct, err := enc.EncryptWithContext(secret, crypto.SecretAADForRow(deviceID, actionID, "lps", rowID))
		require.NoError(t, err)

		pt, err := enc.DecryptWithContext(ct, crypto.SecretAADForRow(deviceID, actionID, "lps", rowID))
		require.NoError(t, err, "the same row must open its own ciphertext")
		assert.Equal(t, secret, pt)

		_, err = enc.DecryptWithContext(ct, crypto.SecretAADForRow(deviceID, actionID, "lps", "01HROWSIBLING"))
		assert.Error(t, err,
			"a ciphertext sealed for one row must not open under a sibling row id sharing the device and action")
	})

	t.Run("sibling rotation rows for one username are not interchangeable", func(t *testing.T) {
		// Two rotation rows for the SAME LPS username: only the immutable row
		// id differs. Binding to the username alone would leave the two
		// ciphertexts interchangeable, so a DB-level attacker could swap the
		// retired row's ciphertext onto the current row. Binding to the row id
		// does not.
		const currentRow, historicalRow = "01HROWNEW", "01HROWOLD"
		ctOld, err := enc.EncryptWithContext("retired-secret",
			crypto.SecretAADForRow(deviceID, actionID, "lps", historicalRow))
		require.NoError(t, err)

		_, err = enc.DecryptWithContext(ctOld, crypto.SecretAADForRow(deviceID, actionID, "lps", currentRow))
		assert.Error(t, err,
			"a retired rotation row's ciphertext must not open under the current row's context")

		pt, err := enc.DecryptWithContext(ctOld, crypto.SecretAADForRow(deviceID, actionID, "lps", historicalRow))
		require.NoError(t, err, "the retired row must still open under its own id")
		assert.Equal(t, "retired-secret", pt)
	})

	t.Run("LUKS rows bind the row id too", func(t *testing.T) {
		const rowID = "01HLUKSROW"
		const secret = "a-real-luks-passphrase"
		ct, err := enc.EncryptWithContext(secret, crypto.SecretAADForRow(deviceID, actionID, "luks", rowID))
		require.NoError(t, err)

		pt, err := enc.DecryptWithContext(ct, crypto.SecretAADForRow(deviceID, actionID, "luks", rowID))
		require.NoError(t, err, "the same row must open its own ciphertext")
		assert.Equal(t, secret, pt)

		_, err = enc.DecryptWithContext(ct, crypto.SecretAADForRow(deviceID, actionID, "luks", "01HLUKSROWB"))
		assert.Error(t, err,
			"a LUKS ciphertext sealed for one row must not open under a sibling row id")
	})

	// The four-segment row form must not collide with the three-segment
	// SecretAAD form for the same device/action/type, or a discriminator-less
	// ciphertext would open a row-bound context and vice versa.
	t.Run("row form does not collide with the legacy three-segment form", func(t *testing.T) {
		ct, err := enc.EncryptWithContext("secret", crypto.SecretAADForRow(deviceID, actionID, "lps", "01HROWX"))
		require.NoError(t, err)
		_, err = enc.DecryptWithContext(ct, crypto.SecretAAD(deviceID, actionID, "lps"))
		assert.Error(t, err, "a row-bound ciphertext must not open under the discriminator-less AAD")
	})
}
