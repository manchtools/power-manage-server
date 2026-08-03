package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
)

// TestSecretAADForRow_BindsRowDiscriminator proves the at-rest AAD binds the
// per-row discriminator, so a ciphertext sealed for one sibling row (an LPS
// username, a LUKS device_path) cannot be relocated onto another row sharing
// the same (device, action) and opened under its context. The positive control
// confirms the very same row still opens.
func TestSecretAADForRow_BindsRowDiscriminator(t *testing.T) {
	enc, err := crypto.NewEncryptor(testKey())
	require.NoError(t, err)

	const (
		deviceID = "01HDEVICEA"
		actionID = "01HACTIONA"
	)

	t.Run("LPS username is bound", func(t *testing.T) {
		const secret = "administrator-password"
		ct, err := enc.EncryptWithContext(secret, crypto.SecretAADForRow(deviceID, actionID, "lps", "administrator"))
		require.NoError(t, err)

		pt, err := enc.DecryptWithContext(ct, crypto.SecretAADForRow(deviceID, actionID, "lps", "administrator"))
		require.NoError(t, err, "the same row must open its own ciphertext")
		assert.Equal(t, secret, pt)

		_, err = enc.DecryptWithContext(ct, crypto.SecretAADForRow(deviceID, actionID, "lps", "svc-backup"))
		assert.Error(t, err,
			"a ciphertext sealed for one username must not open under a sibling username sharing the device and action")
	})

	t.Run("LUKS device_path is bound", func(t *testing.T) {
		const secret = "a-real-luks-passphrase"
		ct, err := enc.EncryptWithContext(secret, crypto.SecretAADForRow(deviceID, actionID, "luks", "/dev/sda2"))
		require.NoError(t, err)

		pt, err := enc.DecryptWithContext(ct, crypto.SecretAADForRow(deviceID, actionID, "luks", "/dev/sda2"))
		require.NoError(t, err, "the same row must open its own ciphertext")
		assert.Equal(t, secret, pt)

		_, err = enc.DecryptWithContext(ct, crypto.SecretAADForRow(deviceID, actionID, "luks", "/dev/sdb3"))
		assert.Error(t, err,
			"a ciphertext sealed for one device_path must not open under a sibling device_path sharing the device and action")
	})

	// The four-segment row form must not collide with the three-segment
	// SecretAAD form for the same device/action/type, or a discriminator-less
	// legacy ciphertext would open a row-bound context and vice versa.
	t.Run("row form does not collide with the legacy three-segment form", func(t *testing.T) {
		ct, err := enc.EncryptWithContext("secret", crypto.SecretAADForRow(deviceID, actionID, "lps", "administrator"))
		require.NoError(t, err)
		_, err = enc.DecryptWithContext(ct, crypto.SecretAAD(deviceID, actionID, "lps"))
		assert.Error(t, err, "a row-bound ciphertext must not open under the discriminator-less AAD")
	})
}
