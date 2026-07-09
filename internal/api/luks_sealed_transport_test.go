package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// CHARTER — sealed LUKS passphrase transport (spec 25, SERVER side).
//
// The agent seals each managed LUKS passphrase to the control X25519 key
// (the SAME keypair LPS uses, distinct HKDF info/AAD); the gateway relays
// opaque bytes; ProxyStoreLuksKey unseals at receipt and re-encrypts with
// the at-rest path. An unsealable blob — tampered, wrong key, wrong
// context, or sealed under the LPS domain — is rejected with
// InvalidArgument and appends no event; a nil keypair fails closed.

// TestProxyStoreLuksKey_SealedRoundTrip covers spec 25 AC 2 end-to-end: the
// agent-sealed passphrase unseals at control, re-encrypts at rest, and
// decrypts back to the original under the at-rest AAD.
func TestProxyStoreLuksKey_SealedRoundTrip(t *testing.T) {
	h, st, enc, pub, _ := newLpsHandler(t)
	ctx := context.Background()
	deviceID := testutil.CreateTestDevice(t, st, "luks-seal-host")
	actionID := testutil.NewID()
	const passphrase = "disk-Passphrase-0riginal-42"

	sealed, err := sdkcrypto.SealLuksPassphrase(pub, passphrase, deviceID, actionID)
	require.NoError(t, err)

	resp, err := h.ProxyStoreLuksKey(ctx, connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId:         deviceID,
		ActionId:         actionID,
		DevicePath:       "/dev/sda2",
		SealedPassphrase: sealed,
		RotationReason:   pm.RotationReason_ROTATION_REASON_INITIAL,
	}))
	require.NoError(t, err)
	require.True(t, resp.Msg.Success)

	current, err := st.Repos().Luks.ListCurrent(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, current, 1)
	assert.Equal(t, "/dev/sda2", current[0].DevicePath)
	dec, err := enc.DecryptWithContext(current[0].Passphrase, crypto.SecretAAD(deviceID, actionID, "luks"))
	require.NoError(t, err)
	assert.Equal(t, passphrase, dec, "stored passphrase must decrypt to the agent's original")
}

// TestProxyStoreLuksKey_RejectsUnsealable covers spec 25 AC 3: tampered,
// wrong-key, or wrong-context blobs are rejected with InvalidArgument and no
// luks_key event is appended.
func TestProxyStoreLuksKey_RejectsUnsealable(t *testing.T) {
	h, st, _, pub, _ := newLpsHandler(t)
	ctx := context.Background()
	deviceID := testutil.CreateTestDevice(t, st, "luks-reject-host")
	otherDevice := testutil.CreateTestDevice(t, st, "luks-other-host")
	actionID := testutil.NewID()

	good, err := sdkcrypto.SealLuksPassphrase(pub, "pw-secret", deviceID, actionID)
	require.NoError(t, err)

	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xFF

	otherPriv, err := sdkcrypto.GenerateX25519()
	require.NoError(t, err)
	wrongKey, err := sdkcrypto.SealLuksPassphrase(otherPriv.PublicKey(), "pw-secret", deviceID, actionID)
	require.NoError(t, err)

	// Sealed for another device: valid blob, wrong AAD context on open.
	wrongDevice, err := sdkcrypto.SealLuksPassphrase(pub, "pw-secret", otherDevice, actionID)
	require.NoError(t, err)
	wrongAction, err := sdkcrypto.SealLuksPassphrase(pub, "pw-secret", deviceID, testutil.NewID())
	require.NoError(t, err)

	cases := map[string][]byte{
		"tampered":     tampered,
		"wrong key":    wrongKey,
		"wrong device": wrongDevice,
		"wrong action": wrongAction,
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := h.ProxyStoreLuksKey(ctx, connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
				DeviceId:         deviceID,
				ActionId:         actionID,
				DevicePath:       "/dev/sda2",
				SealedPassphrase: blob,
				RotationReason:   pm.RotationReason_ROTATION_REASON_INITIAL,
			}))
			require.Error(t, err)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
			// The rejection must not echo secret material or the blob.
			assert.NotContains(t, err.Error(), "pw-secret")
		})
	}

	events, err := st.LoadStreamByType(ctx, "luks_key", 100, 0)
	require.NoError(t, err)
	assert.Empty(t, events, "a rejected unseal must append no event")
}

// TestProxyStoreLuksKey_RejectsCrossDomainBlob covers spec 25 AC 4: a blob
// sealed under the LPS domain — even with a byte-identical AAD (username
// "luks") — must not open in the LUKS store path.
func TestProxyStoreLuksKey_RejectsCrossDomainBlob(t *testing.T) {
	h, st, _, pub, _ := newLpsHandler(t)
	ctx := context.Background()
	deviceID := testutil.CreateTestDevice(t, st, "luks-xdomain-host")
	actionID := testutil.NewID()

	lpsBlob, err := sdkcrypto.SealLpsPassword(pub, "pw-secret", deviceID, actionID, "luks")
	require.NoError(t, err)

	_, err = h.ProxyStoreLuksKey(ctx, connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId:         deviceID,
		ActionId:         actionID,
		DevicePath:       "/dev/sda2",
		SealedPassphrase: lpsBlob,
		RotationReason:   pm.RotationReason_ROTATION_REASON_INITIAL,
	}))
	require.Error(t, err, "an LPS-domain blob must not unseal in the LUKS store path")
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	events, err := st.LoadStreamByType(ctx, "luks_key", 100, 0)
	require.NoError(t, err)
	assert.Empty(t, events)
}

// TestProxyStoreLuksKey_NilKeypairFailsClosed pins that a handler without a
// configured keypair refuses the store rather than accepting bytes it cannot
// open (no cleartext fallback path exists to fall back to).
func TestProxyStoreLuksKey_NilKeypairFailsClosed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	deviceID := testutil.CreateTestDevice(t, st, "luks-nokey-host")

	_, err := h.ProxyStoreLuksKey(context.Background(), connect.NewRequest(&pm.InternalStoreLuksKeyRequest{
		DeviceId:         deviceID,
		ActionId:         testutil.NewID(),
		DevicePath:       "/dev/sda2",
		SealedPassphrase: make([]byte, 61),
		RotationReason:   pm.RotationReason_ROTATION_REASON_INITIAL,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))

	events, err := st.LoadStreamByType(context.Background(), "luks_key", 100, 0)
	require.NoError(t, err)
	assert.Empty(t, events, "no event may be appended without an unseal")
}
