package api_test

import (
	"context"
	"crypto/ecdh"
	"log/slog"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// CHARTER — sealed LPS password transport (spec 18, SERVER side).
//
//   - EnsureLpsKeypair generates exactly one keypair, idempotently and
//     race-safely; the private key is never stored in cleartext.
//   - ProxySyncActions distributes the public key CA-signed so a relaying
//     gateway cannot substitute its own key.
//   - ProxyStoreLpsPasswords unseals the agent-sealed password and re-encrypts
//     it at rest — an unsealable blob is rejected with no event appended, and a
//     nil keypair fails closed.

// TestEnsureLpsKeypair_IdempotentAndConcurrent covers criterion 7: exactly one
// row, the same key on repeat and under concurrency, private key encrypted at
// rest.
func TestEnsureLpsKeypair_IdempotentAndConcurrent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	ctx := context.Background()

	priv1, pub1, err := api.EnsureLpsKeypair(ctx, st, enc)
	require.NoError(t, err)
	require.Len(t, pub1, 32)

	// Idempotent: a second call loads the same key.
	priv2, pub2, err := api.EnsureLpsKeypair(ctx, st, enc)
	require.NoError(t, err)
	assert.Equal(t, pub1, pub2, "public key must be stable across calls")
	assert.True(t, priv1.Equal(priv2), "private key must be stable across calls")

	// Concurrent callers converge on one key.
	const n = 8
	var wg sync.WaitGroup
	pubs := make([][]byte, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, p, e := api.EnsureLpsKeypair(ctx, st, enc)
			pubs[i], errs[i] = p, e
		}()
	}
	wg.Wait()
	for i := range n {
		require.NoError(t, errs[i])
		assert.Equal(t, pub1, pubs[i], "all concurrent callers must see the same key")
	}

	// Exactly one row, and the stored private key is encrypted (the single
	// AAD-bound enc:v1 format, spec 20), never the raw 32 bytes.
	row, err := st.Queries().GetLpsKeypair(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, string(priv1.Bytes()), row.PrivateKeyEnc, "private key stored in cleartext")
	assert.Contains(t, row.PrivateKeyEnc, "enc:v1:", "private key must be AAD-encrypted at rest")

	// A nil encryptor is refused — the key cannot be protected at rest.
	freshDB := testutil.SetupPostgres(t)
	_, _, err = api.EnsureLpsKeypair(ctx, freshDB, nil)
	require.Error(t, err)
}

// newLpsHandler builds an InternalHandler with a real CA signer and a
// bootstrapped LPS keypair, returning the pieces a test needs to act as the
// agent (public key) and to assert at-rest state (encryptor).
func newLpsHandler(t *testing.T) (h *api.InternalHandler, st *store.Store, enc *crypto.Encryptor, pub *ecdh.PublicKey, verifier *verify.ActionVerifier) {
	t.Helper()
	st = testutil.SetupPostgres(t)
	enc = testutil.NewEncryptor(t)
	signer, v := newDispatchTestCA(t)
	h = api.NewInternalHandler(st, enc, slog.Default(), signer)

	priv, pubRaw, err := api.EnsureLpsKeypair(context.Background(), st, enc)
	require.NoError(t, err)
	signedPub, err := api.BuildSignedLpsPublicKey(pubRaw, signer)
	require.NoError(t, err)
	h.SetLpsKeypair(priv, signedPub)

	pub, err = sdkcrypto.ParseX25519PublicKey(pubRaw)
	require.NoError(t, err)
	return h, st, enc, pub, v
}

// TestProxySyncActions_AttachesSignedLpsPublicKey covers criterion 8: the sync
// response carries the public key with a CA signature verifiable under the
// lps-pubkey domain, and a swapped key breaks that signature.
func TestProxySyncActions_AttachesSignedLpsPublicKey(t *testing.T) {
	h, st, _, pub, verifier := newLpsHandler(t)
	deviceID := testutil.CreateTestDevice(t, st, "lps-sync-host")

	resp, err := h.ProxySyncActions(context.Background(), connect.NewRequest(&pm.InternalSyncActionsRequest{
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.LpsPublicKey, "sync response must carry the LPS public key")
	assert.Equal(t, pub.Bytes(), resp.Msg.LpsPublicKey.PublicKey)

	// Verify the signature exactly as the agent would: canonical form under the
	// lps-pubkey domain.
	canonical, err := verify.LpsPublicKeyCanonical(resp.Msg.LpsPublicKey)
	require.NoError(t, err)
	require.NoError(t, verifier.VerifyDomain(verify.LpsPublicKeySignatureDomain, canonical, resp.Msg.LpsPublicKey.Signature),
		"distributed LPS public key must verify under the CA")

	// A gateway swapping the key keeps the signature but breaks verification.
	swapped := &pm.LpsPublicKey{PublicKey: make([]byte, 32), Signature: resp.Msg.LpsPublicKey.Signature}
	sc, err := verify.LpsPublicKeyCanonical(swapped)
	require.NoError(t, err)
	require.Error(t, verifier.VerifyDomain(verify.LpsPublicKeySignatureDomain, sc, swapped.Signature),
		"a substituted key must fail signature verification")
}

// TestLpsSealedTransport_EndToEnd covers criterion 9: a password sealed by the
// SDK primitive to the distributed key round-trips through
// ProxyStoreLpsPasswords and is recoverable (decrypts to the original) from the
// at-rest store.
func TestLpsSealedTransport_EndToEnd(t *testing.T) {
	h, st, enc, pub, _ := newLpsHandler(t)
	ctx := context.Background()

	deviceID := testutil.CreateTestDevice(t, st, "lps-e2e-host")
	actionID := testutil.NewID()
	const username, password = "alice", "R0tated-P@ss!"

	sealed, err := sdkcrypto.SealLpsPassword(pub, password, deviceID, actionID, username)
	require.NoError(t, err)

	_, err = h.ProxyStoreLpsPasswords(ctx, connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
		DeviceId: deviceID,
		ActionId: actionID,
		Rotations: []*pm.LpsPasswordRotation{{
			Username:       username,
			SealedPassword: sealed,
			RotatedAt:      "2026-03-31T12:00:00Z",
			Reason:         pm.RotationReason_ROTATION_REASON_SCHEDULED,
		}},
	}))
	require.NoError(t, err)

	// Recover from the store and decrypt with the at-rest AAD — must equal the
	// original plaintext the agent sealed.
	current, err := st.Repos().Lps.ListCurrent(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, current, 1)
	dec, err := enc.DecryptWithContext(current[0].Password, crypto.SecretAAD(deviceID, actionID, "lps"))
	require.NoError(t, err)
	assert.Equal(t, password, dec, "stored password must decrypt to the agent's original")
}

// TestProxyStoreLpsPasswords_RejectsUnsealable covers criterion 10: a blob that
// does not unseal (tampered, wrong key, or wrong context) is rejected with
// InvalidArgument and appends no lps_password event.
func TestProxyStoreLpsPasswords_RejectsUnsealable(t *testing.T) {
	h, st, _, pub, _ := newLpsHandler(t)
	ctx := context.Background()
	deviceID := testutil.CreateTestDevice(t, st, "lps-reject-host")
	actionID := testutil.NewID()

	good, err := sdkcrypto.SealLpsPassword(pub, "pw", deviceID, actionID, "alice")
	require.NoError(t, err)

	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xFF

	otherPriv, err := sdkcrypto.GenerateX25519()
	require.NoError(t, err)
	wrongKey, err := sdkcrypto.SealLpsPassword(otherPriv.PublicKey(), "pw", deviceID, actionID, "alice")
	require.NoError(t, err)

	cases := map[string]*pm.LpsPasswordRotation{
		"tampered":   {Username: "alice", SealedPassword: tampered, RotatedAt: "2026-03-31T12:00:00Z", Reason: pm.RotationReason_ROTATION_REASON_SCHEDULED},
		"wrong key":  {Username: "alice", SealedPassword: wrongKey, RotatedAt: "2026-03-31T12:00:00Z", Reason: pm.RotationReason_ROTATION_REASON_SCHEDULED},
		"wrong user": {Username: "mallory", SealedPassword: good, RotatedAt: "2026-03-31T12:00:00Z", Reason: pm.RotationReason_ROTATION_REASON_SCHEDULED},
	}
	for name, rot := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := h.ProxyStoreLpsPasswords(ctx, connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
				DeviceId:  deviceID,
				ActionId:  actionID,
				Rotations: []*pm.LpsPasswordRotation{rot},
			}))
			require.Error(t, err)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		})
	}

	// No lps_password event should have been appended by any rejected call.
	events, err := st.LoadStreamByType(ctx, "lps_password", 100, 0)
	require.NoError(t, err)
	assert.Empty(t, events, "a rejected unseal must append no event")
}

// TestProxyStoreLpsPasswords_BatchIsAtomic pins that a batch is all-or-nothing:
// a [good, bad] batch rejects with InvalidArgument and appends NO event — the
// good entry must not slip through before the bad one is reached (staging
// unseals the whole batch before any append).
func TestProxyStoreLpsPasswords_BatchIsAtomic(t *testing.T) {
	h, st, _, pub, _ := newLpsHandler(t)
	ctx := context.Background()
	deviceID := testutil.CreateTestDevice(t, st, "lps-atomic-host")
	actionID := testutil.NewID()

	good, err := sdkcrypto.SealLpsPassword(pub, "pw", deviceID, actionID, "alice")
	require.NoError(t, err)
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0xFF

	_, err = h.ProxyStoreLpsPasswords(ctx, connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
		DeviceId: deviceID,
		ActionId: actionID,
		Rotations: []*pm.LpsPasswordRotation{
			{Username: "alice", SealedPassword: good, RotatedAt: "2026-03-31T12:00:00Z", Reason: pm.RotationReason_ROTATION_REASON_SCHEDULED},
			{Username: "bob", SealedPassword: bad, RotatedAt: "2026-03-31T12:00:00Z", Reason: pm.RotationReason_ROTATION_REASON_SCHEDULED},
		},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	events, err := st.LoadStreamByType(ctx, "lps_password", 100, 0)
	require.NoError(t, err)
	assert.Empty(t, events, "one bad entry must roll back the whole batch — no partial append")
}

// TestProxyStoreLpsPasswords_NilKeypairFailsClosed pins that a handler without
// a configured keypair refuses to store rather than falling back to a cleartext
// path.
func TestProxyStoreLpsPasswords_NilKeypairFailsClosed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewInternalHandler(st, testutil.NewEncryptor(t), slog.Default(), api.NoOpSigner{})
	deviceID := testutil.CreateTestDevice(t, st, "lps-nokey-host")

	_, err := h.ProxyStoreLpsPasswords(context.Background(), connect.NewRequest(&pm.InternalStoreLpsPasswordsRequest{
		DeviceId: deviceID,
		ActionId: testutil.NewID(),
		Rotations: []*pm.LpsPasswordRotation{{
			Username:       "alice",
			SealedPassword: make([]byte, 61),
			RotatedAt:      "2026-03-31T12:00:00Z",
			Reason:         pm.RotationReason_ROTATION_REASON_SCHEDULED,
		}},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}
