package api_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// CHARTER — event-sourced LPS keypair (#495).
//
//   - The ONLY write path is the LpsKeypairGenerated append at stream
//     version 1; the lps_keypair row is a projection of it.
//   - Concurrency: N racing EnsureLpsKeypair calls produce EXACTLY ONE event
//     (the UNIQUE stream-version constraint is the first-writer-wins) and
//     every caller converges on the winner's key (AC2).
//   - Replay: RebuildAll("lps_keypair") reproduces the row 1:1 (AC1).
//   - Upgrade: a pre-#495 row without a stream gets a synthetic
//     LpsKeypairGenerated backfilled with identical key bytes (AC3).

// TestEnsureLpsKeypair_AppendsExactlyOneEvent proves the fresh-generation
// path is event-sourced: one LpsKeypairGenerated at version 1, whose payload
// matches the projected row byte-for-byte — even under concurrency.
func TestEnsureLpsKeypair_AppendsExactlyOneEvent(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	ctx := context.Background()

	const n = 6
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
		assert.Equal(t, pubs[0], pubs[i], "all racers must converge on the winner's key")
	}

	events, err := st.LoadStream(ctx, "lps_keypair", "global")
	require.NoError(t, err)
	require.Len(t, events, 1, "exactly one LpsKeypairGenerated — the version-1 slot is first-writer-wins")
	require.Equal(t, string(eventtypes.LpsKeypairGenerated), events[0].EventType)

	var payload payloads.LpsKeypairGenerated
	require.NoError(t, json.Unmarshal(events[0].Data, &payload))
	require.Equal(t, pubs[0], payload.PublicKey, "event payload carries the adopted public key")

	row, err := st.Queries().GetLpsKeypair(ctx)
	require.NoError(t, err)
	assert.Equal(t, payload.PublicKey, row.PublicKey, "projection row derives from the event")
	assert.Equal(t, payload.PrivateKeyEnc, row.PrivateKeyEnc, "projection row derives from the event")
}

// TestLpsKeypair_RebuildReproducesRow is AC1: drop the projection via
// RebuildAll and the replay reproduces the row 1:1, and the reloaded keypair
// still decodes to the same keys (the signed public key BuildSignedLpsPublicKey
// distributes stays byte-identical).
func TestLpsKeypair_RebuildReproducesRow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	ctx := context.Background()

	priv, pub, err := api.EnsureLpsKeypair(ctx, st, enc)
	require.NoError(t, err)

	before, err := st.Queries().GetLpsKeypair(ctx)
	require.NoError(t, err)

	res, err := st.RebuildAll(ctx, "lps_keypair")
	require.NoError(t, err)
	require.Len(t, res.Targets, 1)
	require.EqualValues(t, 1, res.Targets[0].EventsApplied, "the singleton stream replays exactly one event")

	after, err := st.Queries().GetLpsKeypair(ctx)
	require.NoError(t, err)
	assert.Equal(t, before.PublicKey, after.PublicKey, "replayed public key must be byte-identical")
	assert.Equal(t, before.PrivateKeyEnc, after.PrivateKeyEnc, "replayed ciphertext must be byte-identical")
	assert.True(t, before.CreatedAt.Time.Equal(after.CreatedAt.Time), "replayed created_at must match the event's")

	privAfter, pubAfter, err := api.EnsureLpsKeypair(ctx, st, enc)
	require.NoError(t, err)
	assert.Equal(t, pub, pubAfter, "post-rebuild public key must be byte-identical (signed distribution unchanged)")
	assert.True(t, priv.Equal(privAfter), "post-rebuild private key must be the same key")
}

// TestLpsKeypair_BackfillsPre495Row is AC3, the upgrade path: a deployment
// that wrote the row directly (pre-#495) has no stream. EnsureLpsKeypair
// backfills a synthetic LpsKeypairGenerated with the row's exact bytes and
// original created_at — idempotently — so the replay guarantee holds for
// upgraded deployments.
func TestLpsKeypair_BackfillsPre495Row(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	ctx := context.Background()

	// Simulate the pre-#495 state: a directly-inserted row, no stream. The
	// key bytes must be a REAL pair encrypted under the production AAD
	// context so EnsureLpsKeypair's decode path accepts them.
	seedPriv, err := sdkcrypto.GenerateX25519()
	require.NoError(t, err)
	seedPub := seedPriv.PublicKey().Bytes()
	seedEnc, err := enc.EncryptWithContext(string(seedPriv.Bytes()),
		crypto.SecretAAD("global", "lps-keypair", "lps-keypair-priv"))
	require.NoError(t, err)
	_, err = st.TestingPool().Exec(ctx,
		`INSERT INTO lps_keypair (id, public_key, private_key_enc, created_at)
		 VALUES ('global', $1, $2, now() - interval '30 days')`, seedPub, seedEnc)
	require.NoError(t, err)

	priv, pub, err := api.EnsureLpsKeypair(ctx, st, enc)
	require.NoError(t, err)
	assert.Equal(t, seedPub, pub, "backfill must adopt the existing key, never mint a new one")
	assert.True(t, priv.Equal(seedPriv), "backfill must preserve the private key")

	events, err := st.LoadStream(ctx, "lps_keypair", "global")
	require.NoError(t, err)
	require.Len(t, events, 1, "backfill appends exactly one synthetic event")
	require.Equal(t, string(eventtypes.LpsKeypairGenerated), events[0].EventType)

	var payload payloads.LpsKeypairGenerated
	require.NoError(t, json.Unmarshal(events[0].Data, &payload))
	assert.Equal(t, seedPub, payload.PublicKey, "backfilled payload preserves the key bytes")
	assert.Equal(t, seedEnc, payload.PrivateKeyEnc, "backfilled payload preserves the ciphertext")
	require.NotNil(t, payload.CreatedAt, "backfill preserves the row's original created_at")

	// Idempotent: a second Ensure appends nothing.
	_, _, err = api.EnsureLpsKeypair(ctx, st, enc)
	require.NoError(t, err)
	events, err = st.LoadStream(ctx, "lps_keypair", "global")
	require.NoError(t, err)
	require.Len(t, events, 1, "backfill must be idempotent")

	// And the replay now reproduces the pre-#495 row, original timestamp
	// included (the payload carries it).
	before, err := st.Queries().GetLpsKeypair(ctx)
	require.NoError(t, err)
	_, err = st.RebuildAll(ctx, "lps_keypair")
	require.NoError(t, err)
	after, err := st.Queries().GetLpsKeypair(ctx)
	require.NoError(t, err)
	assert.Equal(t, before.PublicKey, after.PublicKey)
	assert.Equal(t, before.PrivateKeyEnc, after.PrivateKeyEnc)
	assert.True(t, before.CreatedAt.Time.Equal(after.CreatedAt.Time), "original created_at survives the replay")
}
