package projectors_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestLpsKeypairGeneratedFromEvent_Pure exercises the pure decoder without
// the database (#495). Table-driven over the correct / absent / wrong triad
// for both payload halves.
func TestLpsKeypairGeneratedFromEvent_Pure(t *testing.T) {
	pub := bytes.Repeat([]byte{0x42}, 32)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	t.Run("happy path", func(t *testing.T) {
		got, err := projectors.LpsKeypairGeneratedFromEvent(store.PersistedEvent{
			StreamType: "lps_keypair",
			EventType:  "LpsKeypairGenerated",
			Data: jsonOrFail(t, map[string]any{
				"public_key":      pubB64,
				"private_key_enc": "enc:v2:abc",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, pub, got.PublicKey)
		assert.Equal(t, "enc:v2:abc", got.PrivateKeyEnc)
		assert.Nil(t, got.CreatedAt, "created_at is optional (backfill-only)")
	})

	t.Run("backfill carries created_at", func(t *testing.T) {
		created := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
		got, err := projectors.LpsKeypairGeneratedFromEvent(store.PersistedEvent{
			StreamType: "lps_keypair",
			EventType:  "LpsKeypairGenerated",
			Data: jsonOrFail(t, map[string]any{
				"public_key":      pubB64,
				"private_key_enc": "enc:v2:abc",
				"created_at":      created.Format(time.RFC3339),
			}),
		})
		require.NoError(t, err)
		require.NotNil(t, got.CreatedAt)
		assert.True(t, got.CreatedAt.Equal(created))
	})

	t.Run("wrong stream type is ignored", func(t *testing.T) {
		_, err := projectors.LpsKeypairGeneratedFromEvent(store.PersistedEvent{
			StreamType: "lps_password",
			EventType:  "LpsKeypairGenerated",
			Data:       jsonOrFail(t, map[string]any{"public_key": pubB64, "private_key_enc": "enc:v2:abc"}),
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("wrong event type is ignored", func(t *testing.T) {
		_, err := projectors.LpsKeypairGeneratedFromEvent(store.PersistedEvent{
			StreamType: "lps_keypair",
			EventType:  "LpsPasswordRotated",
			Data:       jsonOrFail(t, map[string]any{"public_key": pubB64, "private_key_enc": "enc:v2:abc"}),
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("empty payload rejected", func(t *testing.T) {
		_, err := projectors.LpsKeypairGeneratedFromEvent(store.PersistedEvent{
			StreamType: "lps_keypair",
			EventType:  "LpsKeypairGenerated",
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})

	t.Run("missing public_key rejected", func(t *testing.T) {
		_, err := projectors.LpsKeypairGeneratedFromEvent(store.PersistedEvent{
			StreamType: "lps_keypair",
			EventType:  "LpsKeypairGenerated",
			Data:       jsonOrFail(t, map[string]any{"private_key_enc": "enc:v2:abc"}),
		})
		require.ErrorContains(t, err, "public_key")
	})

	t.Run("wrong-size public_key rejected", func(t *testing.T) {
		_, err := projectors.LpsKeypairGeneratedFromEvent(store.PersistedEvent{
			StreamType: "lps_keypair",
			EventType:  "LpsKeypairGenerated",
			Data: jsonOrFail(t, map[string]any{
				"public_key":      base64.StdEncoding.EncodeToString([]byte("short")),
				"private_key_enc": "enc:v2:abc",
			}),
		})
		require.ErrorContains(t, err, "public_key")
	})

	t.Run("missing private_key_enc rejected", func(t *testing.T) {
		_, err := projectors.LpsKeypairGeneratedFromEvent(store.PersistedEvent{
			StreamType: "lps_keypair",
			EventType:  "LpsKeypairGenerated",
			Data:       jsonOrFail(t, map[string]any{"public_key": pubB64}),
		})
		require.ErrorContains(t, err, "private_key_enc")
	})
}

// TestLpsKeypairListener_MaterializesRow drives a real LpsKeypairGenerated
// through Store.AppendEvent on real Postgres (SetupPostgres wires WireAll)
// and asserts the projection row appears with the event's exact content —
// the listener integration half of the #495 projector port.
func TestLpsKeypairListener_MaterializesRow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	pub := bytes.Repeat([]byte{0x24}, 32)
	require.NoError(t, st.AppendEventWithVersion(ctx, store.Event{
		StreamType: "lps_keypair",
		StreamID:   "global",
		EventType:  "LpsKeypairGenerated",
		Data: payloads.LpsKeypairGenerated{
			PublicKey:     pub,
			PrivateKeyEnc: "enc:v2:listener-test",
		},
		ActorType: "system",
		ActorID:   "system",
	}, 1))

	row, err := st.Queries().GetLpsKeypair(ctx)
	require.NoError(t, err, "listener must materialise the projection row synchronously")
	assert.Equal(t, pub, row.PublicKey)
	assert.Equal(t, "enc:v2:listener-test", row.PrivateKeyEnc)
	assert.True(t, row.CreatedAt.Valid)
}
