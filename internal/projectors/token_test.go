package projectors_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/projectors"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestTokenCreatedFromEvent_Pure exercises the decoder. The PL/pgSQL
// projector defaulted name='', one_time=FALSE, max_uses=0; the Go
// shape mirrors via zero values.
func TestTokenCreatedFromEvent_Pure(t *testing.T) {
	expires := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	t.Run("happy path with all fields", func(t *testing.T) {
		got, err := projectors.TokenCreatedFromEvent(store.PersistedEvent{
			StreamType: "token", StreamID: "tok-1", EventType: "TokenCreated", ActorID: "actor-1",
			Data: jsonOrFail(t, map[string]any{
				"value_hash": "h1",
				"name":       "agent-token",
				"one_time":   true,
				"max_uses":   5,
				"expires_at": expires.Format(time.RFC3339),
				"owner_id":   "user-1",
			}),
		})
		require.NoError(t, err)
		assert.Equal(t, "tok-1", got.ID)
		assert.Equal(t, "h1", got.ValueHash)
		assert.Equal(t, "agent-token", got.Name)
		assert.True(t, got.OneTime)
		assert.Equal(t, int32(5), got.MaxUses)
		require.NotNil(t, got.ExpiresAt)
		assert.True(t, got.ExpiresAt.Equal(expires))
		require.NotNil(t, got.OwnerID)
		assert.Equal(t, "user-1", *got.OwnerID)
		assert.Equal(t, "actor-1", got.CreatedBy)
	})

	t.Run("defaults: name='', one_time=false, max_uses=0, expires_at=nil, owner_id=nil", func(t *testing.T) {
		got, err := projectors.TokenCreatedFromEvent(store.PersistedEvent{
			StreamType: "token", StreamID: "tok-2", EventType: "TokenCreated", ActorID: "a",
			Data: jsonOrFail(t, map[string]any{"value_hash": "h"}),
		})
		require.NoError(t, err)
		assert.Equal(t, "", got.Name)
		assert.False(t, got.OneTime)
		assert.Equal(t, int32(0), got.MaxUses)
		assert.Nil(t, got.ExpiresAt, "missing expires_at → nil (nullable column)")
		assert.Nil(t, got.OwnerID, "missing owner_id → nil (nullable column; PL/pgSQL stored NULL)")
	})

	t.Run("value_hash is required", func(t *testing.T) {
		_, err := projectors.TokenCreatedFromEvent(store.PersistedEvent{
			StreamType: "token", StreamID: "tok-3", EventType: "TokenCreated", ActorID: "a",
			Data: jsonOrFail(t, map[string]any{"name": "no hash"}),
		})
		require.Error(t, err)
		assert.False(t, errors.Is(err, projectors.ErrIgnoredEvent))
		assert.Contains(t, err.Error(), "value_hash")
	})

	t.Run("wrong stream/event type → ErrIgnoredEvent", func(t *testing.T) {
		_, err := projectors.TokenCreatedFromEvent(store.PersistedEvent{
			StreamType: "user", EventType: "TokenCreated",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
		_, err = projectors.TokenCreatedFromEvent(store.PersistedEvent{
			StreamType: "token", EventType: "TokenRenamed",
		})
		assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))
	})
}

// TestTokenRenamedFromEvent_Pure — minimal decoder.
func TestTokenRenamedFromEvent_Pure(t *testing.T) {
	got, err := projectors.TokenRenamedFromEvent(store.PersistedEvent{
		StreamType: "token", StreamID: "tok-1", EventType: "TokenRenamed",
		Data: jsonOrFail(t, map[string]any{"name": "renamed"}),
	})
	require.NoError(t, err)
	assert.Equal(t, "tok-1", got.ID)
	assert.Equal(t, "renamed", got.Name)

	_, err = projectors.TokenRenamedFromEvent(store.PersistedEvent{
		StreamType: "user", EventType: "TokenRenamed",
	})
	assert.True(t, errors.Is(err, projectors.ErrIgnoredEvent))

	_, err = projectors.TokenRenamedFromEvent(store.PersistedEvent{
		StreamType: "token", StreamID: "tok-1", EventType: "TokenRenamed",
		Data: jsonOrFail(t, map[string]any{}),
	})
	require.Error(t, err, "missing name is a validation error")
}

// TestTokenListener_CreateRenameUseDisableEnableDeleteLifecycle walks
// every event type through the listener in sequence and asserts the
// projection state at each step. Replaces 6 isolated tests with one
// flow that enforces the cumulative invariants (current_uses
// increments, disable/enable toggles, soft-delete preserves the row).
func TestTokenListener_CreateRenameUseDisableEnableDeleteLifecycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	tokenID := testutil.NewID()
	hash := "hash-" + testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token", StreamID: tokenID, EventType: "TokenCreated",
		Data: map[string]any{
			"value_hash": hash,
			"name":       "initial",
			"one_time":   false,
			"max_uses":   3,
			"owner_id":   "user-A",
		},
		ActorType: "user", ActorID: "u",
	}))
	tok, err := st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err)
	assert.Equal(t, hash, tok.ValueHash)
	assert.Equal(t, "initial", tok.Name)
	assert.False(t, tok.OneTime)
	assert.Equal(t, int32(3), tok.MaxUses)
	assert.Equal(t, int32(0), tok.CurrentUses)
	require.NotNil(t, tok.OwnerID)
	assert.Equal(t, "user-A", *tok.OwnerID)
	assert.False(t, tok.Disabled)
	assert.False(t, tok.IsDeleted)

	// Rename
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token", StreamID: tokenID, EventType: "TokenRenamed",
		Data: map[string]any{"name": "renamed"}, ActorType: "user", ActorID: "u",
	}))
	tok, err = st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err)
	assert.Equal(t, "renamed", tok.Name)

	// Use twice
	for i := 0; i < 2; i++ {
		require.NoError(t, st.AppendEvent(ctx, store.Event{
			StreamType: "token", StreamID: tokenID, EventType: "TokenUsed",
			Data: map[string]any{}, ActorType: "system", ActorID: "registration",
		}))
	}
	tok, err = st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err)
	assert.Equal(t, int32(2), tok.CurrentUses, "TokenUsed increments current_uses")

	// Disable then enable
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token", StreamID: tokenID, EventType: "TokenDisabled",
		Data: map[string]any{}, ActorType: "user", ActorID: "u",
	}))
	tok, err = st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err)
	assert.True(t, tok.Disabled)

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token", StreamID: tokenID, EventType: "TokenEnabled",
		Data: map[string]any{}, ActorType: "user", ActorID: "u",
	}))
	tok, err = st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err)
	assert.False(t, tok.Disabled)

	// Delete (soft) — GetTokenByID filters is_deleted=FALSE so this
	// makes the token disappear from that query.
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token", StreamID: tokenID, EventType: "TokenDeleted",
		Data: map[string]any{}, ActorType: "user", ActorID: "u",
	}))
	_, err = st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.Error(t, err, "GetTokenByID excludes soft-deleted rows")
	// Confirm row still exists with is_deleted=TRUE for audit.
	var isDeleted bool
	require.NoError(t, st.Pool().QueryRow(ctx,
		"SELECT is_deleted FROM tokens_projection WHERE id = $1", tokenID,
	).Scan(&isDeleted))
	assert.True(t, isDeleted)
}

// TestTokenListener_StaleReplayRejected confirms the projection_version
// guard rejects an UPDATE whose projection_version is older than the
// row's current value. The PL/pgSQL projector lacked this guard; the
// Go port tightens it.
func TestTokenListener_StaleReplayRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	tokenID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token", StreamID: tokenID, EventType: "TokenCreated",
		Data: map[string]any{"value_hash": "h-" + testutil.NewID(), "name": "n"},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token", StreamID: tokenID, EventType: "TokenDisabled",
		Data: map[string]any{}, ActorType: "user", ActorID: "u",
	}))
	current, err := st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err)
	require.True(t, current.Disabled)
	currentVer := current.ProjectionVersion

	// Stale replay would re-enable; the guard must reject.
	require.NoError(t, st.Queries().SetTokenDisabledProjection(ctx, db.SetTokenDisabledProjectionParams{
		ID:                tokenID,
		Disabled:          false,
		ProjectionVersion: currentVer - 5,
	}))
	after, err := st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err)
	assert.True(t, after.Disabled, "stale projection_version must NOT clobber fresher state")
	assert.Equal(t, currentVer, after.ProjectionVersion)
}

// TestTokenListener_StaleReplayRejected_TokenUsed is the load-bearing
// guard test for IncrementTokenUseProjection. Without the
// projection_version guard, a duplicate reconciler replay of TokenUsed
// would erroneously bump current_uses twice. The PR description
// specifically called this out as the most critical guarded path; it
// deserves a dedicated regression test rather than relying on the
// SetTokenDisabledProjection coverage alone.
func TestTokenListener_StaleReplayRejected_TokenUsed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	tokenID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token", StreamID: tokenID, EventType: "TokenCreated",
		Data: map[string]any{"value_hash": "h-" + testutil.NewID(), "name": "n", "max_uses": 3},
		ActorType: "user", ActorID: "u",
	}))
	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "token", StreamID: tokenID, EventType: "TokenUsed",
		Data: map[string]any{}, ActorType: "system", ActorID: "registration",
	}))
	current, err := st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err)
	require.Equal(t, int32(1), current.CurrentUses)
	currentVer := current.ProjectionVersion

	// Stale replay of TokenUsed would re-bump current_uses to 2; the
	// projection_version guard must reject it so the count stays at 1.
	require.NoError(t, st.Queries().IncrementTokenUseProjection(ctx, db.IncrementTokenUseProjectionParams{
		ID:                tokenID,
		ProjectionVersion: currentVer - 5,
	}))
	after, err := st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.NoError(t, err)
	assert.Equal(t, int32(1), after.CurrentUses, "stale projection_version must NOT double-increment current_uses")
	assert.Equal(t, currentVer, after.ProjectionVersion, "projection_version unchanged when guard rejects")
}

// TestTokenListener_IgnoresWrongStreamType — defensive.
func TestTokenListener_IgnoresWrongStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()
	tokenID := testutil.NewID()

	require.NoError(t, st.AppendEvent(ctx, store.Event{
		StreamType: "user", // wrong
		StreamID:   tokenID, EventType: "TokenCreated",
		Data: map[string]any{"value_hash": "h"}, ActorType: "user", ActorID: "u",
	}))

	_, err := st.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: tokenID})
	require.Error(t, err, "wrong-stream-type TokenCreated must NOT create a tokens_projection row")
}
