package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/registrationtoken"
	"github.com/manchtools/power-manage/server/internal/store"
)

type tokenHandlerFixture struct {
	t        *testing.T
	store    *store.Store
	raw      *pgxpool.Pool
	handlers *registrationtoken.Handlers
	now      time.Time
	actorID  string
	otherID  string
}

const tokenCAPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTokenHandlerFixture(t *testing.T) *tokenHandlerFixture {
	t.Helper()
	st, raw := setupPostgres(t)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	f := &tokenHandlerFixture{
		t: t, store: st, raw: raw, now: now, actorID: newID(), otherID: newID(),
	}
	_, err := raw.Exec(context.Background(), `
		INSERT INTO users (id, email, display_name, linux_username, linux_uid, created_at)
		VALUES ($1, 'actor@example.test', 'Actor', 'actor', 200001, $3),
		       ($2, 'other@example.test', 'Other', 'other', 200002, $3)`,
		f.actorID, f.otherID, now)
	require.NoError(t, err)
	f.handlers = registrationtoken.New(registrationtoken.Config{
		Store: st, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return now }, CAFingerprint: tokenCAPin,
	})
	return f
}

func (f *tokenHandlerFixture) actor(perms ...string) context.Context {
	f.t.Helper()
	return auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser, Permissions: perms,
	})
}

func TestTokenHandlers_ValidateBeforeAuthentication(t *testing.T) {
	f := newTokenHandlerFixture(t)
	_, err := f.handlers.GetToken(context.Background(), connect.NewRequest(&pmv1.GetTokenRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.GetToken(context.Background(), connect.NewRequest(&pmv1.GetTokenRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestTokenHandlers_CRUDIsDirectAuditedState(t *testing.T) {
	f := newTokenHandlerFixture(t)
	ctx := f.actor("CreateToken", "GetToken", "ListTokens", "RenameToken", "SetTokenDisabled", "DeleteToken")
	expires := f.now.Add(48 * time.Hour)

	created, err := f.handlers.CreateToken(ctx, connect.NewRequest(&pmv1.CreateTokenRequest{
		Name: "rack enrollment", OneTime: true, MaxUses: 3,
		ExpiresAt: timestamp(expires), OwnerId: f.otherID,
	}))
	require.NoError(t, err)
	tokenID, plaintext := created.Msg.Token.Id, created.Msg.Token.Value
	require.NotEmpty(t, plaintext)
	assert.Equal(t, tokenCAPin, created.Msg.CaFingerprintPin)
	assert.Equal(t, f.otherID, created.Msg.Token.OwnerId)
	assert.True(t, created.Msg.Token.CreatedAt.AsTime().Equal(f.now))

	var storedHash string
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT value_hash FROM tokens WHERE id = $1`, tokenID).Scan(&storedHash))
	digest := sha256.Sum256([]byte(plaintext))
	assert.Equal(t, hex.EncodeToString(digest[:]), storedHash)
	assert.NotEqual(t, plaintext, storedHash)

	got, err := f.handlers.GetToken(ctx, connect.NewRequest(&pmv1.GetTokenRequest{Id: tokenID}))
	require.NoError(t, err)
	assert.Empty(t, got.Msg.Token.Value, "stored tokens are never recoverable")

	renamed, err := f.handlers.RenameToken(ctx, connect.NewRequest(&pmv1.RenameTokenRequest{Id: tokenID, Name: "renamed"}))
	require.NoError(t, err)
	assert.Equal(t, "renamed", renamed.Msg.Token.Name)

	disabled, err := f.handlers.SetTokenDisabled(ctx, connect.NewRequest(&pmv1.SetTokenDisabledRequest{Id: tokenID, Disabled: true}))
	require.NoError(t, err)
	assert.True(t, disabled.Msg.Token.Disabled)

	hidden, err := f.handlers.ListTokens(ctx, connect.NewRequest(&pmv1.ListTokensRequest{}))
	require.NoError(t, err)
	assert.Empty(t, hidden.Msg.Tokens)
	assert.Zero(t, hidden.Msg.TotalCount)
	visible, err := f.handlers.ListTokens(ctx, connect.NewRequest(&pmv1.ListTokensRequest{IncludeDisabled: true}))
	require.NoError(t, err)
	require.Len(t, visible.Msg.Tokens, 1)
	assert.Empty(t, visible.Msg.Tokens[0].Value)

	_, err = f.handlers.DeleteToken(ctx, connect.NewRequest(&pmv1.DeleteTokenRequest{Id: tokenID}))
	require.NoError(t, err)
	_, err = f.handlers.GetToken(ctx, connect.NewRequest(&pmv1.GetTokenRequest{Id: tokenID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	for _, procedure := range registrationtoken.MutationProcedures() {
		operation, err := latestOperationFor(t, f.store, f.raw, procedure)
		require.NoError(t, err, procedure)
		effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
		require.NoError(t, err, procedure)
		assert.NotEmpty(t, effects, procedure)
	}
}

func TestTokenHandlers_SelfCreationAndReservedTokenIsolation(t *testing.T) {
	f := newTokenHandlerFixture(t)
	self, err := f.handlers.CreateToken(f.actor("CreateToken:self"), connect.NewRequest(&pmv1.CreateTokenRequest{
		Name: "my device", MaxUses: 99, OwnerId: f.otherID,
	}))
	require.NoError(t, err)
	assert.True(t, self.Msg.Token.OneTime)
	assert.Equal(t, int32(1), self.Msg.Token.MaxUses)
	assert.Equal(t, f.actorID, self.Msg.Token.OwnerId)
	assert.True(t, self.Msg.Token.ExpiresAt.AsTime().Equal(f.now.Add(7*24*time.Hour)))

	_, err = f.handlers.CreateToken(f.actor("CreateToken"), connect.NewRequest(&pmv1.CreateTokenRequest{
		Name: store.BootstrapAdminTokenName,
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	bootstrapID := newID()
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO tokens (
			id, value_hash, name, one_time, max_uses, created_at, created_by
		) VALUES ($1, $2, $3, TRUE, 1, $4, $5)`,
		bootstrapID, strings.Repeat("a", 64), store.BootstrapAdminTokenName, f.now, auth.BootstrapPrincipalID)
	require.NoError(t, err)
	operator := f.actor("GetToken", "ListTokens", "RenameToken", "SetTokenDisabled", "DeleteToken")
	_, err = f.handlers.GetToken(operator, connect.NewRequest(&pmv1.GetTokenRequest{Id: bootstrapID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	listed, err := f.handlers.ListTokens(operator, connect.NewRequest(&pmv1.ListTokensRequest{}))
	require.NoError(t, err)
	require.Len(t, listed.Msg.Tokens, 1, "only the ordinary self token is visible")
	assert.Equal(t, self.Msg.Token.Id, listed.Msg.Tokens[0].Id)
	for name, call := range map[string]func() error{
		"rename": func() error {
			_, err := f.handlers.RenameToken(operator, connect.NewRequest(&pmv1.RenameTokenRequest{Id: bootstrapID, Name: "stolen"}))
			return err
		},
		"disable": func() error {
			_, err := f.handlers.SetTokenDisabled(operator, connect.NewRequest(&pmv1.SetTokenDisabledRequest{Id: bootstrapID, Disabled: true}))
			return err
		},
		"delete": func() error {
			_, err := f.handlers.DeleteToken(operator, connect.NewRequest(&pmv1.DeleteTokenRequest{Id: bootstrapID}))
			return err
		},
	} {
		t.Run(name+" bootstrap token", func(t *testing.T) {
			assert.Equal(t, connect.CodeNotFound, connect.CodeOf(call()))
		})
	}
	var bootstrapDeleted, bootstrapDisabled bool
	require.NoError(t, f.raw.QueryRow(context.Background(),
		`SELECT is_deleted, disabled FROM tokens WHERE id = $1`, bootstrapID).Scan(&bootstrapDeleted, &bootstrapDisabled))
	assert.False(t, bootstrapDeleted)
	assert.False(t, bootstrapDisabled)

	_, err = f.handlers.CreateToken(f.actor("CreateToken"), connect.NewRequest(&pmv1.CreateTokenRequest{
		Name: "missing owner", OwnerId: newID(),
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestTokenHandlers_KeysetPaginationAndMountSurface(t *testing.T) {
	f := newTokenHandlerFixture(t)
	ctx := f.actor("CreateToken", "ListTokens")
	for _, name := range []string{"one", "two", "three"} {
		_, err := f.handlers.CreateToken(ctx, connect.NewRequest(&pmv1.CreateTokenRequest{Name: name}))
		require.NoError(t, err)
	}
	first, err := f.handlers.ListTokens(ctx, connect.NewRequest(&pmv1.ListTokensRequest{PageSize: 2}))
	require.NoError(t, err)
	require.Len(t, first.Msg.Tokens, 2)
	require.NotEmpty(t, first.Msg.NextPageToken)
	assert.Equal(t, int32(3), first.Msg.TotalCount)
	second, err := f.handlers.ListTokens(ctx, connect.NewRequest(&pmv1.ListTokensRequest{
		PageSize: 2, PageToken: first.Msg.NextPageToken,
	}))
	require.NoError(t, err)
	require.Len(t, second.Msg.Tokens, 1)
	assert.Empty(t, second.Msg.NextPageToken)
	assert.NotEqual(t, first.Msg.Tokens[1].Id, second.Msg.Tokens[0].Id)

	_, err = f.handlers.ListTokens(ctx, connect.NewRequest(&pmv1.ListTokensRequest{PageToken: "not-a-ulid"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	mounted := f.handlers.Mount(http.NewServeMux())
	assert.ElementsMatch(t, append(registrationtoken.MutationProcedures(), registrationtoken.ReadProcedures()...), mounted)
	assert.ElementsMatch(t, []string{
		powermanagev1connect.ControlServiceCreateTokenProcedure,
		powermanagev1connect.ControlServiceRenameTokenProcedure,
		powermanagev1connect.ControlServiceSetTokenDisabledProcedure,
		powermanagev1connect.ControlServiceDeleteTokenProcedure,
	}, registrationtoken.MutationProcedures())
}

func timestamp(at time.Time) *timestamppb.Timestamp { return timestamppb.New(at) }
