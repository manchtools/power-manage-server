package api_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestListIdentityLinks_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIdentityLinkHandler(st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, userID, "Google", "google")
	testutil.CreateTestIdentityLink(t, st, userID, providerID, "google-ext-123", "user@gmail.com")

	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID:          userID,
		Email:       email,
		Permissions: auth.DefaultUserPermissions(),
	})

	resp, err := h.ListIdentityLinks(ctx, connect.NewRequest(&pm.ListIdentityLinksRequest{}))
	require.NoError(t, err)

	assert.Len(t, resp.Msg.Links, 1)
	link := resp.Msg.Links[0]
	assert.Equal(t, userID, link.UserId)
	assert.Equal(t, providerID, link.ProviderId)
	assert.Equal(t, "google-ext-123", link.ExternalId)
	assert.Equal(t, "user@gmail.com", link.ExternalEmail)
	assert.Equal(t, "Google", link.ProviderName)
	assert.Equal(t, "google", link.ProviderSlug)
}

func TestListIdentityLinks_Empty(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewIdentityLinkHandler(st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")

	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID:          userID,
		Email:       email,
		Permissions: auth.DefaultUserPermissions(),
	})

	resp, err := h.ListIdentityLinks(ctx, connect.NewRequest(&pm.ListIdentityLinksRequest{}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Links)
}

func TestUnlinkIdentity_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIdentityLinkHandler(st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, userID, "Google", "google")
	linkID := testutil.CreateTestIdentityLink(t, st, userID, providerID, "google-ext-123", "user@gmail.com")

	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID:          userID,
		Email:       email,
		Permissions: auth.DefaultUserPermissions(),
	})

	// User has a password, so unlinking is allowed
	_, err := h.UnlinkIdentity(ctx, connect.NewRequest(&pm.UnlinkIdentityRequest{
		LinkId: linkID,
	}))
	require.NoError(t, err)

	// Verify the link is gone
	linksResp, err := h.ListIdentityLinks(ctx, connect.NewRequest(&pm.ListIdentityLinksRequest{}))
	require.NoError(t, err)
	assert.Empty(t, linksResp.Msg.Links)
}

func TestUnlinkIdentity_NotOwned(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIdentityLinkHandler(st)

	// Create two users
	email1 := testutil.NewID() + "@test.com"
	userID1 := testutil.CreateTestUser(t, st, email1, "pass", "user")
	email2 := testutil.NewID() + "@test.com"
	userID2 := testutil.CreateTestUser(t, st, email2, "pass", "user")

	providerID := testutil.CreateTestIdentityProvider(t, st, enc, userID1, "Google", "google")
	linkID := testutil.CreateTestIdentityLink(t, st, userID1, providerID, "google-ext-123", email1)

	// User 2 tries to unlink user 1's identity
	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID:          userID2,
		Email:       email2,
		Permissions: auth.DefaultUserPermissions(),
	})

	_, err := h.UnlinkIdentity(ctx, connect.NewRequest(&pm.UnlinkIdentityRequest{
		LinkId: linkID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestUnlinkIdentity_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewIdentityLinkHandler(st)

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")

	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID:          userID,
		Email:       email,
		Permissions: auth.DefaultUserPermissions(),
	})

	_, err := h.UnlinkIdentity(ctx, connect.NewRequest(&pm.UnlinkIdentityRequest{
		LinkId: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestUnlinkIdentity_LastAuthMethod(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIdentityLinkHandler(st)

	// Create SSO-only user (no password)
	email := testutil.NewID() + "@test.com"
	userID := testutil.NewID()
	err := st.AppendEvent(context.Background(), testutil.SSOOnlyUserEvent(userID, email))
	require.NoError(t, err)

	providerID := testutil.CreateTestIdentityProvider(t, st, enc, userID, "Google", "google")
	linkID := testutil.CreateTestIdentityLink(t, st, userID, providerID, "google-ext-123", email)

	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID:          userID,
		Email:       email,
		Permissions: auth.DefaultUserPermissions(),
	})

	// Should fail because user has no password and this is the last link
	_, err = h.UnlinkIdentity(ctx, connect.NewRequest(&pm.UnlinkIdentityRequest{
		LinkId: linkID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	assert.Contains(t, err.Error(), "last authentication method")
}
