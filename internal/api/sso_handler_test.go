package api_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestListAuthMethods_PasswordEnabled(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewSSOHandler(st, jwtMgr, enc, true, "https://app.example.com")

	resp, err := h.ListAuthMethods(context.Background(), connect.NewRequest(&pm.ListAuthMethodsRequest{}))
	require.NoError(t, err)

	assert.True(t, resp.Msg.PasswordEnabled)
	assert.False(t, resp.Msg.TotpEnabled)
	assert.Empty(t, resp.Msg.Providers)
}

func TestListAuthMethods_PasswordDisabledGlobally(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewSSOHandler(st, jwtMgr, enc, false, "https://app.example.com")

	resp, err := h.ListAuthMethods(context.Background(), connect.NewRequest(&pm.ListAuthMethodsRequest{}))
	require.NoError(t, err)

	assert.False(t, resp.Msg.PasswordEnabled)
}

func TestListAuthMethods_WithProviders(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewSSOHandler(st, jwtMgr, enc, true, "https://app.example.com")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Google", "google")

	// Enable the provider
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "identity_provider",
		StreamID:   providerID,
		EventType:  "IdentityProviderUpdated",
		Data: map[string]any{
			"name":    "Google",
			"enabled": true,
		},
		ActorType: "user",
		ActorID:   adminID,
	})
	require.NoError(t, err)

	resp, err := h.ListAuthMethods(context.Background(), connect.NewRequest(&pm.ListAuthMethodsRequest{}))
	require.NoError(t, err)

	assert.True(t, resp.Msg.PasswordEnabled)
	require.Len(t, resp.Msg.Providers, 1)
	assert.Equal(t, "google", resp.Msg.Providers[0].Slug)
	assert.Equal(t, "Google", resp.Msg.Providers[0].Name)
	assert.Equal(t, "oidc", resp.Msg.Providers[0].ProviderType)
}

func TestListAuthMethods_WithEmailUserHasTOTP(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewSSOHandler(st, jwtMgr, enc, true, "https://app.example.com")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")
	testutil.SetupTOTP(t, st, enc, userID, email)

	resp, err := h.ListAuthMethods(context.Background(), connect.NewRequest(&pm.ListAuthMethodsRequest{
		Email: email,
	}))
	require.NoError(t, err)

	assert.True(t, resp.Msg.PasswordEnabled)
	assert.True(t, resp.Msg.TotpEnabled)
}

func TestListAuthMethods_WithEmailPasswordDisabledByProvider(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewSSOHandler(st, jwtMgr, enc, true, "https://app.example.com")

	email := testutil.NewID() + "@test.com"
	userID := testutil.CreateTestUser(t, st, email, "pass", "user")

	// Create a provider with disable_password_for_linked=true
	providerID := testutil.NewID()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "identity_provider",
		StreamID:   providerID,
		EventType:  "IdentityProviderCreated",
		Data: map[string]any{
			"name":                        "Corporate SSO",
			"slug":                        "corporate",
			"provider_type":               "oidc",
			"client_id":                   "client-corp",
			"client_secret_encrypted":     "encrypted",
			"issuer_url":                  "https://corp.example.com",
			"enabled":                     true,
			"disable_password_for_linked": true,
		},
		ActorType: "system",
		ActorID:   "test",
	})
	require.NoError(t, err)

	// Link the user to this provider
	testutil.CreateTestIdentityLink(t, st, userID, providerID, "corp-ext-123", email)

	resp, err := h.ListAuthMethods(context.Background(), connect.NewRequest(&pm.ListAuthMethodsRequest{
		Email: email,
	}))
	require.NoError(t, err)

	assert.False(t, resp.Msg.PasswordEnabled, "password should be disabled for user linked to provider with disable_password_for_linked")
}

func TestListAuthMethods_NonexistentEmailShowsDefaults(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	jwtMgr := testutil.NewJWTManager()
	h := api.NewSSOHandler(st, jwtMgr, enc, true, "https://app.example.com")

	resp, err := h.ListAuthMethods(context.Background(), connect.NewRequest(&pm.ListAuthMethodsRequest{
		Email: "nonexistent@test.com",
	}))
	require.NoError(t, err)

	// Should still return defaults without revealing the user doesn't exist
	assert.True(t, resp.Msg.PasswordEnabled)
	assert.False(t, resp.Msg.TotpEnabled)
}
