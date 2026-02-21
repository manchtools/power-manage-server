package api_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestCreateIdentityProvider_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateIdentityProvider(ctx, connect.NewRequest(&pm.CreateIdentityProviderRequest{
		Name:         "Test Google",
		Slug:         "google",
		ProviderType: "oidc",
		ClientId:     "client-123",
		ClientSecret: "secret-456",
		IssuerUrl:    "https://accounts.google.com",
		Scopes:       []string{"openid", "profile", "email"},
	}))
	require.NoError(t, err)

	p := resp.Msg.Provider
	assert.NotEmpty(t, p.Id)
	assert.Equal(t, "Test Google", p.Name)
	assert.Equal(t, "google", p.Slug)
	assert.Equal(t, "oidc", p.ProviderType)
	assert.Equal(t, "client-123", p.ClientId)
	assert.NotNil(t, p.CreatedAt)
}

func TestCreateIdentityProvider_DuplicateSlug(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Create the first provider
	testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Google", "google")

	// Try to create another with the same slug
	_, err := h.CreateIdentityProvider(ctx, connect.NewRequest(&pm.CreateIdentityProviderRequest{
		Name:         "Another Google",
		Slug:         "google",
		ProviderType: "oidc",
		ClientId:     "client-other",
		ClientSecret: "secret-other",
		IssuerUrl:    "https://accounts.google.com",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
}

func TestGetIdentityProvider_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Google", "google")

	resp, err := h.GetIdentityProvider(ctx, connect.NewRequest(&pm.GetIdentityProviderRequest{
		Id: providerID,
	}))
	require.NoError(t, err)

	assert.Equal(t, providerID, resp.Msg.Provider.Id)
	assert.Equal(t, "Google", resp.Msg.Provider.Name)
	assert.Equal(t, "google", resp.Msg.Provider.Slug)
}

func TestGetIdentityProvider_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetIdentityProvider(ctx, connect.NewRequest(&pm.GetIdentityProviderRequest{
		Id: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListIdentityProviders_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Google", "google")
	testutil.CreateTestIdentityProvider(t, st, enc, adminID, "GitHub", "github")

	resp, err := h.ListIdentityProviders(ctx, connect.NewRequest(&pm.ListIdentityProvidersRequest{
		PageSize: 50,
	}))
	require.NoError(t, err)

	assert.Equal(t, int32(2), resp.Msg.TotalCount)
	assert.Len(t, resp.Msg.Providers, 2)
}

func TestUpdateIdentityProvider_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Google", "google")

	resp, err := h.UpdateIdentityProvider(ctx, connect.NewRequest(&pm.UpdateIdentityProviderRequest{
		Id:              providerID,
		Name:            "Google Updated",
		Enabled:         true,
		AutoCreateUsers: true,
	}))
	require.NoError(t, err)

	assert.Equal(t, "Google Updated", resp.Msg.Provider.Name)
	assert.True(t, resp.Msg.Provider.Enabled)
	assert.True(t, resp.Msg.Provider.AutoCreateUsers)
}

func TestUpdateIdentityProvider_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.UpdateIdentityProvider(ctx, connect.NewRequest(&pm.UpdateIdentityProviderRequest{
		Id:   testutil.NewID(),
		Name: "Doesn't Matter",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestDeleteIdentityProvider_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Google", "google")

	_, err := h.DeleteIdentityProvider(ctx, connect.NewRequest(&pm.DeleteIdentityProviderRequest{
		Id: providerID,
	}))
	require.NoError(t, err)

	// After deletion, Get should return not found
	_, err = h.GetIdentityProvider(ctx, connect.NewRequest(&pm.GetIdentityProviderRequest{
		Id: providerID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestCreateIdentityProvider_WithGroupMapping(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	groupID := testutil.CreateTestUserGroup(t, st, adminID, "Engineering")

	resp, err := h.CreateIdentityProvider(ctx, connect.NewRequest(&pm.CreateIdentityProviderRequest{
		Name:         "Okta",
		Slug:         "okta",
		ProviderType: "oidc",
		ClientId:     "client-okta",
		ClientSecret: "secret-okta",
		IssuerUrl:    "https://dev.okta.com",
		GroupClaim:   "groups",
		GroupMapping: map[string]string{
			"engineering": groupID,
		},
	}))
	require.NoError(t, err)

	p := resp.Msg.Provider
	assert.Equal(t, "groups", p.GroupClaim)
	assert.Equal(t, groupID, p.GroupMapping["engineering"])
}

func TestEnableSCIM_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Okta", "okta")

	resp, err := h.EnableSCIM(ctx, connect.NewRequest(&pm.EnableSCIMRequest{
		Id: providerID,
	}))
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Msg.Token)
	assert.Len(t, resp.Msg.Token, 64) // 32 bytes = 64 hex chars
	assert.Equal(t, "http://localhost:8081/scim/v2/okta", resp.Msg.EndpointUrl)

	// Verify provider now shows SCIM enabled
	getResp, err := h.GetIdentityProvider(ctx, connect.NewRequest(&pm.GetIdentityProviderRequest{
		Id: providerID,
	}))
	require.NoError(t, err)
	assert.True(t, getResp.Msg.Provider.ScimEnabled)
}

func TestEnableSCIM_AlreadyEnabled(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Okta", "okta")
	testutil.EnableSCIMForProvider(t, st, adminID, providerID)

	_, err := h.EnableSCIM(ctx, connect.NewRequest(&pm.EnableSCIMRequest{
		Id: providerID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
}

func TestDisableSCIM_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Okta", "okta")
	testutil.EnableSCIMForProvider(t, st, adminID, providerID)

	_, err := h.DisableSCIM(ctx, connect.NewRequest(&pm.DisableSCIMRequest{
		Id: providerID,
	}))
	require.NoError(t, err)

	// Verify provider now shows SCIM disabled
	getResp, err := h.GetIdentityProvider(ctx, connect.NewRequest(&pm.GetIdentityProviderRequest{
		Id: providerID,
	}))
	require.NoError(t, err)
	assert.False(t, getResp.Msg.Provider.ScimEnabled)
}

func TestDisableSCIM_NotEnabled(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Okta", "okta")

	_, err := h.DisableSCIM(ctx, connect.NewRequest(&pm.DisableSCIMRequest{
		Id: providerID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestRotateSCIMToken_Success(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Okta", "okta")
	originalToken := testutil.EnableSCIMForProvider(t, st, adminID, providerID)

	resp, err := h.RotateSCIMToken(ctx, connect.NewRequest(&pm.RotateSCIMTokenRequest{
		Id: providerID,
	}))
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Msg.Token)
	assert.Len(t, resp.Msg.Token, 64)
	assert.NotEqual(t, originalToken, resp.Msg.Token) // New token must differ
}

func TestRotateSCIMToken_NotEnabled(t *testing.T) {
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewIDPHandler(st, enc, "http://localhost:8081")

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	providerID := testutil.CreateTestIdentityProvider(t, st, enc, adminID, "Okta", "okta")

	_, err := h.RotateSCIMToken(ctx, connect.NewRequest(&pm.RotateSCIMTokenRequest{
		Id: providerID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}
