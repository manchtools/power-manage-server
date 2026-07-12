package scim_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// setProviderFlags appends an IdentityProviderUpdated event toggling the named
// boolean provider flags (auto_link_by_email, trust_email_assertions, enabled).
func setProviderFlags(t *testing.T, env *scimTestEnv, providerID string, flags map[string]any) {
	t.Helper()
	require.NoError(t, env.st.AppendEvent(context.Background(), store.Event{
		StreamType: "identity_provider",
		StreamID:   providerID,
		EventType:  string(eventtypes.IdentityProviderUpdated),
		Data:       flags,
		ActorType:  "user",
		ActorID:    env.adminID,
	}))
}

// createPasswordlessUser seeds a user with NO local password (HasPassword=false),
// i.e. an already-SSO-provisioned account that is safe to auto-link.
func createPasswordlessUser(t *testing.T, env *scimTestEnv, email string) string {
	t.Helper()
	id := testutil.NewID()
	// Spec 19: the SCIM auto-link path emits typed IdentityLinked PII
	// for this user — the sealer fails closed without a DEK.
	testutil.MintTestUserDEK(t, env.st, id)
	require.NoError(t, env.st.AppendEvent(context.Background(), store.Event{
		StreamType: "user",
		StreamID:   id,
		EventType:  string(eventtypes.UserCreatedWithRoles),
		Data: map[string]any{
			"email":         email,
			"password_hash": "",
			"role":          "user",
			"role_ids":      []string{},
		},
		ActorType: "system",
		ActorID:   "test",
	}))
	return id
}

func providerOwnsUser(t *testing.T, env *scimTestEnv, providerID, userID string) bool {
	t.Helper()
	_, err := env.st.Queries().GetIdentityLinkByProviderAndUser(context.Background(),
		db.GetIdentityLinkByProviderAndUserParams{ProviderID: providerID, UserID: userID})
	if err == nil {
		return true
	}
	require.True(t, store.IsNotFound(err), "unexpected error checking link: %v", err)
	return false
}

func postSCIMUser(t *testing.T, env *scimTestEnv, userName string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   userName,
		"externalId": "ext-" + testutil.NewID(),
		"active":     true,
	}
	return scimReq(t, env, env.slug, env.token, http.MethodPost, "/Users", body)
}

// TestCreateUser_AutoLinkByEmail_RequiresVerifiedSignal pins #2: with
// AutoLinkByEmail on, a SCIM POST whose email matches a pre-existing LOCAL
// PASSWORD account must NOT bind that account to the provider unless the
// operator opted in via trust_email_assertions (account-takeover guard).
func TestCreateUser_AutoLinkByEmail_RequiresVerifiedSignal(t *testing.T) {
	t.Run("takeover_password_account_refused", func(t *testing.T) {
		env := setupSCIM(t)
		setProviderFlags(t, env, env.providerID, map[string]any{"auto_link_by_email": true})
		victim := testutil.CreateTestUser(t, env.st, "victim-"+testutil.NewID()[:6]+"@corp.com", "s3cret", "admin")
		// Re-read the victim's email to POST against it.
		vu, err := env.st.Repos().User.Get(context.Background(), victim)
		require.NoError(t, err)

		w := postSCIMUser(t, env, vu.Email)
		assert.Equal(t, http.StatusConflict, w.Code,
			"auto-link to a local password account must be refused without trust opt-in: %s", w.Body.String())
		assert.False(t, providerOwnsUser(t, env, env.providerID, victim),
			"the victim's local account must NOT gain a provider link")
	})

	t.Run("explicit_trust_allows_password_account", func(t *testing.T) {
		env := setupSCIM(t)
		setProviderFlags(t, env, env.providerID, map[string]any{
			"auto_link_by_email":     true,
			"trust_email_assertions": true,
		})
		u := testutil.CreateTestUser(t, env.st, "trust-"+testutil.NewID()[:6]+"@corp.com", "s3cret", "user")
		uu, err := env.st.Repos().User.Get(context.Background(), u)
		require.NoError(t, err)

		w := postSCIMUser(t, env, uu.Email)
		assert.Equal(t, http.StatusCreated, w.Code, "%s", w.Body.String())
		assert.True(t, providerOwnsUser(t, env, env.providerID, u),
			"with trust_email_assertions the password account may be linked")
	})

	t.Run("passwordless_account_linked", func(t *testing.T) {
		env := setupSCIM(t)
		setProviderFlags(t, env, env.providerID, map[string]any{"auto_link_by_email": true})
		email := "sso-" + testutil.NewID()[:6] + "@corp.com"
		u := createPasswordlessUser(t, env, email)

		w := postSCIMUser(t, env, email)
		assert.Equal(t, http.StatusCreated, w.Code, "%s", w.Body.String())
		assert.True(t, providerOwnsUser(t, env, env.providerID, u),
			"a passwordless (already-SSO) account is safe to auto-link")
	})

	t.Run("absent_account_creates_new", func(t *testing.T) {
		env := setupSCIM(t)
		setProviderFlags(t, env, env.providerID, map[string]any{"auto_link_by_email": true})
		w := postSCIMUser(t, env, "fresh-"+testutil.NewID()[:6]+"@corp.com")
		assert.Equal(t, http.StatusCreated, w.Code, "no matching local account → create new: %s", w.Body.String())
	})
}

// TestReplaceUser_LoginUpdatedCarriesUserID pins the #507 / spec 19
// contract on the SCIM sync path: the IdentityLinkLoginUpdated event
// carries PII (external_email/external_name), so its payload must name
// the owning user — the crypto-shred layer resolves the DEK owner from
// data->>'user_id'.
func TestReplaceUser_LoginUpdatedCarriesUserID(t *testing.T) {
	env := setupSCIM(t)

	email := "louu-" + testutil.NewID()[:6] + "@corp.com"
	w := postSCIMUser(t, env, email)
	require.Equal(t, http.StatusCreated, w.Code, "%s", w.Body.String())
	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	userID := created["id"].(string)

	// PUT triggers syncIdentityLink → IdentityLinkLoginUpdated.
	put := scimReq(t, env, env.slug, env.token, http.MethodPut, "/Users/"+userID, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"name":     map[string]any{"givenName": "Lou", "familyName": "Update"},
		"active":   true,
	})
	require.Equal(t, http.StatusOK, put.Code, "%s", put.Body.String())

	var gotUserID string
	require.NoError(t, env.st.TestingPool().QueryRow(context.Background(),
		`SELECT data->>'user_id' FROM events
		 WHERE event_type = 'IdentityLinkLoginUpdated'
		 ORDER BY sequence_num DESC LIMIT 1`).Scan(&gotUserID))
	assert.Equal(t, userID, gotUserID,
		"IdentityLinkLoginUpdated must carry the DEK-owner user_id")
}

// TestReplaceUser_ExplicitEmptyNameClearsProfile pins the SCIM
// source-of-truth contract on profile sync: a PUT that carries an
// explicit empty name object CLEARS the profile fields (pointer
// semantics: present-but-"" = overwrite), while a PUT that omits the
// name object entirely PRESERVES them (absent = not asserted). The
// old gate skipped the event whenever every computed value was empty,
// making an explicit clear impossible (local CR finding on #507).
func TestReplaceUser_ExplicitEmptyNameClearsProfile(t *testing.T) {
	env := setupSCIM(t)

	email := "clear-" + testutil.NewID()[:6] + "@corp.com"
	w := scimReq(t, env, env.slug, env.token, http.MethodPost, "/Users", map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   email,
		"externalId": "ext-" + testutil.NewID(),
		"active":     true,
		"name":       map[string]any{"givenName": "Lou", "familyName": "Update"},
	})
	require.Equal(t, http.StatusCreated, w.Code, "%s", w.Body.String())
	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	userID := created["id"].(string)

	seeded, err := env.st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	require.Equal(t, "Lou", seeded.GivenName, "seed sanity: given_name populated")

	// PUT with NO name object — profile must be preserved.
	put := scimReq(t, env, env.slug, env.token, http.MethodPut, "/Users/"+userID, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"active":   true,
	})
	require.Equal(t, http.StatusOK, put.Code, "%s", put.Body.String())
	kept, err := env.st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	assert.Equal(t, "Lou", kept.GivenName, "omitted name object must not touch the profile")

	// PUT with an explicit EMPTY name object — profile must clear.
	put = scimReq(t, env, env.slug, env.token, http.MethodPut, "/Users/"+userID, map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"active":   true,
		"name":     map[string]any{},
	})
	require.Equal(t, http.StatusOK, put.Code, "%s", put.Body.String())
	cleared, err := env.st.Queries().GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	assert.Empty(t, cleared.GivenName, "explicit empty name object must clear given_name")
	assert.Empty(t, cleared.FamilyName, "explicit empty name object must clear family_name")
	assert.Empty(t, cleared.DisplayName, "explicit empty name object must clear display_name")
}

// TestCreateUser_CrossProviderLink_RequiresTrust pins spec 29 S14: a passwordless
// user already OWNED by one identity provider must not be silently claimed by a
// SECOND provider via email — a lower-trust IdP's SCIM token could otherwise
// seize a higher-trust IdP's passwordless SSO user. The HasPassword guard does
// not cover this (the user is passwordless); the cross-provider guard does.
func TestCreateUser_CrossProviderLink_RequiresTrust(t *testing.T) {
	setup := func(t *testing.T) (env *scimTestEnv, email, userID, slugB, tokenB, providerB string) {
		env = setupSCIM(t)
		setProviderFlags(t, env, env.providerID, map[string]any{"auto_link_by_email": true})
		email = "sso-" + testutil.NewID()[:6] + "@corp.com"
		userID = createPasswordlessUser(t, env, email)
		// Provider A legitimately claims the passwordless user (first link).
		require.Equal(t, http.StatusCreated, postSCIMUser(t, env, email).Code)
		require.True(t, providerOwnsUser(t, env, env.providerID, userID))
		// A second provider appears.
		slugB, tokenB, providerB = secondSCIMProvider(t, env)
		return
	}

	postAsB := func(t *testing.T, env *scimTestEnv, slugB, tokenB, email string) *httptest.ResponseRecorder {
		return scimReq(t, env, slugB, tokenB, http.MethodPost, "/Users", map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName":   email,
			"externalId": "extB-" + testutil.NewID(),
			"active":     true,
		})
	}

	t.Run("second_provider_refused_without_trust", func(t *testing.T) {
		env, email, userID, slugB, tokenB, providerB := setup(t)
		setProviderFlags(t, env, providerB, map[string]any{"auto_link_by_email": true})

		w := postAsB(t, env, slugB, tokenB, email)
		assert.Equal(t, http.StatusConflict, w.Code,
			"a user owned by another provider must not be cross-linked without trust opt-in: %s", w.Body.String())
		assert.False(t, providerOwnsUser(t, env, providerB, userID),
			"provider B must NOT gain a link to a user owned by provider A")
	})

	t.Run("second_provider_allowed_with_trust", func(t *testing.T) {
		env, email, userID, slugB, tokenB, providerB := setup(t)
		setProviderFlags(t, env, providerB, map[string]any{"auto_link_by_email": true, "trust_email_assertions": true})

		w := postAsB(t, env, slugB, tokenB, email)
		assert.Equal(t, http.StatusCreated, w.Code, "%s", w.Body.String())
		assert.True(t, providerOwnsUser(t, env, providerB, userID),
			"with trust_email_assertions provider B may cross-link")
	})
}
