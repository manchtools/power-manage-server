package scim_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/testutil"
)

// rawSCIMReq issues a GET /Users with an explicit Authorization header value
// (or none when authHeader == "") against the given slug.
func rawSCIMReq(env *scimTestEnv, slug, authHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/"+slug+"/Users", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	return w
}

// TestSCIMAuth_RejectionMatrix pins every fail-closed branch of withAuth: all
// malformed/credential failures return 401 (slug-shape errors aside).
func TestSCIMAuth_RejectionMatrix(t *testing.T) {
	env := setupSCIM(t)
	valid := env.token

	cases := []struct {
		name   string
		header string
	}{
		{"basic_scheme", "Basic " + valid},
		{"bare_token_no_bearer", valid},
		{"bearer_empty_token", "Bearer "},
		{"missing_header", ""},
		{"wrong_token_bytes", "Bearer not-the-real-token"},
		{"byte_tampered_token", "Bearer " + flipLastChar(valid)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := rawSCIMReq(env, env.slug, tc.header)
			assert.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
		})
	}

	t.Run("unknown_slug", func(t *testing.T) {
		w := rawSCIMReq(env, "no-such-slug-"+testutil.NewID()[:6], "Bearer "+valid)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// TestSCIMAuth_DisabledProviderStillGated pins #5: a provider with
// scim_enabled=true but enabled=false (disabled for login) must reject SCIM
// even with a valid bearer.
func TestSCIMAuth_DisabledProviderStillGated(t *testing.T) {
	env := setupSCIM(t)
	// Provider is SCIM-enabled with a valid token; now disable it for login.
	setProviderFlags(t, env, env.providerID, map[string]any{"enabled": false})

	w := rawSCIMReq(env, env.slug, "Bearer "+env.token)
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"a login-disabled provider must reject SCIM even with a valid token")
}

// TestSCIMAuth_ScimDisabledProviderGated pins #11: a provider that never had
// SCIM enabled (scim_enabled=false) rejects even a valid-looking bearer.
func TestSCIMAuth_ScimDisabledProviderGated(t *testing.T) {
	env := setupSCIM(t)
	slug := "no-scim-" + testutil.NewID()[:8]
	_ = testutil.CreateTestIdentityProvider(t, env.st, env.enc, env.adminID, "No SCIM", slug)
	// No EnableSCIMForProvider call → scim_enabled stays false.

	w := rawSCIMReq(env, slug, "Bearer some-token")
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"a provider without SCIM enabled must reject SCIM")
}

// TestSCIMAuth_UnknownSlugIsTimingIndistinguishable pins #9: the unknown-slug
// path and the wrong-token path return the SAME status and SAME body, so a
// client cannot distinguish "provider exists" from "wrong token" via the
// response (the constant-time bcrypt on the unknown path equalises timing too).
func TestSCIMAuth_UnknownSlugIsTimingIndistinguishable(t *testing.T) {
	env := setupSCIM(t)

	unknown := rawSCIMReq(env, "ghost-"+testutil.NewID()[:6], "Bearer "+env.token)
	wrongToken := rawSCIMReq(env, env.slug, "Bearer definitely-wrong")

	require.Equal(t, http.StatusUnauthorized, unknown.Code)
	require.Equal(t, http.StatusUnauthorized, wrongToken.Code)
	assert.Equal(t, wrongToken.Code, unknown.Code, "status must match across unknown-slug and wrong-token")
	assert.Equal(t, wrongToken.Body.String(), unknown.Body.String(),
		"body must be identical (no provider-existence oracle)")
	assert.Contains(t, unknown.Body.String(), "invalid credentials")
}

func flipLastChar(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[len(b)-1] == 'a' {
		b[len(b)-1] = 'b'
	} else {
		b[len(b)-1] = 'a'
	}
	return string(b)
}
