package identity_test

// The single-sign-on flow, driven against a LOCAL identity provider.
//
// The provider is a real OIDC endpoint: real discovery, a real JWKS, a
// real signed id_token. Nothing about the exchange is stubbed, so the
// nonce check, the PKCE verifier and the state consumption are all
// exercised as written.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"connectrpc.com/connect"
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/idp"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestListAuthMethods_ReturnsEnabledProvidersAndNothingAboutTheEmail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.insertProvider("corp", nil)
	f.insertProvider("retired", func(s *providerSeed) { s.Enabled = false })
	known := f.seedSubject()

	forKnown, err := f.client.ListAuthMethods(f.ctx(), connect.NewRequest(&pmv1.ListAuthMethodsRequest{
		Email: known.Email,
	}))
	require.NoError(t, err)
	forUnknown, err := f.client.ListAuthMethods(f.ctx(), connect.NewRequest(&pmv1.ListAuthMethodsRequest{
		Email: "nobody@test.example",
	}))
	require.NoError(t, err)

	require.Len(t, forKnown.Msg.Providers, 1)
	assert.Equal(t, "corp", forKnown.Msg.Providers[0].Slug, "a disabled provider is not offered")
	assert.Equal(t, len(forKnown.Msg.Providers), len(forUnknown.Msg.Providers),
		"the answer must not depend on whether the address has an account here")
	assert.Equal(t, forKnown.Msg.Providers[0].Slug, forUnknown.Msg.Providers[0].Slug)
}

func TestGetSSOLoginURL_MintsStateAndRecordsOnlyItsDigest(t *testing.T) {
	t.Parallel()
	oidc := newOIDCDouble(t)
	f := newFixture(t, withProviderFactory(loopbackProviderFactory))
	providerID := f.insertProvider("corp", func(s *providerSeed) { s.IssuerURL = oidc.URL })

	resp, err := f.client.GetSSOLoginURL(f.ctx(), connect.NewRequest(&pmv1.GetSSOLoginURLRequest{
		Slug: "corp", RedirectUrl: testBaseURL + "/auth/callback",
	}))
	require.NoError(t, err)

	parsed, err := url.Parse(resp.Msg.LoginUrl)
	require.NoError(t, err)
	state := parsed.Query().Get("state")
	require.NotEmpty(t, state)
	assert.NotEmpty(t, parsed.Query().Get("code_challenge"), "the flow is PKCE-protected")
	assert.Equal(t, "S256", parsed.Query().Get("code_challenge_method"))
	assert.NotEmpty(t, parsed.Query().Get("nonce"))

	var storedProvider string
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT provider_id FROM auth_states WHERE state = $1`, state).Scan(&storedProvider))
	assert.Equal(t, providerID, storedProvider)

	op := f.operationOfClass(powermanagev1connect.ControlServiceGetSSOLoginURLProcedure, "BACKGROUND_WRITER")
	assert.Equal(t, "BACKGROUND_WRITER", op.Class)
	assert.Empty(t, op.ActorID, "there is no subject yet")
	effect := f.effectWithAction(f.effectsOf(op.OperationID), "START_LOGIN")
	assert.Equal(t, sha256Hex(state), effect.EvidenceFingerprint,
		"the state is the flow's one-time credential and is recorded as a digest")
}

func TestGetSSOLoginURL_ReportsADisabledProviderAsAbsent(t *testing.T) {
	t.Parallel()
	f := newFixture(t, withProviderFactory(discardProviderFactory))
	f.insertProvider("retired", func(s *providerSeed) { s.Enabled = false })

	_, err := f.client.GetSSOLoginURL(f.ctx(), connect.NewRequest(&pmv1.GetSSOLoginURLRequest{
		Slug: "retired", RedirectUrl: testBaseURL + "/auth/callback",
	}))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err))

	_, err = f.client.GetSSOLoginURL(f.ctx(), connect.NewRequest(&pmv1.GetSSOLoginURLRequest{
		Slug: "never-existed", RedirectUrl: testBaseURL + "/auth/callback",
	}))
	assert.Equal(t, connect.CodeNotFound, connectCodeOf(t, err),
		"a disabled provider and an absent one look identical to an anonymous caller")
}

func TestGetSSOLoginURL_RejectsAMalformedRedirect(t *testing.T) {
	t.Parallel()
	f := newFixture(t, withProviderFactory(discardProviderFactory))
	f.insertProvider("corp", nil)

	_, err := f.client.GetSSOLoginURL(f.ctx(), connect.NewRequest(&pmv1.GetSSOLoginURLRequest{
		Slug: "corp", RedirectUrl: "not a url",
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))
	assert.Zero(t, f.countAuditOperations())
}

func TestSSOCallback_AutoCreatesASubjectAndIssuesASession(t *testing.T) {
	t.Parallel()
	oidc := newOIDCDouble(t)
	f := newFixture(t, withProviderFactory(loopbackProviderFactory))
	role := f.insertRole([]string{"GetCurrentUser"})
	f.insertProvider("corp", func(s *providerSeed) {
		s.IssuerURL = oidc.URL
		s.AutoCreateUsers = true
		s.DefaultRoleID = role
	})

	oidc.subject = "external-subject-1"
	oidc.email = "newcomer@test.example"
	oidc.emailVerified = true
	oidc.name = "New Comer"

	state := f.startLogin("corp")
	oidc.nonce = f.nonceFor(state)

	resp, err := f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "corp", Code: "auth-code", State: state,
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.User)
	assert.Equal(t, "newcomer@test.example", resp.Msg.User.Email)
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)
	require.Len(t, resp.Msg.User.RoleGrants, 1)
	assert.Equal(t, role, resp.Msg.User.RoleGrants[0].Role.Id,
		"the provider's default role is granted on auto-create")
	require.Len(t, resp.Msg.User.IdentityLinks, 1)
	row, err := f.store.GetUser(f.ctx(), resp.Msg.User.Id)
	require.NoError(t, err)
	assert.Equal(t, store.UserProvisioningSourceOIDCJIT, row.ProvisioningSource)

	op := f.operationOfClass(powermanagev1connect.ControlServiceSSOCallbackProcedure, "MUTATION")
	effects := f.effectsOf(op.OperationID)
	provision := f.effectWithAction(effects, "PROVISION")
	assert.Equal(t, sha256Hex("newcomer@test.example"), provision.EvidenceFingerprint)
	f.effectWithAction(effects, "LINK")
	f.effectWithAction(effects, "ISSUE")

	// The state was consumed, so the same code cannot be replayed.
	var remaining int
	require.NoError(t, f.raw.QueryRow(f.ctx(),
		`SELECT count(*) FROM auth_states WHERE state = $1`, state).Scan(&remaining))
	assert.Zero(t, remaining)
}

func TestSSOCallback_RefusesAReplayedState(t *testing.T) {
	t.Parallel()
	oidc := newOIDCDouble(t)
	f := newFixture(t, withProviderFactory(loopbackProviderFactory))
	f.insertProvider("corp", func(s *providerSeed) {
		s.IssuerURL = oidc.URL
		s.AutoCreateUsers = true
	})
	oidc.subject, oidc.email, oidc.emailVerified = "external-1", "person@test.example", true

	state := f.startLogin("corp")
	oidc.nonce = f.nonceFor(state)
	_, err := f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "corp", Code: "auth-code", State: state,
	}))
	require.NoError(t, err)

	_, err = f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "corp", Code: "auth-code", State: state,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err),
		"a login state is consumed exactly once")

	// The replay is recorded as a rejected authentication, distinct
	// from the successful attempt's own records.
	f.operationOfClass(powermanagev1connect.ControlServiceSSOCallbackProcedure, "REJECTED_AUTHENTICATION")
}

// The account-takeover guard: a provider may not bind an address that
// already belongs to a subject bound to some OTHER provider, unless the
// operator has explicitly delegated email identity to it.
func TestSSOCallback_RefusesToAutoLinkAnAlreadyBoundAccount(t *testing.T) {
	t.Parallel()
	oidc := newOIDCDouble(t)
	f := newFixture(t, withProviderFactory(loopbackProviderFactory))

	victim := f.seedSubject()
	firstProvider := f.insertProvider("first", nil)
	f.insertIdentityLink(victim.ID, firstProvider, "first-subject")

	f.insertProvider("attacker", func(s *providerSeed) {
		s.IssuerURL = oidc.URL
		s.AutoLinkByEmail = true
		s.TrustEmailAssertions = false
	})
	oidc.subject, oidc.email, oidc.emailVerified = "attacker-subject", victim.Email, true

	state := f.startLogin("attacker")
	oidc.nonce = f.nonceFor(state)
	_, err := f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "attacker", Code: "auth-code", State: state,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))

	links, err := f.store.ListIdentityLinksForUser(f.ctx(), victim.ID)
	require.NoError(t, err)
	assert.Len(t, links, 1, "the victim's account gained no second binding")
}

// With the operator's explicit opt-in the same flow links, because the
// operator has delegated email identity to that provider.
func TestSSOCallback_LinksAnAlreadyBoundAccountWhenEmailAssertionsAreTrusted(t *testing.T) {
	t.Parallel()
	oidc := newOIDCDouble(t)
	f := newFixture(t, withProviderFactory(loopbackProviderFactory))

	subject := f.seedSubject()
	first := f.insertProvider("first", nil)
	f.insertIdentityLink(subject.ID, first, "first-subject")

	f.insertProvider("second", func(s *providerSeed) {
		s.IssuerURL = oidc.URL
		s.AutoLinkByEmail = true
		s.TrustEmailAssertions = true
	})
	oidc.subject, oidc.email, oidc.emailVerified = "second-subject", subject.Email, true

	state := f.startLogin("second")
	oidc.nonce = f.nonceFor(state)
	resp, err := f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "second", Code: "auth-code", State: state,
	}))
	require.NoError(t, err)
	assert.Equal(t, subject.ID, resp.Msg.User.Id)

	links, err := f.store.ListIdentityLinksForUser(f.ctx(), subject.ID)
	require.NoError(t, err)
	assert.Len(t, links, 2)
}

// An account with no binding yet is the ordinary invite flow and links
// without the operator opt-in.
func TestSSOCallback_LinksAnUnboundAccountByEmail(t *testing.T) {
	t.Parallel()
	oidc := newOIDCDouble(t)
	f := newFixture(t, withProviderFactory(loopbackProviderFactory))
	invited := f.seedSubject()
	f.insertProvider("corp", func(s *providerSeed) {
		s.IssuerURL = oidc.URL
		s.AutoLinkByEmail = true
	})
	oidc.subject, oidc.email, oidc.emailVerified = "corp-subject", invited.Email, true

	state := f.startLogin("corp")
	oidc.nonce = f.nonceFor(state)
	resp, err := f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "corp", Code: "auth-code", State: state,
	}))
	require.NoError(t, err)
	assert.Equal(t, invited.ID, resp.Msg.User.Id)
}

// An unverified email claim is not usable for linking or creating: the
// provider asserting it is the party the guard defends against.
func TestSSOCallback_IgnoresAnUnverifiedEmailClaim(t *testing.T) {
	t.Parallel()
	oidc := newOIDCDouble(t)
	f := newFixture(t, withProviderFactory(loopbackProviderFactory))
	invited := f.seedSubject()
	f.insertProvider("corp", func(s *providerSeed) {
		s.IssuerURL = oidc.URL
		s.AutoLinkByEmail = true
		s.AutoCreateUsers = true
	})
	oidc.subject, oidc.email, oidc.emailVerified = "corp-subject", invited.Email, false

	state := f.startLogin("corp")
	oidc.nonce = f.nonceFor(state)
	_, err := f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "corp", Code: "auth-code", State: state,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))

	links, err := f.store.ListIdentityLinksForUser(f.ctx(), invited.ID)
	require.NoError(t, err)
	assert.Empty(t, links)
}

func TestSSOCallback_RefusesADisabledSubject(t *testing.T) {
	t.Parallel()
	oidc := newOIDCDouble(t)
	f := newFixture(t, withProviderFactory(loopbackProviderFactory))
	subject := f.seedSubject()
	_, err := f.raw.Exec(f.ctx(), `UPDATE users SET disabled = TRUE WHERE id = $1`, subject.ID)
	require.NoError(t, err)

	providerID := f.insertProvider("corp", func(s *providerSeed) { s.IssuerURL = oidc.URL })
	f.insertIdentityLink(subject.ID, providerID, "corp-subject")
	oidc.subject, oidc.email, oidc.emailVerified = "corp-subject", subject.Email, true

	state := f.startLogin("corp")
	oidc.nonce = f.nonceFor(state)
	_, err = f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "corp", Code: "auth-code", State: state,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err),
		"a verified external identity does not resurrect a retired subject")
}

// A state minted for one provider cannot be redeemed at another.
func TestSSOCallback_RefusesAStateFromAnotherProvider(t *testing.T) {
	t.Parallel()
	oidc := newOIDCDouble(t)
	f := newFixture(t, withProviderFactory(loopbackProviderFactory))
	f.insertProvider("first", func(s *providerSeed) { s.IssuerURL = oidc.URL })
	f.insertProvider("second", func(s *providerSeed) { s.IssuerURL = oidc.URL; s.AutoCreateUsers = true })

	state := f.startLogin("first")
	_, err := f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "second", Code: "auth-code", State: state,
	}))
	assert.Equal(t, connect.CodeUnauthenticated, connectCodeOf(t, err))
}

func TestSSOCallback_RejectsAMissingCode(t *testing.T) {
	t.Parallel()
	f := newFixture(t, withProviderFactory(discardProviderFactory))
	f.insertProvider("corp", nil)

	_, err := f.client.SSOCallback(f.ctx(), connect.NewRequest(&pmv1.SSOCallbackRequest{
		Slug: "corp", State: "some-state",
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))
	assert.Zero(t, f.countAuditOperations())
}

// ---------------------------------------------------------------------------
// The local identity provider
// ---------------------------------------------------------------------------

// startLogin drives GetSSOLoginURL and returns the minted state.
func (f *fixture) startLogin(slug string) string {
	f.t.Helper()
	resp, err := f.client.GetSSOLoginURL(f.ctx(), connect.NewRequest(&pmv1.GetSSOLoginURLRequest{
		Slug: slug, RedirectUrl: testBaseURL + "/auth/callback",
	}))
	require.NoError(f.t, err)
	parsed, err := url.Parse(resp.Msg.LoginUrl)
	require.NoError(f.t, err)
	state := parsed.Query().Get("state")
	require.NotEmpty(f.t, state)
	return state
}

// nonceFor reads the nonce the server pinned for a login attempt, so
// the double can mint an id_token that actually satisfies the check.
func (f *fixture) nonceFor(state string) string {
	f.t.Helper()
	var nonce string
	require.NoError(f.t, f.raw.QueryRow(f.ctx(),
		`SELECT nonce FROM auth_states WHERE state = $1`, state).Scan(&nonce))
	return nonce
}

// oidcDouble is a minimal but REAL OpenID provider: discovery, a JWKS
// and a token endpoint that returns a properly signed id_token.
type oidcDouble struct {
	URL           string
	key           *rsa.PrivateKey
	keyID         string
	subject       string
	email         string
	emailVerified bool
	name          string
	nonce         string
	groups        []string
}

func newOIDCDouble(t *testing.T) *oidcDouble {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	d := &oidcDouble{key: key, keyID: "test-key"}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	d.URL = srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"userinfo_endpoint":                     srv.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     d.keyID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		writeJSON(w, map[string]any{
			"access_token": "double-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     d.idToken(t, srv.URL),
		})
	})
	return d
}

func (d *oidcDouble) idToken(t *testing.T, issuer string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: d.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", d.keyID),
	)
	require.NoError(t, err)

	now := time.Now()
	claims := map[string]any{
		"iss":            issuer,
		"sub":            d.subject,
		"aud":            "client-id",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"nonce":          d.nonce,
		"email":          d.email,
		"email_verified": d.emailVerified,
		"name":           d.name,
	}
	if len(d.groups) > 0 {
		claims["groups"] = d.groups
	}
	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// loopbackProviderFactory builds the SAME idp.OIDCProvider production
// uses — its AuthCodeURL, ExchangeCode and VerifyAndExtractClaims are
// the code under test — but performs discovery over an ordinary HTTP
// client.
//
// Production wraps discovery in a client whose dial control refuses
// internal addresses, which correctly blocks the loopback double. That
// guard is a property of the outbound client, not of the exchange
// logic, and it is unit-tested where it lives: internal/idp exercises
// ssrfSafeDialControl directly.
func loopbackProviderFactory(ctx context.Context, cfg idp.ProviderConfig) (*idp.OIDCProvider, error) {
	provider, err := coreoidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{coreoidc.ScopeOpenID, "profile", "email"}
	}
	endpoint := provider.Endpoint()
	if cfg.AuthorizationURL != "" {
		endpoint.AuthURL = cfg.AuthorizationURL
	}
	if cfg.TokenURL != "" {
		endpoint.TokenURL = cfg.TokenURL
	}
	return &idp.OIDCProvider{
		Provider: provider,
		OAuth2Cfg: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     endpoint,
			Scopes:       scopes,
			RedirectURL:  cfg.RedirectURL,
		},
		Verifier:    provider.Verifier(&coreoidc.Config{ClientID: cfg.ClientID}),
		GroupClaim:  cfg.GroupClaim,
		UserinfoURL: cfg.UserinfoURL,
	}, nil
}
