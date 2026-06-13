// Package idp provides identity provider integration for OIDC SSO.
package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider wraps the go-oidc provider and OAuth2 config.
type OIDCProvider struct {
	Provider    *oidc.Provider
	OAuth2Cfg   oauth2.Config
	Verifier    *oidc.IDTokenVerifier
	GroupClaim  string
	UserinfoURL string
	// httpClient bounds every outbound OIDC call (discovery, token exchange,
	// lazy JWKS keyset fetch) with connect/handshake/response timeouts (WS5
	// #6/#14). Without it go-oidc falls back to http.DefaultClient, which has
	// no timeout — a slow/hung IdP (or an attacker-controlled one reached via a
	// public SSOCallback) could hang a request indefinitely. Threaded into
	// every call via oidc.ClientContext.
	httpClient *http.Client
}

// oidcHTTPTimeout is the overall per-request ceiling for outbound OIDC calls.
// A package var (not a const) so tests can shrink it to assert the timeout
// fires without a multi-second wait.
var oidcHTTPTimeout = 12 * time.Second

// newBoundedOIDCClient returns an *http.Client with connect, TLS-handshake,
// response-header and overall timeouts so no outbound OIDC call can hang.
func newBoundedOIDCClient() *http.Client {
	return &http.Client{
		Timeout: oidcHTTPTimeout,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second,
		},
	}
}

// ProviderConfig holds the configuration needed to create an OIDC provider.
type ProviderConfig struct {
	IssuerURL        string
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	ClientID         string
	ClientSecret     string
	Scopes           []string
	RedirectURL      string
	GroupClaim       string
}

// NewOIDCProvider creates a new OIDC provider by performing discovery.
func NewOIDCProvider(ctx context.Context, cfg ProviderConfig) (*OIDCProvider, error) {
	httpClient := newBoundedOIDCClient()
	// Inject the bounded client BEFORE discovery; go-oidc stores it
	// (getClient(ctx)) and threads it into the lazy keyset fetch the Verifier
	// uses, so the JWKS GET inherits the same timeout.
	ctx = oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	endpoint := provider.Endpoint()
	if cfg.AuthorizationURL != "" {
		endpoint.AuthURL = cfg.AuthorizationURL
	}
	if cfg.TokenURL != "" {
		endpoint.TokenURL = cfg.TokenURL
	}

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       scopes,
		RedirectURL:  cfg.RedirectURL,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	userinfoURL := cfg.UserinfoURL
	if userinfoURL == "" {
		// Use the one from discovery
		var claims struct {
			UserinfoEndpoint string `json:"userinfo_endpoint"`
		}
		if err := provider.Claims(&claims); err == nil {
			userinfoURL = claims.UserinfoEndpoint
		}
	}

	return &OIDCProvider{
		Provider:    provider,
		OAuth2Cfg:   oauth2Cfg,
		Verifier:    verifier,
		GroupClaim:  cfg.GroupClaim,
		UserinfoURL: userinfoURL,
		httpClient:  httpClient,
	}, nil
}

// clientCtx threads the bounded HTTP client onto ctx so token exchange and the
// lazy JWKS keyset fetch (during Verify) inherit the connect/response timeouts.
func (p *OIDCProvider) clientCtx(ctx context.Context) context.Context {
	if p.httpClient == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, p.httpClient)
}

// AuthCodeURL generates the authorization URL with PKCE and nonce.
func (p *OIDCProvider) AuthCodeURL(state, nonce, codeVerifier string) string {
	opts := []oauth2.AuthCodeOption{
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(codeVerifier),
	}
	return p.OAuth2Cfg.AuthCodeURL(state, opts...)
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.VerifierOption(codeVerifier),
	}
	return p.OAuth2Cfg.Exchange(p.clientCtx(ctx), code, opts...)
}

// UserClaims holds the extracted claims from an OIDC id_token or userinfo.
type UserClaims struct {
	Subject           string
	Email             string
	Name              string
	GivenName         string
	FamilyName        string
	PreferredUsername string
	Picture           string
	Locale            string
	Groups            []string
}

// VerifyAndExtractClaims verifies the id_token and extracts claims.
func (p *OIDCProvider) VerifyAndExtractClaims(ctx context.Context, oauth2Token *oauth2.Token, expectedNonce string) (*UserClaims, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := p.Verifier.Verify(p.clientCtx(ctx), rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}

	if idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("nonce mismatch")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extract claims: %w", err)
	}

	userClaims := &UserClaims{
		Subject: idToken.Subject,
	}

	// Only trust the email for linking / auto-create when the IdP asserts it
	// is verified (#359). Without this gate, an attacker who can set an
	// arbitrary, unverified email at the IdP (common with multi-tenant Azure
	// AD or self-service IdPs) could set it to a local admin's address and,
	// with AutoLinkByEmail on, receive that admin's session. The external
	// identity is keyed on the subject regardless; only the email field —
	// which the linker uses for auto-link/auto-create — is gated.
	if email, ok := claims["email"].(string); ok && email != "" {
		if claimIsTrue(claims["email_verified"]) {
			userClaims.Email = email
		} else {
			slog.Warn("SSO: ignoring email claim because email_verified is not true; it will not be used for auto-link or auto-create",
				"subject", idToken.Subject)
		}
	}
	if name, ok := claims["name"].(string); ok {
		userClaims.Name = name
	}
	if v, ok := claims["given_name"].(string); ok {
		userClaims.GivenName = v
	}
	if v, ok := claims["family_name"].(string); ok {
		userClaims.FamilyName = v
	}
	if v, ok := claims["preferred_username"].(string); ok {
		userClaims.PreferredUsername = v
	}
	if v, ok := claims["picture"].(string); ok {
		userClaims.Picture = v
	}
	if v, ok := claims["locale"].(string); ok {
		userClaims.Locale = v
	}

	// Extract groups from the configured claim
	if p.GroupClaim != "" {
		userClaims.Groups = extractGroups(claims, p.GroupClaim)
	}

	return userClaims, nil
}

// claimIsTrue interprets an OIDC boolean claim. The spec defines
// email_verified as a JSON boolean, but some IdPs (and some proxies) emit it
// as the string "true"/"false"; accept both. Anything else — including an
// absent claim — is treated as not-true, which is the fail-closed default.
func claimIsTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	}
	return false
}

// extractGroups extracts group names from claims.
// Supports nested claims using dot notation (e.g. "realm_access.roles").
func extractGroups(claims map[string]any, claimName string) []string {
	var value any

	// Support nested claims with dot notation
	parts := strings.Split(claimName, ".")
	current := claims
	for i, part := range parts {
		v, ok := current[part]
		if !ok {
			return nil
		}
		if i == len(parts)-1 {
			value = v
		} else {
			next, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			current = next
		}
	}

	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case []any:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				groups = append(groups, s)
			}
		}
		return groups
	case string:
		// Some providers return space-separated groups
		return strings.Fields(v)
	default:
		// Try JSON unmarshal
		data, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		var groups []string
		if err := json.Unmarshal(data, &groups); err != nil {
			return nil
		}
		return groups
	}
}
