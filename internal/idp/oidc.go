// Package idp provides identity provider integration for OIDC SSO.
package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
	GroupClaim        string
}

// NewOIDCProvider creates a new OIDC provider by performing discovery.
func NewOIDCProvider(ctx context.Context, cfg ProviderConfig) (*OIDCProvider, error) {
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
	}, nil
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
		oauth2.S256ChallengeOption(codeVerifier),
	}
	return p.OAuth2Cfg.Exchange(ctx, code, opts...)
}

// UserClaims holds the extracted claims from an OIDC id_token or userinfo.
type UserClaims struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

// VerifyAndExtractClaims verifies the id_token and extracts claims.
func (p *OIDCProvider) VerifyAndExtractClaims(ctx context.Context, oauth2Token *oauth2.Token, expectedNonce string) (*UserClaims, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
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

	if email, ok := claims["email"].(string); ok {
		userClaims.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		userClaims.Name = name
	}

	// Extract groups from the configured claim
	if p.GroupClaim != "" {
		userClaims.Groups = extractGroups(claims, p.GroupClaim)
	}

	return userClaims, nil
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
