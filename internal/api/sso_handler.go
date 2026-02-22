package api

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/idp"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// SSOHandler handles SSO authentication flow RPCs.
type SSOHandler struct {
	store              *store.Store
	jwtManager         *auth.JWTManager
	enc                *crypto.Encryptor
	passwordAuthEnabled bool
	callbackBaseURL    string
}

// NewSSOHandler creates a new SSO handler.
func NewSSOHandler(st *store.Store, jwtManager *auth.JWTManager, enc *crypto.Encryptor, passwordAuthEnabled bool, callbackBaseURL string) *SSOHandler {
	return &SSOHandler{
		store:              st,
		jwtManager:         jwtManager,
		enc:                enc,
		passwordAuthEnabled: passwordAuthEnabled,
		callbackBaseURL:    callbackBaseURL,
	}
}

// ListAuthMethods returns the available authentication methods.
func (h *SSOHandler) ListAuthMethods(ctx context.Context, req *connect.Request[pm.ListAuthMethodsRequest]) (*connect.Response[pm.ListAuthMethodsResponse], error) {
	resp := &pm.ListAuthMethodsResponse{
		PasswordEnabled: h.passwordAuthEnabled,
	}

	// If email is provided, check user-specific auth methods
	if req.Msg.Email != "" {
		user, err := h.store.Queries().GetUserByEmail(ctx, req.Msg.Email)
		if err == nil {
			resp.TotpEnabled = user.TotpEnabled

			// Check if any linked provider disables password
			if h.passwordAuthEnabled {
				disablingProviders, err := h.store.Queries().GetLinkedProvidersDisablingPassword(ctx, user.ID)
				if err == nil && len(disablingProviders) > 0 {
					resp.PasswordEnabled = false
				}
			}
		}
		// If user not found, don't reveal it — just show global defaults
	}

	// List enabled providers
	providers, err := h.store.Queries().ListEnabledIdentityProviders(ctx)
	if err == nil {
		for _, p := range providers {
			resp.Providers = append(resp.Providers, &pm.AuthMethodProvider{
				Slug:         p.Slug,
				Name:         p.Name,
				ProviderType: p.ProviderType,
			})
		}
	}

	return connect.NewResponse(resp), nil
}

// GetSSOLoginURL generates the SSO authorization URL.
func (h *SSOHandler) GetSSOLoginURL(ctx context.Context, req *connect.Request[pm.GetSSOLoginURLRequest]) (*connect.Response[pm.GetSSOLoginURLResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	provider, err := h.store.Queries().GetIdentityProviderBySlug(ctx, req.Msg.Slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("provider not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get provider"))
	}

	if !provider.Enabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("provider is disabled"))
	}

	// Decrypt client secret
	clientSecret, err := h.enc.Decrypt(provider.ClientSecretEncrypted)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to decrypt client secret"))
	}

	// Generate state, nonce, and PKCE code verifier
	state, err := idp.GenerateState()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate state"))
	}
	nonce, err := idp.GenerateNonce()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate nonce"))
	}
	codeVerifier, err := idp.GenerateCodeVerifier()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate code verifier"))
	}

	// Store auth state (10 min expiry)
	expiresAt := time.Now().Add(10 * time.Minute)
	err = h.store.Queries().CreateAuthState(ctx, db.CreateAuthStateParams{
		State:        state,
		ProviderID:   provider.ID,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		RedirectUri:  req.Msg.RedirectUrl,
		ExpiresAt:    pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		slog.Error("failed to store auth state", "error", err, "provider", provider.Slug)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to store auth state"))
	}

	slog.Info("SSO auth state created", "provider", provider.Slug, "state_prefix", state[:8], "expires_at", expiresAt.UTC())

	// Create OIDC provider and generate auth URL
	callbackURL := h.callbackBaseURL + "/auth/callback/" + provider.Slug
	oidcProvider, err := idp.NewOIDCProvider(ctx, idp.ProviderConfig{
		IssuerURL:        provider.IssuerUrl,
		AuthorizationURL: provider.AuthorizationUrl,
		TokenURL:         provider.TokenUrl,
		UserinfoURL:      provider.UserinfoUrl,
		ClientID:         provider.ClientID,
		ClientSecret:     clientSecret,
		Scopes:           provider.Scopes,
		RedirectURL:      callbackURL,
		GroupClaim:        provider.GroupClaim,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to initialize OIDC provider"))
	}

	loginURL := oidcProvider.AuthCodeURL(state, nonce, codeVerifier)

	return connect.NewResponse(&pm.GetSSOLoginURLResponse{
		LoginUrl: loginURL,
	}), nil
}

// SSOCallback handles the OIDC callback after user authentication.
func (h *SSOHandler) SSOCallback(ctx context.Context, req *connect.Request[pm.SSOCallbackRequest]) (*connect.Response[pm.SSOCallbackResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Look up and validate auth state
	statePrefix := req.Msg.State
	if len(statePrefix) > 8 {
		statePrefix = statePrefix[:8]
	}
	slog.Info("SSO callback received", "slug", req.Msg.Slug, "state_prefix", statePrefix)

	authState, err := h.store.Queries().ConsumeAuthState(ctx, req.Msg.State)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("SSO auth state not found or expired", "state_prefix", statePrefix, "slug", req.Msg.Slug)
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired state"))
		}
		slog.Error("SSO auth state lookup failed", "error", err, "state_prefix", statePrefix)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to validate state"))
	}

	// Get provider
	provider, err := h.store.Queries().GetIdentityProviderByID(ctx, authState.ProviderID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get provider"))
	}

	if !provider.Enabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("provider is disabled"))
	}

	// Verify slug matches
	if provider.Slug != req.Msg.Slug {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("slug mismatch"))
	}

	// Decrypt client secret
	clientSecret, err := h.enc.Decrypt(provider.ClientSecretEncrypted)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to decrypt client secret"))
	}

	// Create OIDC provider
	callbackURL := h.callbackBaseURL + "/auth/callback/" + provider.Slug
	oidcProvider, err := idp.NewOIDCProvider(ctx, idp.ProviderConfig{
		IssuerURL:        provider.IssuerUrl,
		AuthorizationURL: provider.AuthorizationUrl,
		TokenURL:         provider.TokenUrl,
		UserinfoURL:      provider.UserinfoUrl,
		ClientID:         provider.ClientID,
		ClientSecret:     clientSecret,
		Scopes:           provider.Scopes,
		RedirectURL:      callbackURL,
		GroupClaim:        provider.GroupClaim,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to initialize OIDC provider"))
	}

	// Exchange code for tokens
	oauth2Token, err := oidcProvider.ExchangeCode(ctx, req.Msg.Code, authState.CodeVerifier)
	if err != nil {
		slog.Error("SSO code exchange failed", "error", err, "slug", req.Msg.Slug)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("failed to exchange code"))
	}

	// Verify id_token and extract claims
	claims, err := oidcProvider.VerifyAndExtractClaims(ctx, oauth2Token, authState.Nonce)
	if err != nil {
		slog.Error("SSO id_token verification failed", "error", err, "slug", req.Msg.Slug)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("failed to verify id_token"))
	}

	slog.Info("SSO claims verified", "slug", req.Msg.Slug, "email", claims.Email, "subject", claims.Subject)

	// Link or create user
	linker := idp.NewLinker(h.store.Queries(), &storeEventAdapter{store: h.store})
	linkResult, err := linker.LinkOrCreate(ctx, provider, claims)
	if err != nil {
		slog.Warn("SSO user link/create failed", "error", err, "slug", req.Msg.Slug, "email", claims.Email)
		if errors.Is(err, idp.ErrNoMatchingAccount) {
			return nil, connect.NewError(connect.CodeUnauthenticated, err)
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to authenticate"))
	}

	// Get and validate user before proceeding
	user, err := h.store.Queries().GetUserByID(ctx, linkResult.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("account not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	if user.Disabled {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("account is disabled"))
	}

	// Sync group memberships (only for valid, active users)
	groupMapping := idp.ParseGroupMapping(provider.GroupMapping)
	if len(claims.Groups) > 0 && len(groupMapping) > 0 {
		if err := linker.SyncGroupMemberships(ctx, linkResult.UserID, claims.Groups, groupMapping); err != nil {
			slog.Warn("failed to sync SSO group memberships", "user_id", linkResult.UserID, "error", err)
		}
	}

	// Check if TOTP is required (don't emit login event — TOTP handler will)
	if user.TotpEnabled {
		challenge, err := h.jwtManager.GenerateTOTPChallenge(user.ID, user.Email, user.SessionVersion)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate TOTP challenge"))
		}
		return connect.NewResponse(&pm.SSOCallbackResponse{
			TotpRequired:  true,
			TotpChallenge: challenge,
		}), nil
	}

	// Emit login event (fully authenticated — no TOTP required)
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   user.ID,
		EventType:  "UserLoggedIn",
		Data: map[string]any{
			"provider": provider.Slug,
		},
		ActorType: "user",
		ActorID:   user.ID,
	}); err != nil {
		slog.Warn("failed to append UserLoggedIn event", "user_id", user.ID, "provider", provider.Slug, "error", err)
	}

	// Generate tokens
	permissions, err := h.store.Queries().GetUserPermissionsWithGroups(ctx, user.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to resolve permissions"))
	}

	tokens, err := h.jwtManager.GenerateTokens(user.ID, user.Email, permissions, user.SessionVersion)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate tokens"))
	}

	protoUser := userToProto(user)
	if roles, err := h.store.Queries().GetUserRoles(ctx, user.ID); err == nil {
		for _, r := range roles {
			protoUser.Roles = append(protoUser.Roles, roleToProto(r))
		}
	}

	return connect.NewResponse(&pm.SSOCallbackResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    timestamppb.New(tokens.ExpiresAt),
		User:         protoUser,
	}), nil
}

// storeEventAdapter adapts store.Store to the idp.EventAppender interface.
type storeEventAdapter struct {
	store *store.Store
}

func (a *storeEventAdapter) AppendEvent(ctx context.Context, event idp.EventInput) error {
	return a.store.AppendEvent(ctx, store.Event{
		StreamType: event.StreamType,
		StreamID:   event.StreamID,
		EventType:  event.EventType,
		Data:       event.Data,
		ActorType:  event.ActorType,
		ActorID:    event.ActorID,
	})
}
