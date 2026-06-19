package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"

	"connectrpc.com/connect"

	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
)

// IDPHandler handles identity provider CRUD RPCs.
type IDPHandler struct {
	store       *store.Store
	enc         *crypto.Encryptor
	scimBaseURL string
	logger      *slog.Logger
}

// NewIDPHandler creates a new identity provider handler.
func NewIDPHandler(st *store.Store, enc *crypto.Encryptor, scimBaseURL string, logger *slog.Logger) *IDPHandler {
	return &IDPHandler{store: st, enc: enc, scimBaseURL: scimBaseURL, logger: logger}
}

// CreateIdentityProvider creates a new identity provider.
func (h *IDPHandler) CreateIdentityProvider(ctx context.Context, req *connect.Request[pm.CreateIdentityProviderRequest]) (*connect.Response[pm.CreateIdentityProviderResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Check for duplicate slug
	_, err = h.store.Repos().IdentityProvider.GetBySlug(ctx, req.Msg.Slug)
	if err == nil {
		return nil, apiErrorCtx(ctx, ErrProviderSlugExists, connect.CodeAlreadyExists, "provider with this slug already exists")
	}
	if !store.IsNotFound(err) {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check slug")
	}

	// Encrypt client secret
	encryptedSecret, err := h.enc.Encrypt(req.Msg.ClientSecret)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to encrypt client secret")
	}

	groupMappingJSON, _ := json.Marshal(req.Msg.GroupMapping)

	id := newULID()
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "identity_provider",
		StreamID:   id,
		EventType:  string(eventtypes.IdentityProviderCreated),
		Data: payloads.IdentityProviderCreated{
			Name:                  req.Msg.Name,
			Slug:                  req.Msg.Slug,
			ProviderType:          identityProviderTypeToString(req.Msg.ProviderType),
			ClientID:              req.Msg.ClientId,
			ClientSecretEncrypted: encryptedSecret,
			IssuerURL:             req.Msg.IssuerUrl,
			AuthorizationURL:      req.Msg.AuthorizationUrl,
			TokenURL:              req.Msg.TokenUrl,
			UserinfoURL:           req.Msg.UserinfoUrl,
			Scopes:                req.Msg.Scopes,
			AutoCreateUsers:       req.Msg.AutoCreateUsers,
			// AutoLinkByEmail defaults to FALSE for new providers
			// (proto bool default) and must be explicitly enabled
			// by the operator (audit F-28). Enabling it makes the
			// IdP's email-verification policy a hard dependency
			// for the local-account trust boundary — an IdP that
			// returns unverified emails would let an attacker hijack
			// a local user by signing into the IdP with the
			// victim's email address. Document this in operator
			// guidance before flipping the default.
			AutoLinkByEmail:          req.Msg.AutoLinkByEmail,
			TrustEmailAssertions:     req.Msg.TrustEmailAssertions,
			DefaultRoleID:            req.Msg.DefaultRoleId,
			DisablePasswordForLinked: req.Msg.DisablePasswordForLinked,
			GroupClaim:               req.Msg.GroupClaim,
			GroupMapping:             json.RawMessage(groupMappingJSON),
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to create provider"); err != nil {
		return nil, err
	}

	provider, err := h.store.Repos().IdentityProvider.Get(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to read back provider")
	}

	return connect.NewResponse(&pm.CreateIdentityProviderResponse{
		Provider: h.idpToProto(provider),
	}), nil
}

// GetIdentityProvider returns an identity provider by ID.
func (h *IDPHandler) GetIdentityProvider(ctx context.Context, req *connect.Request[pm.GetIdentityProviderRequest]) (*connect.Response[pm.GetIdentityProviderResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	provider, err := h.store.Repos().IdentityProvider.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrProviderNotFound, "provider not found")
	}

	return connect.NewResponse(&pm.GetIdentityProviderResponse{
		Provider: h.idpToProto(provider),
	}), nil
}

// ListIdentityProviders returns a paginated list of identity providers.
func (h *IDPHandler) ListIdentityProviders(ctx context.Context, req *connect.Request[pm.ListIdentityProvidersRequest]) (*connect.Response[pm.ListIdentityProvidersResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	providers, err := h.store.Repos().IdentityProvider.List(ctx, store.ListIdentityProvidersFilter{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list providers")
	}

	count, err := h.store.Repos().IdentityProvider.Count(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count providers")
	}

	nextPageToken := buildNextPageToken(int32(len(providers)), offset, pageSize, count)

	protoProviders := make([]*pm.IdentityProvider, len(providers))
	for i, p := range providers {
		protoProviders[i] = h.idpToProto(p)
	}

	return connect.NewResponse(&pm.ListIdentityProvidersResponse{
		Providers:     protoProviders,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// UpdateIdentityProvider updates an existing identity provider.
func (h *IDPHandler) UpdateIdentityProvider(ctx context.Context, req *connect.Request[pm.UpdateIdentityProviderRequest]) (*connect.Response[pm.UpdateIdentityProviderResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Verify provider exists
	_, err = h.store.Repos().IdentityProvider.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrProviderNotFound, "provider not found")
	}

	data := map[string]any{
		"name":                        req.Msg.Name,
		"enabled":                     req.Msg.Enabled,
		"auto_create_users":           req.Msg.AutoCreateUsers,
		"auto_link_by_email":          req.Msg.AutoLinkByEmail,
		"trust_email_assertions":      req.Msg.TrustEmailAssertions,
		"default_role_id":             req.Msg.DefaultRoleId,
		"disable_password_for_linked": req.Msg.DisablePasswordForLinked,
		"group_claim":                 req.Msg.GroupClaim,
	}

	if req.Msg.ClientId != "" {
		data["client_id"] = req.Msg.ClientId
	}
	if req.Msg.IssuerUrl != "" {
		data["issuer_url"] = req.Msg.IssuerUrl
	}
	data["authorization_url"] = req.Msg.AuthorizationUrl
	data["token_url"] = req.Msg.TokenUrl
	data["userinfo_url"] = req.Msg.UserinfoUrl

	if len(req.Msg.Scopes) > 0 {
		data["scopes"] = req.Msg.Scopes
	}

	if req.Msg.ClientSecret != "" {
		encryptedSecret, err := h.enc.Encrypt(req.Msg.ClientSecret)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to encrypt client secret")
		}
		data["client_secret_encrypted"] = encryptedSecret
	}

	if req.Msg.GroupMapping != nil {
		groupMappingJSON, _ := json.Marshal(req.Msg.GroupMapping)
		data["group_mapping"] = json.RawMessage(groupMappingJSON)
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "identity_provider",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.IdentityProviderUpdated),
		Data:       data,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to update provider"); err != nil {
		return nil, err
	}

	provider, err := h.store.Repos().IdentityProvider.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to read back provider")
	}

	return connect.NewResponse(&pm.UpdateIdentityProviderResponse{
		Provider: h.idpToProto(provider),
	}), nil
}

// DeleteIdentityProvider deletes an identity provider.
func (h *IDPHandler) DeleteIdentityProvider(ctx context.Context, req *connect.Request[pm.DeleteIdentityProviderRequest]) (*connect.Response[pm.DeleteIdentityProviderResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	providerID := req.Msg.Id

	// Find all identity links for this provider before deleting it.
	links, err := h.store.Queries().ListIdentityLinksByProvider(ctx, providerID)
	if err != nil {
		h.logger.Error("failed to list identity links for provider", "provider_id", providerID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to delete provider")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "identity_provider",
		StreamID:   providerID,
		EventType:  string(eventtypes.IdentityProviderDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete provider"); err != nil {
		return nil, err
	}

	// Unlink all users from this provider and auto-delete orphaned passwordless users.
	for _, link := range links {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "identity_provider",
			StreamID:   link.ID,
			EventType:  string(eventtypes.IdentityUnlinked),
			Data:       map[string]any{},
			ActorType:  "user",
			ActorID:    userCtx.ID,
		}); err != nil {
			h.logger.Error("failed to unlink identity on provider delete", "link_id", link.ID, "user_id", link.UserID, "error", err)
			continue
		}
		h.logger.Debug("event appended",
			"request_id", middleware.RequestIDFromContext(ctx),
			"stream_type", "identity_provider",
			"stream_id", link.ID,
			"event_type", "IdentityUnlinked",
		)

		// If the user has no remaining identity links and no password, delete them.
		if link.HasPassword {
			continue
		}
		remaining, err := h.store.Queries().CountIdentityLinksForUser(ctx, link.UserID)
		if err != nil {
			h.logger.Error("failed to count identity links for user", "user_id", link.UserID, "error", err)
			continue
		}
		if remaining == 0 {
			// Auto-deleting an orphaned passwordless user must not orphan the
			// deployment: route it through the same last-admin advisory lock as
			// the direct delete path, so unlinking an IdP can never remove the
			// final administrator (#5/#369). On the guard's refusal (or any
			// error) we leave the user in place rather than fail the whole
			// provider deletion — best-effort, matching the surrounding loop.
			if err := guardedAdminMutation(ctx, h.store, link.UserID, func() error {
				return h.store.AppendEvent(ctx, store.Event{
					StreamType: "user",
					StreamID:   link.UserID,
					EventType:  string(eventtypes.UserDeleted),
					Data:       map[string]any{},
					ActorType:  "user",
					ActorID:    userCtx.ID,
				})
			}); err != nil {
				h.logger.Error("failed to auto-delete orphaned user", "user_id", link.UserID, "error", err)
			} else {
				h.logger.Debug("event appended",
					"request_id", middleware.RequestIDFromContext(ctx),
					"stream_type", "user",
					"stream_id", link.UserID,
					"event_type", "UserDeleted",
				)
			}
		}
	}

	return connect.NewResponse(&pm.DeleteIdentityProviderResponse{}), nil
}

// EnableSCIM enables SCIM provisioning for an identity provider.
func (h *IDPHandler) EnableSCIM(ctx context.Context, req *connect.Request[pm.EnableSCIMRequest]) (*connect.Response[pm.EnableSCIMResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	provider, err := h.store.Repos().IdentityProvider.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrProviderNotFound, "provider not found")
	}

	if provider.ScimEnabled {
		return nil, apiErrorCtx(ctx, ErrSCIMAlreadyEnabled, connect.CodeAlreadyExists, "SCIM is already enabled for this provider")
	}

	// Generate a 32-byte random token (64 hex characters)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate token")
	}
	plainToken := hex.EncodeToString(tokenBytes)

	hashStr, err := auth.HashPassword(plainToken)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to hash token")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "identity_provider",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.IdentityProviderSCIMEnabled),
		Data: payloads.IdentityProviderSCIMEnabled{
			ScimTokenHash: hashStr,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to enable SCIM"); err != nil {
		return nil, err
	}

	endpointURL := h.scimBaseURL + "/scim/v2/" + provider.Slug

	return connect.NewResponse(&pm.EnableSCIMResponse{
		Token:       plainToken,
		EndpointUrl: endpointURL,
	}), nil
}

// DisableSCIM disables SCIM provisioning for an identity provider.
func (h *IDPHandler) DisableSCIM(ctx context.Context, req *connect.Request[pm.DisableSCIMRequest]) (*connect.Response[pm.DisableSCIMResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	provider, err := h.store.Repos().IdentityProvider.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrProviderNotFound, "provider not found")
	}

	if !provider.ScimEnabled {
		return nil, apiErrorCtx(ctx, ErrSCIMNotEnabled, connect.CodeFailedPrecondition, "SCIM is not enabled for this provider")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "identity_provider",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.IdentityProviderSCIMDisabled),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to disable SCIM"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.DisableSCIMResponse{}), nil
}

// RotateSCIMToken generates a new SCIM bearer token for an identity provider.
func (h *IDPHandler) RotateSCIMToken(ctx context.Context, req *connect.Request[pm.RotateSCIMTokenRequest]) (*connect.Response[pm.RotateSCIMTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	provider, err := h.store.Repos().IdentityProvider.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrProviderNotFound, "provider not found")
	}

	if !provider.ScimEnabled {
		return nil, apiErrorCtx(ctx, ErrSCIMNotEnabled, connect.CodeFailedPrecondition, "SCIM is not enabled for this provider")
	}

	// Generate a 32-byte random token (64 hex characters)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate token")
	}
	plainToken := hex.EncodeToString(tokenBytes)

	hashStr, err := auth.HashPassword(plainToken)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to hash token")
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "identity_provider",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.IdentityProviderSCIMTokenRotated),
		Data: payloads.IdentityProviderSCIMTokenRotated{
			ScimTokenHash: hashStr,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to rotate SCIM token"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.RotateSCIMTokenResponse{
		Token: plainToken,
	}), nil
}

// idpToProto converts a database identity provider to a proto message.
// Note: client_secret is never returned to the client.
func (h *IDPHandler) idpToProto(p store.IdentityProvider) *pm.IdentityProvider {
	provider := &pm.IdentityProvider{
		Id:                       p.ID,
		Name:                     p.Name,
		Slug:                     p.Slug,
		ProviderType:             identityProviderTypeFromString(p.ProviderType),
		Enabled:                  p.Enabled,
		ClientId:                 p.ClientID,
		IssuerUrl:                p.IssuerURL,
		AuthorizationUrl:         p.AuthorizationURL,
		TokenUrl:                 p.TokenURL,
		UserinfoUrl:              p.UserinfoURL,
		Scopes:                   p.Scopes,
		AutoCreateUsers:          p.AutoCreateUsers,
		AutoLinkByEmail:          p.AutoLinkByEmail,
		TrustEmailAssertions:     p.TrustEmailAssertions,
		DefaultRoleId:            p.DefaultRoleID,
		DisablePasswordForLinked: p.DisablePasswordForLinked,
		GroupClaim:               p.GroupClaim,
		ScimEnabled:              p.ScimEnabled,
		ScimEndpointUrl:          h.scimBaseURL + "/scim/v2/" + p.Slug,
	}

	if p.GroupMapping != nil {
		var gm map[string]string
		if err := json.Unmarshal(p.GroupMapping, &gm); err == nil {
			provider.GroupMapping = gm
		}
	}

	provider.CreatedAt = timestamppb.New(p.CreatedAt)
	provider.UpdatedAt = timestamppb.New(p.UpdatedAt)

	return provider
}

// identityProviderTypeToString converts the wire enum to the
// lowercase string used in event payloads and the projection
// `provider_type` column ("oidc" today; "saml2", "ldap" reserved for
// future protocols). UNSPECIFIED maps to the empty string so a
// caller that forgot to set the field stores an empty value rather
// than a fake protocol name — Validate() rejects empty earlier in
// the request path.
func identityProviderTypeToString(t pm.IdentityProviderType) string {
	switch t {
	case pm.IdentityProviderType_IDENTITY_PROVIDER_TYPE_OIDC:
		return "oidc"
	default:
		return ""
	}
}

// identityProviderTypeFromString is the inverse: it parses the
// projection / event-payload string back into the wire enum.
// Unknown / empty values map to UNSPECIFIED so a stale row never
// crashes the handler — the caller surfaces UNSPECIFIED and the
// client treats it as "unknown protocol".
func identityProviderTypeFromString(s string) pm.IdentityProviderType {
	switch s {
	case "oidc":
		return pm.IdentityProviderType_IDENTITY_PROVIDER_TYPE_OIDC
	default:
		return pm.IdentityProviderType_IDENTITY_PROVIDER_TYPE_UNSPECIFIED
	}
}
