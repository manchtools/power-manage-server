package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// IDPHandler handles identity provider CRUD RPCs.
type IDPHandler struct {
	store       *store.Store
	enc         *crypto.Encryptor
	scimBaseURL string
}

// NewIDPHandler creates a new identity provider handler.
func NewIDPHandler(st *store.Store, enc *crypto.Encryptor, scimBaseURL string) *IDPHandler {
	return &IDPHandler{store: st, enc: enc, scimBaseURL: scimBaseURL}
}

// CreateIdentityProvider creates a new identity provider.
func (h *IDPHandler) CreateIdentityProvider(ctx context.Context, req *connect.Request[pm.CreateIdentityProviderRequest]) (*connect.Response[pm.CreateIdentityProviderResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Check for duplicate slug
	_, err := h.store.Queries().GetIdentityProviderBySlug(ctx, req.Msg.Slug)
	if err == nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("provider with this slug already exists"))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to check slug"))
	}

	// Encrypt client secret
	encryptedSecret, err := h.enc.Encrypt(req.Msg.ClientSecret)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to encrypt client secret"))
	}

	groupMappingJSON, _ := json.Marshal(req.Msg.GroupMapping)

	id := newULID()
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   id,
		EventType:  "IdentityProviderCreated",
		Data: map[string]any{
			"name":                        req.Msg.Name,
			"slug":                        req.Msg.Slug,
			"provider_type":               req.Msg.ProviderType,
			"client_id":                   req.Msg.ClientId,
			"client_secret_encrypted":     encryptedSecret,
			"issuer_url":                  req.Msg.IssuerUrl,
			"authorization_url":           req.Msg.AuthorizationUrl,
			"token_url":                   req.Msg.TokenUrl,
			"userinfo_url":                req.Msg.UserinfoUrl,
			"scopes":                      req.Msg.Scopes,
			"auto_create_users":           req.Msg.AutoCreateUsers,
			"auto_link_by_email":          req.Msg.AutoLinkByEmail,
			"default_role_id":             req.Msg.DefaultRoleId,
			"disable_password_for_linked": req.Msg.DisablePasswordForLinked,
			"group_claim":                 req.Msg.GroupClaim,
			"group_mapping":               json.RawMessage(groupMappingJSON),
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create provider"))
	}

	provider, err := h.store.Queries().GetIdentityProviderByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to read back provider"))
	}

	return connect.NewResponse(&pm.CreateIdentityProviderResponse{
		Provider: h.idpToProto(provider),
	}), nil
}

// GetIdentityProvider returns an identity provider by ID.
func (h *IDPHandler) GetIdentityProvider(ctx context.Context, req *connect.Request[pm.GetIdentityProviderRequest]) (*connect.Response[pm.GetIdentityProviderResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	provider, err := h.store.Queries().GetIdentityProviderByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("provider not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get provider"))
	}

	return connect.NewResponse(&pm.GetIdentityProviderResponse{
		Provider: h.idpToProto(provider),
	}), nil
}

// ListIdentityProviders returns a paginated list of identity providers.
func (h *IDPHandler) ListIdentityProviders(ctx context.Context, req *connect.Request[pm.ListIdentityProvidersRequest]) (*connect.Response[pm.ListIdentityProvidersResponse], error) {
	pageSize := int32(req.Msg.PageSize)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	offset := int32(0)
	if req.Msg.PageToken != "" {
		offset64, err := parsePageToken(req.Msg.PageToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid page token"))
		}
		offset = int32(offset64)
	}

	providers, err := h.store.Queries().ListIdentityProviders(ctx, db.ListIdentityProvidersParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list providers"))
	}

	count, err := h.store.Queries().CountIdentityProviders(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count providers"))
	}

	var nextPageToken string
	if int32(len(providers)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

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
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Verify provider exists
	_, err := h.store.Queries().GetIdentityProviderByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("provider not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get provider"))
	}

	data := map[string]any{
		"name":                        req.Msg.Name,
		"enabled":                     req.Msg.Enabled,
		"auto_create_users":           req.Msg.AutoCreateUsers,
		"auto_link_by_email":          req.Msg.AutoLinkByEmail,
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
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to encrypt client secret"))
		}
		data["client_secret_encrypted"] = encryptedSecret
	}

	if req.Msg.GroupMapping != nil {
		groupMappingJSON, _ := json.Marshal(req.Msg.GroupMapping)
		data["group_mapping"] = json.RawMessage(groupMappingJSON)
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   req.Msg.Id,
		EventType:  "IdentityProviderUpdated",
		Data:       data,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update provider"))
	}

	provider, err := h.store.Queries().GetIdentityProviderByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to read back provider"))
	}

	return connect.NewResponse(&pm.UpdateIdentityProviderResponse{
		Provider: h.idpToProto(provider),
	}), nil
}

// DeleteIdentityProvider deletes an identity provider.
func (h *IDPHandler) DeleteIdentityProvider(ctx context.Context, req *connect.Request[pm.DeleteIdentityProviderRequest]) (*connect.Response[pm.DeleteIdentityProviderResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   req.Msg.Id,
		EventType:  "IdentityProviderDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete provider"))
	}

	return connect.NewResponse(&pm.DeleteIdentityProviderResponse{}), nil
}

// EnableSCIM enables SCIM provisioning for an identity provider.
func (h *IDPHandler) EnableSCIM(ctx context.Context, req *connect.Request[pm.EnableSCIMRequest]) (*connect.Response[pm.EnableSCIMResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	provider, err := h.store.Queries().GetIdentityProviderByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("provider not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get provider"))
	}

	if provider.ScimEnabled {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("SCIM is already enabled for this provider"))
	}

	// Generate a 32-byte random token (64 hex characters)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate token"))
	}
	plainToken := hex.EncodeToString(tokenBytes)

	hashStr, err := auth.HashPassword(plainToken)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to hash token"))
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   req.Msg.Id,
		EventType:  "IdentityProviderSCIMEnabled",
		Data: map[string]any{
			"scim_token_hash": hashStr,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to enable SCIM"))
	}

	endpointURL := h.scimBaseURL + "/scim/v2/" + provider.Slug

	return connect.NewResponse(&pm.EnableSCIMResponse{
		Token:       plainToken,
		EndpointUrl: endpointURL,
	}), nil
}

// DisableSCIM disables SCIM provisioning for an identity provider.
func (h *IDPHandler) DisableSCIM(ctx context.Context, req *connect.Request[pm.DisableSCIMRequest]) (*connect.Response[pm.DisableSCIMResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	provider, err := h.store.Queries().GetIdentityProviderByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("provider not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get provider"))
	}

	if !provider.ScimEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("SCIM is not enabled for this provider"))
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   req.Msg.Id,
		EventType:  "IdentityProviderSCIMDisabled",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to disable SCIM"))
	}

	return connect.NewResponse(&pm.DisableSCIMResponse{}), nil
}

// RotateSCIMToken generates a new SCIM bearer token for an identity provider.
func (h *IDPHandler) RotateSCIMToken(ctx context.Context, req *connect.Request[pm.RotateSCIMTokenRequest]) (*connect.Response[pm.RotateSCIMTokenResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	provider, err := h.store.Queries().GetIdentityProviderByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("provider not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get provider"))
	}

	if !provider.ScimEnabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("SCIM is not enabled for this provider"))
	}

	// Generate a 32-byte random token (64 hex characters)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate token"))
	}
	plainToken := hex.EncodeToString(tokenBytes)

	hashStr, err := auth.HashPassword(plainToken)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to hash token"))
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   req.Msg.Id,
		EventType:  "IdentityProviderSCIMTokenRotated",
		Data: map[string]any{
			"scim_token_hash": hashStr,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to rotate SCIM token"))
	}

	return connect.NewResponse(&pm.RotateSCIMTokenResponse{
		Token: plainToken,
	}), nil
}

// idpToProto converts a database identity provider to a proto message.
// Note: client_secret is never returned to the client.
func (h *IDPHandler) idpToProto(p db.IdentityProvidersProjection) *pm.IdentityProvider {
	provider := &pm.IdentityProvider{
		Id:                       p.ID,
		Name:                     p.Name,
		Slug:                     p.Slug,
		ProviderType:             p.ProviderType,
		Enabled:                  p.Enabled,
		ClientId:                 p.ClientID,
		IssuerUrl:                p.IssuerUrl,
		AuthorizationUrl:         p.AuthorizationUrl,
		TokenUrl:                 p.TokenUrl,
		UserinfoUrl:              p.UserinfoUrl,
		Scopes:                   p.Scopes,
		AutoCreateUsers:          p.AutoCreateUsers,
		AutoLinkByEmail:          p.AutoLinkByEmail,
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

	if p.CreatedAt.Valid {
		provider.CreatedAt = timestamppb.New(p.CreatedAt.Time)
	}
	if p.UpdatedAt.Valid {
		provider.UpdatedAt = timestamppb.New(p.UpdatedAt.Time)
	}

	return provider
}
