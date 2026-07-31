package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// scimTokenBytes is the entropy of a SCIM bearer token. 32 bytes is
// well past any brute-force reach and keeps the printed value short
// enough to paste into an IdP console.
const scimTokenBytes = 32

// CreateIdentityProvider registers an OIDC provider.
//
// The client secret is sealed at rest with AAD bound to this provider's
// own row, so a database-level attacker cannot relocate it to another
// provider and have it decrypt. It has no field on the wire in either
// direction after this call: it is write-only by contract.
func (h *Handlers) CreateIdentityProvider(ctx context.Context, req *connect.Request[pmv1.CreateIdentityProviderRequest]) (*connect.Response[pmv1.CreateIdentityProviderResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermCreateIdentityProvider, ""); err != nil {
		return nil, err
	}
	providerType, ok := providerTypeFromProto(req.Msg.ProviderType)
	if !ok {
		return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "unsupported provider_type")
	}
	if req.Msg.DefaultRoleId != "" {
		if _, err := h.store.GetRole(ctx, req.Msg.DefaultRoleId); err != nil {
			if store.IsNotFound(err) {
				return nil, notFound(ctx, ErrRoleNotFound, "default role not found")
			}
			return nil, internalError(ctx, "failed to resolve default role")
		}
	}
	mapping, err := encodeGroupMapping(ctx, req.Msg.GroupMapping)
	if err != nil {
		return nil, err
	}
	// The column is NOT NULL with an empty-array default; a nil slice
	// would be sent as NULL and rejected, so an omitted scope list
	// becomes the empty list rather than a constraint violation.
	scopes := nonNilStrings(req.Msg.Scopes)

	providerID := ulid.Make().String()
	sealed, err := h.kek.EncryptWithContext(req.Msg.ClientSecret, crypto.RowAAD(providerID, crypto.PurposeIdPClientSecret))
	if err != nil {
		return nil, internalError(ctx, "failed to protect the client secret")
	}

	at := h.now().UTC()
	var created store.IdentityProviderRow
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermCreateIdentityProvider),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			var err error
			created, err = tx.InsertIdentityProvider(ctx, db.InsertIdentityProviderParams{
				ID:                    providerID,
				Name:                  req.Msg.Name,
				Slug:                  req.Msg.Slug,
				ProviderType:          providerType,
				Enabled:               true,
				ClientID:              req.Msg.ClientId,
				ClientSecretEncrypted: sealed,
				IssuerUrl:             req.Msg.IssuerUrl,
				AuthorizationUrl:      req.Msg.AuthorizationUrl,
				TokenUrl:              req.Msg.TokenUrl,
				UserinfoUrl:           req.Msg.UserinfoUrl,
				Scopes:                scopes,
				AutoCreateUsers:       req.Msg.AutoCreateUsers,
				AutoLinkByEmail:       req.Msg.AutoLinkByEmail,
				TrustEmailAssertions:  req.Msg.TrustEmailAssertions,
				DefaultRoleID:         req.Msg.DefaultRoleId,
				GroupClaim:            req.Msg.GroupClaim,
				GroupMapping:          mapping,
				CreatedAt:             at,
				CreatedBy:             actor.ID,
			})
			if err != nil {
				return err
			}
			trust := req.Msg.TrustEmailAssertions
			rec.Effect(store.AuditEffect{
				ResourceType: "identity_provider",
				ResourceID:   providerID,
				Action:       "CREATE",
				Outcome:      store.EffectApplied,
				ChangedFields: []string{
					"name", "slug", "client_id", "client_secret_encrypted", "issuer_url",
					"auto_create_users", "auto_link_by_email", "trust_email_assertions",
				},
				// The email-assertion switch is the account-takeover
				// control on this row, so its value is recorded
				// explicitly rather than left implicit in "created".
				AfterFlag: &trust,
				// The secret never appears, but proving WHICH secret was
				// configured is legitimate evidence, so its digest is.
				EvidenceKind:        "idp_client_secret_sha256",
				EvidenceFingerprint: fingerprint(req.Msg.ClientSecret),
			})
			return nil
		})
	if err != nil {
		if store.IsConflict(err) {
			return nil, rpcError(ctx, ErrProviderSlugExists, connect.CodeAlreadyExists, "a provider with that slug already exists")
		}
		return nil, internalError(ctx, "failed to create identity provider")
	}
	return connect.NewResponse(&pmv1.CreateIdentityProviderResponse{Provider: h.providerToProto(created)}), nil
}

// GetIdentityProvider returns one provider's configuration.
func (h *Handlers) GetIdentityProvider(ctx context.Context, req *connect.Request[pmv1.GetIdentityProviderRequest]) (*connect.Response[pmv1.GetIdentityProviderResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermGetIdentityProvider, req.Msg.Id); err != nil {
		return nil, err
	}
	row, err := h.store.GetIdentityProvider(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrProviderNotFound, "identity provider not found")
		}
		return nil, internalError(ctx, "failed to load identity provider")
	}
	return connect.NewResponse(&pmv1.GetIdentityProviderResponse{Provider: h.providerToProto(row)}), nil
}

// ListIdentityProviders pages the configured providers.
func (h *Handlers) ListIdentityProviders(ctx context.Context, req *connect.Request[pmv1.ListIdentityProvidersRequest]) (*connect.Response[pmv1.ListIdentityProvidersResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermListIdentityProviders, ""); err != nil {
		return nil, err
	}
	limit := pageLimit(req.Msg.PageSize)
	rows, err := h.store.ListIdentityProviders(ctx, req.Msg.PageToken, limit)
	if err != nil {
		return nil, internalError(ctx, "failed to list identity providers")
	}
	total, err := h.store.CountIdentityProviders(ctx)
	if err != nil {
		return nil, internalError(ctx, "failed to count identity providers")
	}
	resp := &pmv1.ListIdentityProvidersResponse{TotalCount: int32(total)}
	for _, r := range rows {
		resp.Providers = append(resp.Providers, h.providerToProto(r))
	}
	if len(rows) == int(limit) {
		resp.NextPageToken = rows[len(rows)-1].ID
	}
	return connect.NewResponse(resp), nil
}

// UpdateIdentityProvider rewrites a provider's configuration.
//
// An empty client_secret means "keep the current one": the field is
// write-only, so a client that never received it cannot echo it back,
// and treating empty as "clear it" would silently break every login
// through that provider.
func (h *Handlers) UpdateIdentityProvider(ctx context.Context, req *connect.Request[pmv1.UpdateIdentityProviderRequest]) (*connect.Response[pmv1.UpdateIdentityProviderResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermUpdateIdentityProvider, req.Msg.Id); err != nil {
		return nil, err
	}
	before, err := h.store.GetIdentityProvider(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrProviderNotFound, "identity provider not found")
		}
		return nil, internalError(ctx, "failed to load identity provider")
	}
	if req.Msg.DefaultRoleId != "" {
		if _, err := h.store.GetRole(ctx, req.Msg.DefaultRoleId); err != nil {
			if store.IsNotFound(err) {
				return nil, notFound(ctx, ErrRoleNotFound, "default role not found")
			}
			return nil, internalError(ctx, "failed to resolve default role")
		}
	}
	mapping, err := encodeGroupMapping(ctx, req.Msg.GroupMapping)
	if err != nil {
		return nil, err
	}

	secret := before.ClientSecretEncrypted
	secretChanged := req.Msg.ClientSecret != ""
	if secretChanged {
		secret, err = h.kek.EncryptWithContext(req.Msg.ClientSecret, crypto.RowAAD(before.ID, crypto.PurposeIdPClientSecret))
		if err != nil {
			return nil, internalError(ctx, "failed to protect the client secret")
		}
	}

	at := h.now().UTC()
	var updated store.IdentityProviderRow
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermUpdateIdentityProvider),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			var err error
			updated, err = tx.UpdateIdentityProvider(ctx, db.UpdateIdentityProviderParams{
				ID:                    before.ID,
				Name:                  req.Msg.Name,
				Enabled:               req.Msg.Enabled,
				ClientID:              req.Msg.ClientId,
				ClientSecretEncrypted: secret,
				IssuerUrl:             req.Msg.IssuerUrl,
				AuthorizationUrl:      req.Msg.AuthorizationUrl,
				TokenUrl:              req.Msg.TokenUrl,
				UserinfoUrl:           req.Msg.UserinfoUrl,
				Scopes:                nonNilStrings(req.Msg.Scopes),
				AutoCreateUsers:       req.Msg.AutoCreateUsers,
				AutoLinkByEmail:       req.Msg.AutoLinkByEmail,
				TrustEmailAssertions:  req.Msg.TrustEmailAssertions,
				DefaultRoleID:         req.Msg.DefaultRoleId,
				GroupClaim:            req.Msg.GroupClaim,
				GroupMapping:          mapping,
				UpdatedAt:             at,
			})
			if err != nil {
				return err
			}
			changed := []string{"name", "enabled", "client_id", "issuer_url", "auto_create_users", "auto_link_by_email", "trust_email_assertions"}
			effect := store.AuditEffect{
				ResourceType:  "identity_provider",
				ResourceID:    before.ID,
				Action:        "UPDATE",
				Outcome:       store.EffectApplied,
				ChangedFields: changed,
				BeforeFlag:    &before.TrustEmailAssertions,
				AfterFlag:     &req.Msg.TrustEmailAssertions,
			}
			if secretChanged {
				effect.ChangedFields = append(changed, "client_secret_encrypted")
				effect.EvidenceKind = "idp_client_secret_sha256"
				effect.EvidenceFingerprint = fingerprint(req.Msg.ClientSecret)
			}
			rec.Effect(effect)
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrProviderNotFound, "identity provider not found")
		}
		return nil, internalError(ctx, "failed to update identity provider")
	}
	return connect.NewResponse(&pmv1.UpdateIdentityProviderResponse{Provider: h.providerToProto(updated)}), nil
}

// DeleteIdentityProvider retires a provider.
//
// The row is retired rather than erased: identity links point at it and
// must stay resolvable as evidence of who was once bound where.
func (h *Handlers) DeleteIdentityProvider(ctx context.Context, req *connect.Request[pmv1.DeleteIdentityProviderRequest]) (*connect.Response[pmv1.DeleteIdentityProviderResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermDeleteIdentityProvider, req.Msg.Id); err != nil {
		return nil, err
	}
	before, err := h.store.GetIdentityProvider(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrProviderNotFound, "identity provider not found")
		}
		return nil, internalError(ctx, "failed to load identity provider")
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermDeleteIdentityProvider),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			n, err := tx.SoftDeleteIdentityProvider(ctx, db.SoftDeleteIdentityProviderParams{ID: before.ID, UpdatedAt: at})
			if err != nil {
				return err
			}
			if n == 0 {
				return store.ErrNotFound
			}
			yes := true
			rec.Effect(store.AuditEffect{
				ResourceType:  "identity_provider",
				ResourceID:    before.ID,
				Action:        "DELETE",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"is_deleted"},
				AfterFlag:     &yes,
			})
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrProviderNotFound, "identity provider not found")
		}
		return nil, internalError(ctx, "failed to delete identity provider")
	}
	return connect.NewResponse(&pmv1.DeleteIdentityProviderResponse{}), nil
}

// EnableSCIM turns on directory provisioning and mints the bearer token
// the directory will present.
func (h *Handlers) EnableSCIM(ctx context.Context, req *connect.Request[pmv1.EnableSCIMRequest]) (*connect.Response[pmv1.EnableSCIMResponse], error) {
	token, provider, err := h.setSCIM(ctx, req, req.Msg.Id, PermEnableSCIM, true, "ENABLE_SCIM")
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.EnableSCIMResponse{
		Token:       token,
		EndpointUrl: h.scimEndpointURL(provider.ID),
	}), nil
}

// RotateSCIMToken replaces the directory's bearer token. The previous
// token stops working the moment this commits.
func (h *Handlers) RotateSCIMToken(ctx context.Context, req *connect.Request[pmv1.RotateSCIMTokenRequest]) (*connect.Response[pmv1.RotateSCIMTokenResponse], error) {
	provider, err := h.store.GetIdentityProvider(ctx, req.Msg.Id)
	if err == nil && !provider.ScimEnabled {
		return nil, rpcError(ctx, ErrSCIMNotEnabled, connect.CodeFailedPrecondition, "SCIM is not enabled for this provider")
	}
	token, _, err := h.setSCIM(ctx, req, req.Msg.Id, PermRotateSCIMToken, true, "ROTATE_SCIM_TOKEN")
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.RotateSCIMTokenResponse{Token: token}), nil
}

// DisableSCIM turns directory provisioning off and clears the stored
// token digest, so a token issued earlier cannot be replayed if SCIM is
// later re-enabled.
func (h *Handlers) DisableSCIM(ctx context.Context, req *connect.Request[pmv1.DisableSCIMRequest]) (*connect.Response[pmv1.DisableSCIMResponse], error) {
	if _, _, err := h.setSCIM(ctx, req, req.Msg.Id, PermDisableSCIM, false, "DISABLE_SCIM"); err != nil {
		return nil, err
	}
	return connect.NewResponse(&pmv1.DisableSCIMResponse{}), nil
}

// setSCIM is the shared body of enable, rotate and disable. Only the
// digest of a minted token is stored; the plaintext is returned to the
// caller exactly once and never recoverable afterwards.
func (h *Handlers) setSCIM(
	ctx context.Context,
	req connect.AnyRequest,
	providerID, permission string,
	enable bool,
	action string,
) (string, store.IdentityProviderRow, error) {
	if err := h.validate(ctx, req.Any()); err != nil {
		return "", store.IdentityProviderRow{}, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return "", store.IdentityProviderRow{}, err
	}
	if err := h.authorize(ctx, permission, providerID); err != nil {
		return "", store.IdentityProviderRow{}, err
	}
	before, err := h.store.GetIdentityProvider(ctx, providerID)
	if err != nil {
		if store.IsNotFound(err) {
			return "", store.IdentityProviderRow{}, notFound(ctx, ErrProviderNotFound, "identity provider not found")
		}
		return "", store.IdentityProviderRow{}, internalError(ctx, "failed to load identity provider")
	}

	var token, tokenHash string
	if enable {
		token, err = newSCIMToken()
		if err != nil {
			return "", store.IdentityProviderRow{}, internalError(ctx, "failed to mint a SCIM token")
		}
		tokenHash = fingerprint(token)
	}

	at := h.now().UTC()
	var updated store.IdentityProviderRow
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, permission),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			var err error
			updated, err = tx.SetIdentityProviderSCIM(ctx, db.SetIdentityProviderSCIMParams{
				ID:            before.ID,
				ScimEnabled:   enable,
				ScimTokenHash: tokenHash,
				UpdatedAt:     at,
			})
			if err != nil {
				return err
			}
			effect := store.AuditEffect{
				ResourceType:  "identity_provider",
				ResourceID:    before.ID,
				Action:        action,
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"scim_enabled", "scim_token_hash"},
				BeforeFlag:    &before.ScimEnabled,
				AfterFlag:     &enable,
			}
			if tokenHash != "" {
				// The digest IS the stored form, so recording it proves
				// which token was issued without the audit log holding
				// anything the directory could authenticate with.
				effect.EvidenceKind = "scim_token_sha256"
				effect.EvidenceFingerprint = tokenHash
			}
			rec.Effect(effect)
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return "", store.IdentityProviderRow{}, notFound(ctx, ErrProviderNotFound, "identity provider not found")
		}
		return "", store.IdentityProviderRow{}, internalError(ctx, "failed to update SCIM configuration")
	}
	return token, updated, nil
}

// newSCIMToken mints a bearer token from the cryptographic random
// source.
func newSCIMToken() (string, error) {
	raw := make([]byte, scimTokenBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// nonNilStrings turns a nil slice into an empty one. Every text[]
// column in this schema is NOT NULL, and a nil slice encodes as SQL
// NULL rather than as an empty array.
func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// encodeGroupMapping serialises the external-group map for storage. A
// nil map stores an empty object rather than SQL NULL, so every read
// path sees the same shape.
func encodeGroupMapping(ctx context.Context, mapping map[string]string) ([]byte, error) {
	if mapping == nil {
		mapping = map[string]string{}
	}
	raw, err := json.Marshal(mapping)
	if err != nil {
		return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "group_mapping is not serialisable")
	}
	return raw, nil
}
