package projectors

import (
	"context"
	"errors"
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// IdentityProviderListener returns a store.EventListener that applies
// every identity_provider stream event the deleted PL/pgSQL
// project_identity_provider_event handled. Nine event types — the
// largest projector in tracker #107.
//
// Event-type families:
//   - IdP CRUD: Created (INSERT), Updated (partial UPDATE),
//     Deleted (soft + cascade DELETE on identity_links + scim_group_mapping).
//   - SCIM toggles: SCIMEnabled, SCIMDisabled (cascade DELETE on
//     scim_group_mapping), SCIMTokenRotated.
//   - Identity links: IdentityLinked (UPSERT), IdentityLinkLoginUpdated,
//     IdentityUnlinked (DELETE).
//
// Multi-write listeners (Deleted, SCIMDisabled) follow the
// asymmetric-guard discipline: the guarded UPDATE is :execrows, and
// the listener short-circuits the cascade DELETE when n == 0
// (stale projection_version replay).
//
// Wired in projectors.WireAll. Refs #104, tracker #107.
func IdentityProviderListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "identity_provider" {
			return
		}
		switch e.EventType {
		case string(eventtypes.IdentityProviderCreated):
			applyIdentityProviderCreated(ctx, st, logger, e)
		case string(eventtypes.IdentityProviderUpdated):
			applyIdentityProviderUpdated(ctx, st, logger, e)
		case string(eventtypes.IdentityProviderDeleted):
			applyIdentityProviderDeleted(ctx, st, logger, e)
		case string(eventtypes.IdentityProviderSCIMEnabled):
			applyIdentityProviderSCIMEnabled(ctx, st, logger, e)
		case string(eventtypes.IdentityProviderSCIMDisabled):
			applyIdentityProviderSCIMDisabled(ctx, st, logger, e)
		case string(eventtypes.IdentityProviderSCIMTokenRotated):
			applyIdentityProviderSCIMTokenRotated(ctx, st, logger, e)
		case string(eventtypes.IdentityLinked):
			applyIdentityLinked(ctx, st, logger, e)
		case string(eventtypes.IdentityLinkLoginUpdated):
			applyIdentityLinkLoginUpdated(ctx, st, logger, e)
		case string(eventtypes.IdentityUnlinked):
			applyIdentityUnlinked(ctx, st, logger, e)
		}
	}
}

func applyIdentityProviderCreated(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := IdentityProviderCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("identity_provider projector: invalid IdentityProviderCreated payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().InsertIdentityProviderProjection(ctx, db.InsertIdentityProviderProjectionParams{
		ID:                       payload.ID,
		Name:                     payload.Name,
		Slug:                     payload.Slug,
		ProviderType:             payload.ProviderType,
		ClientID:                 payload.ClientID,
		ClientSecretEncrypted:    payload.ClientSecretEncrypted,
		IssuerUrl:                payload.IssuerURL,
		AuthorizationUrl:         payload.AuthorizationURL,
		TokenUrl:                 payload.TokenURL,
		UserinfoUrl:              payload.UserinfoURL,
		Scopes:                   payload.Scopes,
		AutoCreateUsers:          payload.AutoCreateUsers,
		AutoLinkByEmail:          payload.AutoLinkByEmail,
		DefaultRoleID:            payload.DefaultRoleID,
		DisablePasswordForLinked: payload.DisablePasswordForLinked,
		GroupClaim:               payload.GroupClaim,
		GroupMapping:             payload.GroupMapping,
		CreatedAt:                e.OccurredAt,
		CreatedBy:                payload.CreatedBy,
		ProjectionVersion:        e.SequenceNum,
	}); err != nil {
		logger.Warn("identity_provider projector: failed to insert IdentityProviderCreated",
			"event_id", e.ID, "idp_id", payload.ID, "error", err)
	}
}

func applyIdentityProviderUpdated(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := IdentityProviderUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("identity_provider projector: invalid IdentityProviderUpdated payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().UpdateIdentityProviderProjection(ctx, db.UpdateIdentityProviderProjectionParams{
		ID:                       payload.ID,
		Name:                     payload.Name,
		Enabled:                  payload.Enabled,
		ClientID:                 payload.ClientID,
		ClientSecretEncrypted:    payload.ClientSecretEncrypted,
		IssuerUrl:                payload.IssuerURL,
		AuthorizationUrl:         payload.AuthorizationURL,
		TokenUrl:                 payload.TokenURL,
		UserinfoUrl:              payload.UserinfoURL,
		Scopes:                   derefSlice(payload.Scopes),
		AutoCreateUsers:          payload.AutoCreateUsers,
		AutoLinkByEmail:          payload.AutoLinkByEmail,
		DefaultRoleID:            payload.DefaultRoleID,
		DisablePasswordForLinked: payload.DisablePasswordForLinked,
		GroupClaim:               payload.GroupClaim,
		GroupMapping:             payload.GroupMapping,
		UpdatedAt:                e.OccurredAt,
		ProjectionVersion:        e.SequenceNum,
	}); err != nil {
		logger.Warn("identity_provider projector: failed to apply IdentityProviderUpdated",
			"event_id", e.ID, "idp_id", payload.ID, "error", err)
	}
}

func applyIdentityProviderDeleted(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	idpID := e.StreamID
	if err := st.WithTx(ctx, func(q *store.Queries) error {
		// Asymmetric-guard rule: SoftDelete is guarded by
		// projection_version; cascades are not. Short-circuit on
		// n == 0 (stale replay) to keep memberships + mappings.
		n, err := q.SoftDeleteIdentityProviderProjection(ctx, db.SoftDeleteIdentityProviderProjectionParams{
			ID:                idpID,
			UpdatedAt:         e.OccurredAt,
			ProjectionVersion: e.SequenceNum,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if err := q.DeleteIdentityLinksByProvider(ctx, idpID); err != nil {
			return err
		}
		return q.DeleteSCIMGroupMappingsByProvider(ctx, idpID)
	}); err != nil {
		logger.Warn("identity_provider projector: failed to apply IdentityProviderDeleted",
			"event_id", e.ID, "idp_id", idpID, "error", err)
	}
}

func applyIdentityProviderSCIMEnabled(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := SCIMTokenFromEvent(e, "IdentityProviderSCIMEnabled")
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("identity_provider projector: invalid IdentityProviderSCIMEnabled payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().SetIdentityProviderSCIMEnabled(ctx, db.SetIdentityProviderSCIMEnabledParams{
		ID:                payload.ID,
		ScimTokenHash:     payload.ScimTokenHash,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		logger.Warn("identity_provider projector: failed to enable SCIM",
			"event_id", e.ID, "idp_id", payload.ID, "error", err)
	}
}

func applyIdentityProviderSCIMDisabled(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	idpID := e.StreamID
	if err := st.WithTx(ctx, func(q *store.Queries) error {
		// Same asymmetric-guard discipline: cascade only if the
		// guarded SCIM-disable UPDATE actually flipped a row.
		n, err := q.SetIdentityProviderSCIMDisabled(ctx, db.SetIdentityProviderSCIMDisabledParams{
			ID:                idpID,
			UpdatedAt:         e.OccurredAt,
			ProjectionVersion: e.SequenceNum,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		return q.DeleteSCIMGroupMappingsByProvider(ctx, idpID)
	}); err != nil {
		logger.Warn("identity_provider projector: failed to disable SCIM",
			"event_id", e.ID, "idp_id", idpID, "error", err)
	}
}

func applyIdentityProviderSCIMTokenRotated(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := SCIMTokenFromEvent(e, "IdentityProviderSCIMTokenRotated")
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("identity_provider projector: invalid IdentityProviderSCIMTokenRotated payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().RotateIdentityProviderSCIMToken(ctx, db.RotateIdentityProviderSCIMTokenParams{
		ID:                payload.ID,
		ScimTokenHash:     payload.ScimTokenHash,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		logger.Warn("identity_provider projector: failed to rotate SCIM token",
			"event_id", e.ID, "idp_id", payload.ID, "error", err)
	}
}

func applyIdentityLinked(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := IdentityLinkedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("identity_provider projector: invalid IdentityLinked payload",
			"event_id", e.ID, "error", err)
		return
	}
	if err := st.Queries().UpsertIdentityLink(ctx, db.UpsertIdentityLinkParams{
		ID:                payload.ID,
		UserID:            payload.UserID,
		ProviderID:        payload.ProviderID,
		ExternalID:        payload.ExternalID,
		ExternalEmail:     payload.ExternalEmail,
		ExternalName:      payload.ExternalName,
		LinkedAt:          e.OccurredAt,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		logger.Warn("identity_provider projector: failed to upsert identity_link",
			"event_id", e.ID, "link_id", payload.ID, "error", err)
	}
}

func applyIdentityLinkLoginUpdated(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	payload, err := IdentityLinkLoginUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return
		}
		logger.Warn("identity_provider projector: invalid IdentityLinkLoginUpdated payload",
			"event_id", e.ID, "error", err)
		return
	}
	loginAt := e.OccurredAt
	if err := st.Queries().UpdateIdentityLinkLogin(ctx, db.UpdateIdentityLinkLoginParams{
		ProviderID:        payload.ProviderID,
		ExternalID:        payload.ExternalID,
		LastLoginAt:       &loginAt,
		ExternalEmail:     payload.ExternalEmail,
		ExternalName:      payload.ExternalName,
		ProjectionVersion: e.SequenceNum,
	}); err != nil {
		logger.Warn("identity_provider projector: failed to update identity_link login",
			"event_id", e.ID, "provider_id", payload.ProviderID, "external_id", payload.ExternalID, "error", err)
	}
}

func applyIdentityUnlinked(ctx context.Context, st *store.Store, logger *slog.Logger, e store.PersistedEvent) {
	if err := st.Queries().DeleteIdentityLinkByID(ctx, e.StreamID); err != nil {
		logger.Warn("identity_provider projector: failed to delete identity_link",
			"event_id", e.ID, "link_id", e.StreamID, "error", err)
	}
}
