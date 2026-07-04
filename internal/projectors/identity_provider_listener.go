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
// Live dispatch wraps ApplyIdentityProvider (routing the multi-write
// event types through WithTx so their cascade stays atomic on the
// autocommit pool); the rebuild path (#497) registers
// ApplyIdentityProvider via RegisterRebuildApply — the rebuild
// dispatcher already runs inside one transaction and passes q bound to
// it, so every write executes directly on q with no nested transaction.
//
// Wired in projectors.WireAll. Refs #104, tracker #107, #497.
func IdentityProviderListener(st *store.Store, logger *slog.Logger) store.EventListener {
	if st == nil {
		return func(context.Context, store.PersistedEvent) {}
	}
	return func(ctx context.Context, e store.PersistedEvent) {
		if e.StreamType != "identity_provider" {
			return
		}
		// Multi-write events (Deleted, SCIMDisabled) route through
		// WithTx so the guarded UPDATE + cascade DELETE stay atomic;
		// single-statement events go on the autocommit pool. Both share
		// ApplyIdentityProvider's body via the tx-bound / pool-bound
		// Queries.
		switch e.EventType {
		case string(eventtypes.IdentityProviderDeleted),
			string(eventtypes.IdentityProviderSCIMDisabled):
			if err := st.WithTx(ctx, func(q *store.Queries) error {
				return ApplyIdentityProvider(ctx, q, e)
			}); err != nil {
				logger.Warn("identity_provider projector: failed to apply event",
					"event_id", e.ID, "event_type", e.EventType, "idp_id", e.StreamID, "error", err)
			}
			return
		}
		if err := ApplyIdentityProvider(ctx, st.Queries(), e); err != nil {
			logger.Warn("identity_provider projector: failed to apply event",
				"event_id", e.ID, "event_type", e.EventType, "idp_id", e.StreamID, "error", err)
		}
	}
}

// ApplyIdentityProvider is the transactional core of the
// identity_provider projector: it writes through the supplied Queries
// and RETURNS errors instead of logging-and-swallowing, so a rebuild
// fails loudly rather than producing a partial projection. Every write
// runs directly on q — the caller supplies the transaction (WithTx for
// the multi-write event types on the live path, the rebuild tx on the
// rebuild path), so ApplyIdentityProvider does NOT open a nested
// transaction of its own.
//
// The asymmetric-guard discipline is preserved for the multi-write
// events (Deleted, SCIMDisabled): the guarded UPDATE is :execrows and
// the cascade DELETE is short-circuited when n == 0 (stale
// projection_version replay).
func ApplyIdentityProvider(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	if e.StreamType != "identity_provider" {
		return nil
	}
	switch e.EventType {
	case string(eventtypes.IdentityProviderCreated):
		return applyIdentityProviderCreated(ctx, q, e)
	case string(eventtypes.IdentityProviderUpdated):
		return applyIdentityProviderUpdated(ctx, q, e)
	case string(eventtypes.IdentityProviderDeleted):
		return applyIdentityProviderDeleted(ctx, q, e)
	case string(eventtypes.IdentityProviderSCIMEnabled):
		return applyIdentityProviderSCIMEnabled(ctx, q, e)
	case string(eventtypes.IdentityProviderSCIMDisabled):
		return applyIdentityProviderSCIMDisabled(ctx, q, e)
	case string(eventtypes.IdentityProviderSCIMTokenRotated):
		return applyIdentityProviderSCIMTokenRotated(ctx, q, e)
	case string(eventtypes.IdentityLinked):
		return applyIdentityLinked(ctx, q, e)
	case string(eventtypes.IdentityLinkLoginUpdated):
		return applyIdentityLinkLoginUpdated(ctx, q, e)
	case string(eventtypes.IdentityUnlinked):
		return applyIdentityUnlinked(ctx, q, e)
	}
	return nil
}

func applyIdentityProviderCreated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := IdentityProviderCreatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.InsertIdentityProviderProjection(ctx, db.InsertIdentityProviderProjectionParams{
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
		TrustEmailAssertions:     payload.TrustEmailAssertions,
		DefaultRoleID:            payload.DefaultRoleID,
		DisablePasswordForLinked: payload.DisablePasswordForLinked,
		GroupClaim:               payload.GroupClaim,
		GroupMapping:             payload.GroupMapping,
		CreatedAt:                e.OccurredAt,
		CreatedBy:                payload.CreatedBy,
		ProjectionVersion:        e.SequenceNum,
	})
}

func applyIdentityProviderUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := IdentityProviderUpdatedFromEvent(e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.UpdateIdentityProviderProjection(ctx, db.UpdateIdentityProviderProjectionParams{
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
		TrustEmailAssertions:     payload.TrustEmailAssertions,
		DefaultRoleID:            payload.DefaultRoleID,
		DisablePasswordForLinked: payload.DisablePasswordForLinked,
		GroupClaim:               payload.GroupClaim,
		GroupMapping:             payload.GroupMapping,
		UpdatedAt:                e.OccurredAt,
		ProjectionVersion:        e.SequenceNum,
	})
}

func applyIdentityProviderDeleted(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	idpID := e.StreamID
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
}

func applyIdentityProviderSCIMEnabled(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := SCIMTokenFromEvent(e, "IdentityProviderSCIMEnabled")
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.SetIdentityProviderSCIMEnabled(ctx, db.SetIdentityProviderSCIMEnabledParams{
		ID:                payload.ID,
		ScimTokenHash:     payload.ScimTokenHash,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyIdentityProviderSCIMDisabled(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	idpID := e.StreamID
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
}

func applyIdentityProviderSCIMTokenRotated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := SCIMTokenFromEvent(e, "IdentityProviderSCIMTokenRotated")
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.RotateIdentityProviderSCIMToken(ctx, db.RotateIdentityProviderSCIMTokenParams{
		ID:                payload.ID,
		ScimTokenHash:     payload.ScimTokenHash,
		UpdatedAt:         e.OccurredAt,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyIdentityLinked(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := IdentityLinkedFromEvent(ctx, e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	return q.UpsertIdentityLink(ctx, db.UpsertIdentityLinkParams{
		ID:                payload.ID,
		UserID:            payload.UserID,
		ProviderID:        payload.ProviderID,
		ExternalID:        payload.ExternalID,
		ExternalEmail:     payload.ExternalEmail,
		ExternalName:      payload.ExternalName,
		LinkedAt:          e.OccurredAt,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyIdentityLinkLoginUpdated(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	payload, err := IdentityLinkLoginUpdatedFromEvent(ctx, e)
	if err != nil {
		if errors.Is(err, ErrIgnoredEvent) {
			return nil
		}
		return err
	}
	loginAt := e.OccurredAt
	return q.UpdateIdentityLinkLogin(ctx, db.UpdateIdentityLinkLoginParams{
		ProviderID:        payload.ProviderID,
		ExternalID:        payload.ExternalID,
		LastLoginAt:       &loginAt,
		ExternalEmail:     payload.ExternalEmail,
		ExternalName:      payload.ExternalName,
		ProjectionVersion: e.SequenceNum,
	})
}

func applyIdentityUnlinked(ctx context.Context, q *store.Queries, e store.PersistedEvent) error {
	return q.DeleteIdentityLinkByID(ctx, e.StreamID)
}
