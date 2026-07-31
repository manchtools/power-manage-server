package identity

import (
	"context"

	"connectrpc.com/connect"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

// ListIdentityLinks returns the caller's OWN external identities.
//
// The RPC takes no subject: it is self-service by construction, so
// there is no id a caller could substitute to read somebody else's
// linked accounts.
func (h *Handlers) ListIdentityLinks(ctx context.Context, req *connect.Request[pmv1.ListIdentityLinksRequest]) (*connect.Response[pmv1.ListIdentityLinksResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermListIdentityLinks, actor.ID); err != nil {
		return nil, err
	}
	if !actor.CanOwnResources() {
		// A principal that is no subject owns no links.
		return connect.NewResponse(&pmv1.ListIdentityLinksResponse{}), nil
	}
	links, err := h.store.ListIdentityLinksForUser(ctx, actor.ID)
	if err != nil {
		return nil, internalError(ctx, "failed to list identity links")
	}
	resp := &pmv1.ListIdentityLinksResponse{}
	for _, l := range links {
		resp.Links = append(resp.Links, linkToProto(l))
	}
	return connect.NewResponse(resp), nil
}

// UnlinkIdentity removes one of the caller's own external identities.
//
// Two guards, in this order. A link that belongs to somebody else reads
// as not-found, so the id space cannot be probed for other people's
// bindings. And the caller's LAST link cannot be removed: human login
// is OIDC only, so unlinking the last one would lock the subject out of
// their own account with no local credential to fall back on.
func (h *Handlers) UnlinkIdentity(ctx context.Context, req *connect.Request[pmv1.UnlinkIdentityRequest]) (*connect.Response[pmv1.UnlinkIdentityResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermUnlinkIdentity, actor.ID); err != nil {
		return nil, err
	}
	if !actor.CanOwnResources() {
		return nil, notFound(ctx, ErrIdentityLinkNotFound, "identity link not found")
	}

	link, err := h.store.GetIdentityLink(ctx, req.Msg.LinkId)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrIdentityLinkNotFound, "identity link not found")
		}
		return nil, internalError(ctx, "failed to load identity link")
	}
	if link.UserID != actor.ID {
		return nil, notFound(ctx, ErrIdentityLinkNotFound, "identity link not found")
	}

	existing, err := h.store.ListIdentityLinksForUser(ctx, actor.ID)
	if err != nil {
		return nil, internalError(ctx, "failed to load identity links")
	}
	if len(existing) <= 1 {
		return nil, rpcError(ctx, ErrLastAuthMethod, connect.CodeFailedPrecondition,
			"this is your only sign-in method; link another identity before removing it")
	}

	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermUnlinkIdentity),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			removed, err := tx.DeleteIdentityLink(ctx, link.ID)
			if err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType:        "identity_link",
				ResourceID:          removed.ID,
				Action:              "UNLINK",
				Outcome:             store.EffectApplied,
				BeforeRef:           &removed.UserID,
				AfterRef:            &removed.ProviderID,
				EvidenceKind:        "external_subject_sha256",
				EvidenceFingerprint: fingerprint(removed.ExternalID),
			})
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrIdentityLinkNotFound, "identity link not found")
		}
		return nil, internalError(ctx, "failed to unlink identity")
	}
	return connect.NewResponse(&pmv1.UnlinkIdentityResponse{}), nil
}
