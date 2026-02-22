package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// IdentityLinkHandler handles self-service identity linking RPCs.
type IdentityLinkHandler struct {
	store *store.Store
}

// NewIdentityLinkHandler creates a new identity link handler.
func NewIdentityLinkHandler(st *store.Store) *IdentityLinkHandler {
	return &IdentityLinkHandler{store: st}
}

// ListIdentityLinks returns the current user's linked identities.
func (h *IdentityLinkHandler) ListIdentityLinks(ctx context.Context, req *connect.Request[pm.ListIdentityLinksRequest]) (*connect.Response[pm.ListIdentityLinksResponse], error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	links, err := h.store.Queries().ListIdentityLinksForUser(ctx, userCtx.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list identity links"))
	}

	protoLinks := make([]*pm.IdentityLink, len(links))
	for i, link := range links {
		protoLinks[i] = identityLinkRowToProto(link)
	}

	return connect.NewResponse(&pm.ListIdentityLinksResponse{
		Links: protoLinks,
	}), nil
}

// UnlinkIdentity removes a linked identity.
func (h *IdentityLinkHandler) UnlinkIdentity(ctx context.Context, req *connect.Request[pm.UnlinkIdentityRequest]) (*connect.Response[pm.UnlinkIdentityResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Get the link to verify ownership
	link, err := h.store.Queries().GetIdentityLinkByID(ctx, req.Msg.LinkId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("identity link not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get identity link"))
	}

	if link.UserID != userCtx.ID {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("cannot unlink another user's identity"))
	}

	// Prevent unlinking last auth method
	user, err := h.store.Queries().GetUserByID(ctx, userCtx.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	linkCount, err := h.store.Queries().CountIdentityLinksForUser(ctx, userCtx.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count identity links"))
	}

	if !user.HasPassword && linkCount <= 1 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("cannot remove last authentication method; set a password first"))
	}

	// Emit unlink event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   link.ID,
		EventType:  "IdentityUnlinked",
		Data: map[string]any{
			"user_id":     link.UserID,
			"provider_id": link.ProviderID,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to unlink identity"))
	}

	return connect.NewResponse(&pm.UnlinkIdentityResponse{}), nil
}

// identityLinkRowToProto converts a joined identity link row to a proto message.
func identityLinkRowToProto(link db.ListIdentityLinksForUserRow) *pm.IdentityLink {
	protoLink := &pm.IdentityLink{
		Id:            link.ID,
		UserId:        link.UserID,
		ProviderId:    link.ProviderID,
		ProviderName:  link.ProviderName,
		ProviderSlug:  link.ProviderSlug,
		ExternalId:    link.ExternalID,
		ExternalEmail: link.ExternalEmail,
		ExternalName:  link.ExternalName,
	}

	if link.LinkedAt.Valid {
		protoLink.LinkedAt = timestamppb.New(link.LinkedAt.Time)
	}
	if link.LastLoginAt.Valid {
		protoLink.LastLoginAt = timestamppb.New(link.LastLoginAt.Time)
	}

	return protoLink
}
