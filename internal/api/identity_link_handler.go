package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/middleware"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// IdentityLinkHandler handles self-service identity linking RPCs.
type IdentityLinkHandler struct {
	store  *store.Store
	logger *slog.Logger
}

// NewIdentityLinkHandler creates a new identity link handler.
func NewIdentityLinkHandler(st *store.Store, logger *slog.Logger) *IdentityLinkHandler {
	return &IdentityLinkHandler{store: st, logger: logger}
}

// ListIdentityLinks returns the current user's linked identities.
func (h *IdentityLinkHandler) ListIdentityLinks(ctx context.Context, req *connect.Request[pm.ListIdentityLinksRequest]) (*connect.Response[pm.ListIdentityLinksResponse], error) {
	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	links, err := h.store.Queries().ListIdentityLinksForUser(ctx, userCtx.ID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list identity links")
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
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Get the link to verify ownership
	link, err := h.store.Queries().GetIdentityLinkByID(ctx, req.Msg.LinkId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrIdentityLinkNotFound, connect.CodeNotFound, "identity link not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get identity link")
	}

	// Non-admin callers can only unlink their own identities.
	if link.UserID != userCtx.ID && !auth.HasPermission(ctx, "DeleteUser") {
		return nil, apiErrorCtx(ctx, ErrCannotUnlinkOtherUser, connect.CodePermissionDenied, "cannot unlink another user's identity")
	}

	targetUserID := link.UserID

	// Prevent unlinking last auth method
	user, err := h.store.Queries().GetUserByID(ctx, targetUserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	linkCount, err := h.store.Queries().CountIdentityLinksForUser(ctx, targetUserID)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count identity links")
	}

	if !user.HasPassword && linkCount <= 1 {
		return nil, apiErrorCtx(ctx, ErrLastAuthMethod, connect.CodeFailedPrecondition, "cannot remove last authentication method; set a password first")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to unlink identity")
	}
	h.logger.Debug("event appended",
		"request_id", middleware.RequestIDFromContext(ctx),
		"stream_type", "identity_provider",
		"stream_id", link.ID,
		"event_type", "IdentityUnlinked",
	)

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

	protoLink.LinkedAt = timestamppb.New(link.LinkedAt)
	if link.LastLoginAt != nil {
		protoLink.LastLoginAt = timestamppb.New(*link.LastLoginAt)
	}

	return protoLink
}
