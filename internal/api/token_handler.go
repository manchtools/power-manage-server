package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// TokenHandler handles registration token management RPCs.
type TokenHandler struct {
	store  *store.Store
	logger *slog.Logger
}

// NewTokenHandler creates a new token handler.
func NewTokenHandler(st *store.Store, logger *slog.Logger) *TokenHandler {
	return &TokenHandler{
		store:  st,
		logger: logger,
	}
}

// CreateToken creates a new registration token.
func (h *TokenHandler) CreateToken(ctx context.Context, req *connect.Request[pm.CreateTokenRequest]) (*connect.Response[pm.CreateTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Generate token value (32 bytes = 256 bits)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to generate token")
	}
	tokenValue := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash the token for storage
	tokenHash := sha256.Sum256([]byte(tokenValue))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	id := ulid.Make().String()

	// Build event data — unrestricted CreateToken can set any params,
	// self-scoped CreateToken:self forces one-time use with 7-day expiry.
	eventData := map[string]any{
		"value_hash": tokenHashHex,
		"name":       req.Msg.Name,
	}

	if auth.HasPermission(ctx, "CreateToken") {
		// Unrestricted: can set any token configuration
		eventData["one_time"] = req.Msg.OneTime
		eventData["max_uses"] = req.Msg.MaxUses
		if req.Msg.ExpiresAt != nil && req.Msg.ExpiresAt.IsValid() {
			eventData["expires_at"] = req.Msg.ExpiresAt.AsTime().Format(time.RFC3339)
		}
	} else {
		// Self-scoped: one-time use, 7-day validity, owned by creator
		eventData["one_time"] = true
		eventData["max_uses"] = int32(1)
		eventData["expires_at"] = time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339)
		eventData["owner_id"] = userCtx.ID
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "token",
		StreamID:   id,
		EventType:  "TokenCreated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to create token"); err != nil {
		return nil, err
	}

	// Read back from projection
	token, err := h.store.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: id})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get token")
	}

	protoToken := tokenToProto(token)
	protoToken.Value = tokenValue // Only returned on creation

	return connect.NewResponse(&pm.CreateTokenResponse{
		Token: protoToken,
	}), nil
}

// GetToken returns a token by ID.
func (h *TokenHandler) GetToken(ctx context.Context, req *connect.Request[pm.GetTokenRequest]) (*connect.Response[pm.GetTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	token, err := h.store.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: req.Msg.Id})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrTokenNotFound, "token not found")
	}

	return connect.NewResponse(&pm.GetTokenResponse{
		Token: tokenToProto(token),
	}), nil
}

// ListTokens returns a paginated list of tokens.
func (h *TokenHandler) ListTokens(ctx context.Context, req *connect.Request[pm.ListTokensRequest]) (*connect.Response[pm.ListTokensResponse], error) {
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	tokens, err := h.store.Queries().ListTokens(ctx, db.ListTokensParams{
		Column1:       req.Msg.IncludeDisabled,
		Limit:         pageSize,
		Offset:        offset,
		FilterOwnerID: userFilterID(ctx, "ListTokens"),
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list tokens")
	}

	count, err := h.store.Queries().CountTokens(ctx, db.CountTokensParams{
		Column1:       req.Msg.IncludeDisabled,
		FilterOwnerID: userFilterID(ctx, "ListTokens"),
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count tokens")
	}

	nextPageToken := buildNextPageToken(int32(len(tokens)), offset, pageSize, count)

	protoTokens := make([]*pm.RegistrationToken, len(tokens))
	for i, t := range tokens {
		protoTokens[i] = tokenToProto(t)
	}

	return connect.NewResponse(&pm.ListTokensResponse{
		Tokens:        protoTokens,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// RenameToken renames a token.
func (h *TokenHandler) RenameToken(ctx context.Context, req *connect.Request[pm.RenameTokenRequest]) (*connect.Response[pm.UpdateTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Emit TokenRenamed event
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "token",
		StreamID:   req.Msg.Id,
		EventType:  "TokenRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	}, "failed to rename token"); err != nil {
		return nil, err
	}

	// Read back from projection
	token, err := h.store.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: req.Msg.Id})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrTokenNotFound, "token not found")
	}

	return connect.NewResponse(&pm.UpdateTokenResponse{
		Token: tokenToProto(token),
	}), nil
}

// SetTokenDisabled enables or disables a token.
func (h *TokenHandler) SetTokenDisabled(ctx context.Context, req *connect.Request[pm.SetTokenDisabledRequest]) (*connect.Response[pm.UpdateTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Emit appropriate event
	eventType := "TokenEnabled"
	if req.Msg.Disabled {
		eventType = "TokenDisabled"
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "token",
		StreamID:   req.Msg.Id,
		EventType:  eventType,
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to update token"); err != nil {
		return nil, err
	}

	// Read back from projection
	token, err := h.store.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: req.Msg.Id})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrTokenNotFound, "token not found")
	}

	return connect.NewResponse(&pm.UpdateTokenResponse{
		Token: tokenToProto(token),
	}), nil
}

// DeleteToken deletes a token.
func (h *TokenHandler) DeleteToken(ctx context.Context, req *connect.Request[pm.DeleteTokenRequest]) (*connect.Response[pm.DeleteTokenResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Emit TokenDeleted event
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "token",
		StreamID:   req.Msg.Id,
		EventType:  "TokenDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to delete token"); err != nil {
		return nil, err
	}

	return connect.NewResponse(&pm.DeleteTokenResponse{}), nil
}

// tokenToProto converts a database token projection to a protobuf token.
func tokenToProto(t db.TokensProjection) *pm.RegistrationToken {
	token := &pm.RegistrationToken{
		Id:          t.ID,
		Name:        t.Name,
		OneTime:     t.OneTime,
		MaxUses:     t.MaxUses,
		CurrentUses: t.CurrentUses,
		CreatedBy:   t.CreatedBy,
		Disabled:    t.Disabled,
	}

	if t.ExpiresAt != nil {
		token.ExpiresAt = timestamppb.New(*t.ExpiresAt)
	}

	if t.CreatedAt != nil {
		token.CreatedAt = timestamppb.New(*t.CreatedAt)
	}

	if t.OwnerID != nil {
		token.OwnerId = *t.OwnerID
	}

	return token
}
