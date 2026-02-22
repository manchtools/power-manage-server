package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// TokenHandler handles registration token management RPCs.
type TokenHandler struct {
	store   *store.Store
	entropy *ulid.MonotonicEntropy
}

// NewTokenHandler creates a new token handler.
func NewTokenHandler(st *store.Store) *TokenHandler {
	return &TokenHandler{
		store:   st,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// CreateToken creates a new registration token.
func (h *TokenHandler) CreateToken(ctx context.Context, req *connect.Request[pm.CreateTokenRequest]) (*connect.Response[pm.CreateTokenResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Generate token value (32 bytes = 256 bits)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate token"))
	}
	tokenValue := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash the token for storage
	tokenHash := sha256.Sum256([]byte(tokenValue))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

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

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   id,
		EventType:  "TokenCreated",
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create token"))
	}

	// Read back from projection
	token, err := h.store.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: id})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get token"))
	}

	protoToken := tokenToProto(token)
	protoToken.Value = tokenValue // Only returned on creation

	return connect.NewResponse(&pm.CreateTokenResponse{
		Token: protoToken,
	}), nil
}

// GetToken returns a token by ID.
func (h *TokenHandler) GetToken(ctx context.Context, req *connect.Request[pm.GetTokenRequest]) (*connect.Response[pm.GetTokenResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	token, err := h.store.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: req.Msg.Id})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get token"))
	}

	return connect.NewResponse(&pm.GetTokenResponse{
		Token: tokenToProto(token),
	}), nil
}

// ListTokens returns a paginated list of tokens.
func (h *TokenHandler) ListTokens(ctx context.Context, req *connect.Request[pm.ListTokensRequest]) (*connect.Response[pm.ListTokensResponse], error) {
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

	tokens, err := h.store.Queries().ListTokens(ctx, db.ListTokensParams{
		Column1:       req.Msg.IncludeDisabled,
		Limit:         pageSize,
		Offset:        offset,
		FilterOwnerID: userFilterID(ctx, "ListTokens"),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list tokens"))
	}

	count, err := h.store.Queries().CountTokens(ctx, db.CountTokensParams{
		Column1:       req.Msg.IncludeDisabled,
		FilterOwnerID: userFilterID(ctx, "ListTokens"),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count tokens"))
	}

	var nextPageToken string
	if int32(len(tokens)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

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
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Emit TokenRenamed event
	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   req.Msg.Id,
		EventType:  "TokenRenamed",
		Data: map[string]any{
			"name": req.Msg.Name,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to rename token"))
	}

	// Read back from projection
	token, err := h.store.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: req.Msg.Id})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get token"))
	}

	return connect.NewResponse(&pm.UpdateTokenResponse{
		Token: tokenToProto(token),
	}), nil
}

// SetTokenDisabled enables or disables a token.
func (h *TokenHandler) SetTokenDisabled(ctx context.Context, req *connect.Request[pm.SetTokenDisabledRequest]) (*connect.Response[pm.UpdateTokenResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Emit appropriate event
	eventType := "TokenEnabled"
	if req.Msg.Disabled {
		eventType = "TokenDisabled"
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   req.Msg.Id,
		EventType:  eventType,
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update token"))
	}

	// Read back from projection
	token, err := h.store.Queries().GetTokenByID(ctx, db.GetTokenByIDParams{ID: req.Msg.Id})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get token"))
	}

	return connect.NewResponse(&pm.UpdateTokenResponse{
		Token: tokenToProto(token),
	}), nil
}

// DeleteToken deletes a token.
func (h *TokenHandler) DeleteToken(ctx context.Context, req *connect.Request[pm.DeleteTokenRequest]) (*connect.Response[pm.DeleteTokenResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Emit TokenDeleted event
	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "token",
		StreamID:   req.Msg.Id,
		EventType:  "TokenDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete token"))
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

	if t.ExpiresAt.Valid {
		token.ExpiresAt = timestamppb.New(t.ExpiresAt.Time)
	}

	if t.CreatedAt.Valid {
		token.CreatedAt = timestamppb.New(t.CreatedAt.Time)
	}

	if t.OwnerID != nil {
		token.OwnerId = *t.OwnerID
	}

	return token
}
