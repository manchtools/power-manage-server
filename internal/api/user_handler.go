package api

import (
	"context"
	"crypto/rand"
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

// UserHandler handles user management RPCs.
type UserHandler struct {
	store   *store.Store
	entropy *ulid.MonotonicEntropy
}

// NewUserHandler creates a new user handler.
func NewUserHandler(st *store.Store) *UserHandler {
	return &UserHandler{
		store:   st,
		entropy: ulid.Monotonic(rand.Reader, 0),
	}
}

// CreateUser creates a new user.
func (h *UserHandler) CreateUser(ctx context.Context, req *connect.Request[pm.CreateUserRequest]) (*connect.Response[pm.CreateUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	role := req.Msg.Role
	if role == "" {
		role = "user"
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	passwordHash, err := auth.HashPassword(req.Msg.Password)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to hash password"))
	}

	id := ulid.MustNew(ulid.Timestamp(time.Now()), h.entropy).String()

	// Emit UserCreated event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   id,
		EventType:  "UserCreated",
		Data: map[string]any{
			"email":         req.Msg.Email,
			"password_hash": passwordHash,
			"role":          role,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("email already exists"))
	}

	// Read back from projection
	user, err := h.store.QueriesFromContext(ctx).GetUserByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	return connect.NewResponse(&pm.CreateUserResponse{
		User: userToProto(user),
	}), nil
}

// GetUser returns a user by ID.
func (h *UserHandler) GetUser(ctx context.Context, req *connect.Request[pm.GetUserRequest]) (*connect.Response[pm.GetUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	user, err := h.store.QueriesFromContext(ctx).GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	return connect.NewResponse(&pm.GetUserResponse{
		User: userToProto(user),
	}), nil
}

// ListUsers returns a paginated list of users.
func (h *UserHandler) ListUsers(ctx context.Context, req *connect.Request[pm.ListUsersRequest]) (*connect.Response[pm.ListUsersResponse], error) {
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

	users, err := h.store.QueriesFromContext(ctx).ListUsers(ctx, db.ListUsersParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list users"))
	}

	count, err := h.store.QueriesFromContext(ctx).CountUsers(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to count users"))
	}

	var nextPageToken string
	if int32(len(users)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoUsers := make([]*pm.User, len(users))
	for i, u := range users {
		protoUsers[i] = userToProto(u)
	}

	return connect.NewResponse(&pm.ListUsersResponse{
		Users:         protoUsers,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// UpdateUserEmail updates a user's email.
func (h *UserHandler) UpdateUserEmail(ctx context.Context, req *connect.Request[pm.UpdateUserEmailRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Emit UserEmailChanged event
	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  "UserEmailChanged",
		Data: map[string]any{
			"email": req.Msg.Email,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update email"))
	}

	// Read back from projection
	user, err := h.store.QueriesFromContext(ctx).GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// UpdateUserPassword updates a user's password.
func (h *UserHandler) UpdateUserPassword(ctx context.Context, req *connect.Request[pm.UpdateUserPasswordRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// If user is updating their own password, verify current password
	if userCtx.ID == req.Msg.Id {
		if req.Msg.CurrentPassword == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("current_password is required for self-update"))
		}

		user, err := h.store.QueriesFromContext(ctx).GetUserByID(ctx, req.Msg.Id)
		if err != nil {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}

		if !auth.VerifyPassword(req.Msg.CurrentPassword, user.PasswordHash) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("current password is incorrect"))
		}
	} else if userCtx.Role != "admin" {
		// Non-admins can only update their own password
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
	}

	passwordHash, err := auth.HashPassword(req.Msg.NewPassword)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to hash password"))
	}

	// Emit UserPasswordChanged event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  "UserPasswordChanged",
		Data: map[string]any{
			"password_hash": passwordHash,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update password"))
	}

	// Read back from projection
	user, err := h.store.QueriesFromContext(ctx).GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// UpdateUserRole updates a user's role.
func (h *UserHandler) UpdateUserRole(ctx context.Context, req *connect.Request[pm.UpdateUserRoleRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Emit UserRoleChanged event
	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  "UserRoleChanged",
		Data: map[string]any{
			"role": req.Msg.Role,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update role"))
	}

	// Read back from projection
	user, err := h.store.QueriesFromContext(ctx).GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// SetUserDisabled enables or disables a user.
func (h *UserHandler) SetUserDisabled(ctx context.Context, req *connect.Request[pm.SetUserDisabledRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Emit appropriate event
	eventType := "UserEnabled"
	if req.Msg.Disabled {
		eventType = "UserDisabled"
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  eventType,
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update disabled status"))
	}

	// Read back from projection
	user, err := h.store.QueriesFromContext(ctx).GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// DeleteUser deletes a user.
func (h *UserHandler) DeleteUser(ctx context.Context, req *connect.Request[pm.DeleteUserRequest]) (*connect.Response[pm.DeleteUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Emit UserDeleted event
	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  "UserDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete user"))
	}

	return connect.NewResponse(&pm.DeleteUserResponse{}), nil
}

// userToProto converts a database user projection to a protobuf user.
func userToProto(u db.UsersProjection) *pm.User {
	user := &pm.User{
		Id:       u.ID,
		Email:    u.Email,
		Role:     u.Role,
		Disabled: u.Disabled,
	}

	if u.CreatedAt.Valid {
		user.CreatedAt = timestamppb.New(u.CreatedAt.Time)
	}

	if u.LastLoginAt.Valid {
		user.LastLoginAt = timestamppb.New(u.LastLoginAt.Time)
	}

	return user
}
