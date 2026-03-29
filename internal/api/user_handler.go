package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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
	store         *store.Store
	logger        *slog.Logger
	systemActions *SystemActionManager
}

// NewUserHandler creates a new user handler.
func NewUserHandler(st *store.Store, logger *slog.Logger, systemActions *SystemActionManager) *UserHandler {
	return &UserHandler{
		store:         st,
		logger:        logger,
		systemActions: systemActions,
	}
}

// CreateUser creates a new user.
func (h *UserHandler) CreateUser(ctx context.Context, req *connect.Request[pm.CreateUserRequest]) (*connect.Response[pm.CreateUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	passwordHash, err := auth.HashPassword(req.Msg.Password)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to hash password")
	}

	id := ulid.Make().String()

	// Assign Linux UID and derive username
	linuxUID, err := h.store.Queries().GetNextLinuxUID(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to assign linux uid")
	}
	linuxUsername := deriveLinuxUsername(req.Msg.Email, req.Msg.PreferredUsername)
	if linuxUsername == "" {
		linuxUsername = "user_" + id[:8]
	}

	// Emit UserCreated event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   id,
		EventType:  "UserCreated",
		Data: map[string]any{
			"email":              req.Msg.Email,
			"password_hash":      passwordHash,
			"role":               "user",
			"display_name":       req.Msg.DisplayName,
			"given_name":         req.Msg.GivenName,
			"family_name":        req.Msg.FamilyName,
			"preferred_username": req.Msg.PreferredUsername,
			"linux_username":     linuxUsername,
			"linux_uid":          linuxUID,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrEmailAlreadyExists, connect.CodeAlreadyExists, "email already exists")
	}

	// Auto-assign specified roles, or default User role if none specified
	roleIDs := req.Msg.RoleIds
	if len(roleIDs) == 0 {
		// Assign the built-in User role
		userRole, err := h.store.Queries().GetRoleByName(ctx, "User")
		if err == nil {
			roleIDs = []string{userRole.ID}
		}
	}
	for _, roleID := range roleIDs {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "user_role",
			StreamID:   id + ":" + roleID,
			EventType:  "UserRoleAssigned",
			Data: map[string]any{
				"user_id": id,
				"role_id": roleID,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}); err != nil {
			slog.Warn("failed to append UserRoleAssigned event", "user_id", id, "role_id", roleID, "error", err)
		}
	}

	// Auto-enable provisioning/SSH if global server settings are on
	if settings, err := h.store.Queries().GetServerSettings(ctx); err == nil {
		if settings.UserProvisioningEnabled {
			if err := h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   id,
				EventType:  "UserProvisioningSettingsUpdated",
				Data:       map[string]any{"user_provisioning_enabled": true},
				ActorType:  "system",
				ActorID:    "auto",
			}); err != nil {
				h.logger.Warn("failed to auto-enable provisioning for new user", "user_id", id, "error", err)
			}
		}
		if settings.SshAccessForAll {
			if err := h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   id,
				EventType:  "UserSshSettingsUpdated",
				Data: map[string]any{
					"ssh_access_enabled": true,
					"ssh_allow_pubkey":   true,
					"ssh_allow_password": false,
				},
				ActorType: "system",
				ActorID:   "auto",
			}); err != nil {
				h.logger.Warn("failed to auto-enable SSH for new user", "user_id", id, "error", err)
			}
		}
	} else {
		h.logger.Warn("failed to check server settings for new user defaults", "error", err)
	}

	// Read back from projection
	user, err := h.store.Queries().GetUserByID(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	// Sync system actions (fire-and-forget)
	if h.systemActions != nil {
		if err := h.systemActions.SyncUserSystemActions(ctx, id); err != nil {
			h.logger.Error("failed to sync system actions after user creation", "user_id", id, "error", err)
		}
	}

	protoUser := userToProto(user)
	h.populateUserRoles(ctx, protoUser)

	return connect.NewResponse(&pm.CreateUserResponse{
		User: protoUser,
	}), nil
}

// GetUser returns a user by ID.
func (h *UserHandler) GetUser(ctx context.Context, req *connect.Request[pm.GetUserRequest]) (*connect.Response[pm.GetUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceSelfScope(ctx, "GetUser", req.Msg.Id); err != nil {
		return nil, err
	}

	user, err := h.store.Queries().GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	protoUser := userToProto(user)
	h.populateUserRoles(ctx, protoUser)
	h.populateUserIdentityLinks(ctx, protoUser)

	return connect.NewResponse(&pm.GetUserResponse{
		User: protoUser,
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
			return nil, apiErrorCtx(ctx, ErrInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
		}
		offset = int32(offset64)
	}

	users, err := h.store.Queries().ListUsers(ctx, db.ListUsersParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list users")
	}

	count, err := h.store.Queries().CountUsers(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count users")
	}

	var nextPageToken string
	if int32(len(users)) == pageSize && int64(offset)+int64(pageSize) < count {
		nextPageToken = formatPageToken(int64(offset) + int64(pageSize))
	}

	protoUsers := make([]*pm.User, len(users))
	for i, u := range users {
		protoUsers[i] = userToProto(u)
		h.populateUserRoles(ctx, protoUsers[i])
	}

	// Populate inherited roles from user group memberships
	inheritedRoles, err := h.store.Queries().ListAllInheritedRoles(ctx)
	if err != nil {
		slog.Warn("failed to load inherited roles", "error", err)
	} else {
		inheritedMap := make(map[string][]*pm.InheritedRole)
		for _, ir := range inheritedRoles {
			inheritedMap[ir.UserID] = append(inheritedMap[ir.UserID], &pm.InheritedRole{
				RoleId:    ir.RoleID,
				RoleName:  ir.RoleName,
				GroupId:   ir.GroupID,
				GroupName: ir.GroupName,
			})
		}
		for _, u := range protoUsers {
			if roles, ok := inheritedMap[u.Id]; ok {
				u.InheritedRoles = roles
			}
		}
	}

	return connect.NewResponse(&pm.ListUsersResponse{
		Users:         protoUsers,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// UpdateUserEmail updates a user's email.
func (h *UserHandler) UpdateUserEmail(ctx context.Context, req *connect.Request[pm.UpdateUserEmailRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceSelfScope(ctx, "UpdateUserEmail", req.Msg.Id); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update email")
	}

	// Read back from projection
	user, err := h.store.Queries().GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// UpdateUserPassword updates a user's password.
func (h *UserHandler) UpdateUserPassword(ctx context.Context, req *connect.Request[pm.UpdateUserPasswordRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceSelfScope(ctx, "UpdateUserPassword", req.Msg.Id); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// If user is updating their own password, verify current password
	if userCtx.ID == req.Msg.Id {
		if req.Msg.CurrentPassword == "" {
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "current_password is required for self-update")
		}

		user, err := h.store.Queries().GetUserByID(ctx, req.Msg.Id)
		if err != nil {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}

		if !auth.VerifyPassword(req.Msg.CurrentPassword, derefPasswordHash(user.PasswordHash)) {
			return nil, apiErrorCtx(ctx, ErrPasswordIncorrect, connect.CodePermissionDenied, "current password is incorrect")
		}
	}
	// Note: OPA authz interceptor handles permission checks for non-self updates

	passwordHash, err := auth.HashPassword(req.Msg.NewPassword)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to hash password")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update password")
	}

	// Read back from projection
	user, err := h.store.Queries().GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// SetUserDisabled enables or disables a user.
func (h *UserHandler) SetUserDisabled(ctx context.Context, req *connect.Request[pm.SetUserDisabledRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update disabled status")
	}

	// Read back from projection
	user, err := h.store.Queries().GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	// Sync system actions (disabled flag changes USER action params)
	if h.systemActions != nil {
		if err := h.systemActions.SyncUserSystemActions(ctx, req.Msg.Id); err != nil {
			h.logger.Error("failed to sync system actions after disable/enable", "user_id", req.Msg.Id, "error", err)
		}
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// DeleteUser deletes a user.
func (h *UserHandler) DeleteUser(ctx context.Context, req *connect.Request[pm.DeleteUserRequest]) (*connect.Response[pm.DeleteUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Load user BEFORE delete to get system action IDs for cleanup
	user, err := h.store.Queries().GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	// Emit UserDeleted event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  "UserDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to delete user")
	}

	// Clean up system actions
	if err := h.systemActions.CleanupDeletedUserActions(ctx, user); err != nil {
		h.logger.Error("failed to cleanup system actions for deleted user", "user_id", req.Msg.Id, "error", err)
	}

	return connect.NewResponse(&pm.DeleteUserResponse{}), nil
}

// UpdateUserProfile updates a user's profile fields.
func (h *UserHandler) UpdateUserProfile(ctx context.Context, req *connect.Request[pm.UpdateUserProfileRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceSelfScope(ctx, "UpdateUserProfile", req.Msg.Id); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Emit UserProfileUpdated event
	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  "UserProfileUpdated",
		Data: map[string]any{
			"display_name":       req.Msg.DisplayName,
			"given_name":         req.Msg.GivenName,
			"family_name":        req.Msg.FamilyName,
			"preferred_username": req.Msg.PreferredUsername,
			"picture":            req.Msg.Picture,
			"locale":             req.Msg.Locale,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update profile")
	}

	// Read back from projection
	user, err := h.store.Queries().GetUserByID(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	// Sync system actions (display_name change affects USER action comment)
	if h.systemActions != nil {
		if err := h.systemActions.SyncUserSystemActions(ctx, req.Msg.Id); err != nil {
			h.logger.Error("failed to sync system actions after profile update", "user_id", req.Msg.Id, "error", err)
		}
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// userToProto converts a database user projection to a protobuf user.
func userToProto(u db.UsersProjection) *pm.User {
	user := &pm.User{
		Id:                u.ID,
		Email:             u.Email,
		Disabled:          u.Disabled,
		TotpEnabled:       u.TotpEnabled,
		HasPassword:       u.HasPassword,
		DisplayName:       u.DisplayName,
		GivenName:         u.GivenName,
		FamilyName:        u.FamilyName,
		PreferredUsername:  u.PreferredUsername,
		Picture:           u.Picture,
		Locale:            u.Locale,
		LinuxUsername:      u.LinuxUsername,
		LinuxUid:          u.LinuxUid,
		SshAccessEnabled:        u.SshAccessEnabled,
		SshAllowPubkey:          u.SshAllowPubkey,
		SshAllowPassword:        u.SshAllowPassword,
		UserProvisioningEnabled: u.UserProvisioningEnabled,
	}

	if u.CreatedAt != nil {
		user.CreatedAt = timestamppb.New(*u.CreatedAt)
	}

	if u.LastLoginAt != nil {
		user.LastLoginAt = timestamppb.New(*u.LastLoginAt)
	}

	// Parse SSH public keys from JSONB
	if len(u.SshPublicKeys) > 0 {
		var keys []struct {
			ID        string `json:"id"`
			PublicKey string `json:"public_key"`
			Comment   string `json:"comment"`
			AddedAt   string `json:"added_at"`
		}
		if err := json.Unmarshal(u.SshPublicKeys, &keys); err == nil {
			for _, k := range keys {
				pk := &pm.SshPublicKey{
					Id:        k.ID,
					PublicKey: k.PublicKey,
					Comment:   k.Comment,
				}
				if t, err := time.Parse(time.RFC3339, k.AddedAt); err == nil {
					pk.AddedAt = timestamppb.New(t)
				}
				user.SshPublicKeys = append(user.SshPublicKeys, pk)
			}
		}
	}

	return user
}

// SetUserProvisioningEnabled toggles per-user provisioning.
func (h *UserHandler) SetUserProvisioningEnabled(ctx context.Context, req *connect.Request[pm.SetUserProvisioningEnabledRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  "UserProvisioningSettingsUpdated",
		Data: map[string]any{
			"user_provisioning_enabled": req.Msg.Enabled,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update user provisioning settings")
	}

	// Sync system actions
	if err := h.systemActions.SyncUserSystemActions(ctx, req.Msg.UserId); err != nil {
		h.logger.Error("failed to sync system actions after provisioning toggle", "user_id", req.Msg.UserId, "error", err)
	}

	user, err := h.store.Queries().GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// derefPasswordHash safely dereferences a *string password hash.
func derefPasswordHash(ph *string) string {
	if ph == nil {
		return ""
	}
	return *ph
}

// UpdateUserLinuxUsername updates a user's linux username.
func (h *UserHandler) UpdateUserLinuxUsername(ctx context.Context, req *connect.Request[pm.UpdateUserLinuxUsernameRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	// Sanitize the username the same way as during creation
	username := deriveLinuxUsername(req.Msg.LinuxUsername, "")
	if username == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid linux username")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  "UserLinuxUsernameChanged",
		Data: map[string]any{
			"linux_username": username,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update linux username")
	}

	user, err := h.store.Queries().GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	if h.systemActions != nil {
		if err := h.systemActions.SyncUserSystemActions(ctx, req.Msg.UserId); err != nil {
			h.logger.Error("failed to sync system actions after username change", "user_id", req.Msg.UserId, "error", err)
		}
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// AddUserSshKey adds an SSH public key to a user.
func (h *UserHandler) AddUserSshKey(ctx context.Context, req *connect.Request[pm.AddUserSshKeyRequest]) (*connect.Response[pm.AddUserSshKeyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceSelfScope(ctx, "AddUserSshKey", req.Msg.UserId); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	keyID := ulid.Make().String()
	now := time.Now()

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  "UserSshKeyAdded",
		Data: map[string]any{
			"key_id":     keyID,
			"public_key": req.Msg.PublicKey,
			"comment":    req.Msg.Comment,
			"added_at":   now.Format(time.RFC3339),
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to add SSH key")
	}

	if h.systemActions != nil {
		if err := h.systemActions.SyncUserSystemActions(ctx, req.Msg.UserId); err != nil {
			h.logger.Error("failed to sync system actions after SSH key added", "user_id", req.Msg.UserId, "error", err)
		}
	}

	return connect.NewResponse(&pm.AddUserSshKeyResponse{
		Key: &pm.SshPublicKey{
			Id:        keyID,
			PublicKey: req.Msg.PublicKey,
			Comment:   req.Msg.Comment,
			AddedAt:   timestamppb.New(now),
		},
	}), nil
}

// RemoveUserSshKey removes an SSH public key from a user.
func (h *UserHandler) RemoveUserSshKey(ctx context.Context, req *connect.Request[pm.RemoveUserSshKeyRequest]) (*connect.Response[pm.RemoveUserSshKeyResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceSelfScope(ctx, "RemoveUserSshKey", req.Msg.UserId); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  "UserSshKeyRemoved",
		Data: map[string]any{
			"key_id": req.Msg.KeyId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to remove SSH key")
	}

	if h.systemActions != nil {
		if err := h.systemActions.SyncUserSystemActions(ctx, req.Msg.UserId); err != nil {
			h.logger.Error("failed to sync system actions after SSH key removed", "user_id", req.Msg.UserId, "error", err)
		}
	}

	return connect.NewResponse(&pm.RemoveUserSshKeyResponse{}), nil
}

// UpdateUserSshSettings updates a user's SSH access settings.
func (h *UserHandler) UpdateUserSshSettings(ctx context.Context, req *connect.Request[pm.UpdateUserSshSettingsRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceSelfScope(ctx, "UpdateUserSshSettings", req.Msg.UserId); err != nil {
		return nil, err
	}

	userCtx, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, apiErrorCtx(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
	}

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  "UserSshSettingsUpdated",
		Data: map[string]any{
			"ssh_access_enabled": req.Msg.SshAccessEnabled,
			"ssh_allow_pubkey":   req.Msg.SshAllowPubkey,
			"ssh_allow_password": req.Msg.SshAllowPassword,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update SSH settings")
	}

	user, err := h.store.Queries().GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiErrorCtx(ctx, ErrUserNotFound, connect.CodeNotFound, "user not found")
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	if h.systemActions != nil {
		if err := h.systemActions.SyncUserSystemActions(ctx, req.Msg.UserId); err != nil {
			h.logger.Error("failed to sync system actions after SSH settings update", "user_id", req.Msg.UserId, "error", err)
		}
	}

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// populateUserIdentityLinks loads identity links for a user and attaches them to the proto User.
func (h *UserHandler) populateUserIdentityLinks(ctx context.Context, user *pm.User) {
	links, err := h.store.Queries().ListIdentityLinksForUser(ctx, user.Id)
	if err != nil {
		return
	}
	for _, link := range links {
		user.IdentityLinks = append(user.IdentityLinks, identityLinkRowToProto(link))
	}
}

// populateUserRoles loads roles for a user and attaches them to the proto User.
func (h *UserHandler) populateUserRoles(ctx context.Context, user *pm.User) {
	roles, err := h.store.Queries().GetUserRoles(ctx, user.Id)
	if err != nil {
		return
	}
	for _, r := range roles {
		user.Roles = append(user.Roles, roleToProto(r))
	}
}
