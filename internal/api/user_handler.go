package api

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
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

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	passwordHash, err := auth.HashPassword(req.Msg.Password)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to hash password")
	}

	id := ulid.Make().String()

	// Pre-check for an already-existing email so clients get a
	// structured AlreadyExists response in the common case. The
	// projection's UNIQUE WHERE NOT is_deleted constraint still
	// backstops correctness against the rare race where two
	// concurrent CreateUser calls slip past this check.
	//
	// Distinguish three branches: row found → AlreadyExists;
	// store.IsNotFound(err) → proceed (the email is free); any other
	// error → surface as Internal so a transient DB problem
	// doesn't get silently mistaken for "free to create" and
	// then re-surface as the generic Internal from AppendEvent
	// later — matching the established pattern in
	// auth_handler.go:59 and sso_handler.go:179.
	if _, err := h.store.Repos().User.GetByEmail(ctx, req.Msg.Email); err == nil {
		return nil, apiErrorCtx(ctx, ErrEmailAlreadyExists, connect.CodeAlreadyExists, "email already exists")
	} else if !store.IsNotFound(err) {
		// Don't log raw email (PII). At this point the user doesn't
		// exist yet (we're checking IF they should), so there's no
		// user_id either. Operators triaging this can correlate
		// from the request_id in the surrounding handler logs.
		h.logger.Error("failed to pre-check email uniqueness", "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to check email uniqueness")
	}

	// Assign Linux UID and derive username
	linuxUID, err := h.store.Repos().User.NextLinuxUID(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to assign linux uid")
	}
	linuxUsername := deriveLinuxUsername(req.Msg.Email, req.Msg.PreferredUsername)
	if linuxUsername == "" {
		linuxUsername = "user_" + id[:8]
	}

	// Resolve the role ID set BEFORE emitting the event so the user
	// INSERT and the per-role INSERTs land atomically inside the
	// projector's WithTx (issue #135). Empty role list -> look up
	// the built-in "User" role; missing-role lookup is escalated to
	// an Error log because shipping a user with zero permissions
	// silently is the bug operators triage.
	roleIDs := req.Msg.RoleIds
	if len(roleIDs) == 0 {
		userRole, err := h.store.Repos().Role.GetByName(ctx, "User")
		if err == nil {
			roleIDs = []string{userRole.ID}
		} else {
			h.logger.Error("failed to look up default User role; new user will be created with no roles",
				"user_id", id, "error", err)
		}
	}

	// Emit UserCreatedWithRoles compound event - one event, one
	// projector tx. The pre-#135 partial-write window between the
	// user row INSERT and the per-role INSERTs is no longer
	// reachable: either both land or neither does.
	defaultRole := "user"
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   id,
		EventType:  string(eventtypes.UserCreatedWithRoles),
		Data: payloads.UserCreatedWithRoles{
			Email:             &req.Msg.Email,
			PasswordHash:      &passwordHash,
			Role:              &defaultRole,
			DisplayName:       &req.Msg.DisplayName,
			GivenName:         &req.Msg.GivenName,
			FamilyName:        &req.Msg.FamilyName,
			PreferredUsername: &req.Msg.PreferredUsername,
			LinuxUsername:     &linuxUsername,
			LinuxUID:          &linuxUID,
			RoleIDs:           roleIDs,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		// The previous code mapped EVERY AppendEvent failure to
		// ErrEmailAlreadyExists / CodeAlreadyExists, which lied
		// to clients on DB outages, projection-trigger violations,
		// concurrent stream-version conflicts (which Store.AppendEvent
		// retries internally and surfaces as "version conflict
		// after N retries"), or any transient append failure.
		// Detecting a true duplicate-email violation HERE is
		// unreliable because Store.AppendEvent's internal
		// 23505-retry loop masks the original PgError.
		// Defer-to-handler-pre-check is the cleaner fix: callers
		// should look up the email BEFORE AppendEvent if they
		// want a specific already-exists error code. For now,
		// return a structured Internal error and log the actual
		// cause so operators can triage.
		h.logger.Error("failed to append UserCreatedWithRoles event", "user_id", id, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create user")
	}

	// Auto-enable provisioning/SSH if global server settings are on
	if settings, err := h.store.Queries().GetServerSettings(ctx); err == nil {
		if settings.UserProvisioningEnabled {
			provisioningEnabled := true
			if err := h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   id,
				EventType:  string(eventtypes.UserProvisioningSettingsUpdated),
				Data: payloads.UserProvisioningSettingsUpdated{
					UserProvisioningEnabled: &provisioningEnabled,
				},
				ActorType: "system",
				ActorID:   "auto",
			}); err != nil {
				h.logger.Warn("failed to auto-enable provisioning for new user", "user_id", id, "error", err)
			}
		}
		if settings.SshAccessForAll {
			sshOn, sshAllow, sshPwOff := true, true, false
			if err := h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   id,
				EventType:  string(eventtypes.UserSshSettingsUpdated),
				Data: payloads.UserSshSettingsUpdated{
					SshAccessEnabled: &sshOn,
					SshAllowPubkey:   &sshAllow,
					SshAllowPassword: &sshPwOff,
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
	user, err := h.store.Repos().User.Get(ctx, id)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get user")
	}

	// System-action sync runs from the post-commit listener
	// registered on the store (see api.SystemActionListener) — handler-
	// side calls were removed in rc11 #77 to keep the derived-model
	// invariant: handlers mutate source state only.

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

	user, err := h.store.Repos().User.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
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
	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	users, err := h.store.Repos().User.List(ctx, store.ListUsersFilter{Limit: pageSize, Offset: offset})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list users")
	}

	count, err := h.store.Repos().User.Count(ctx)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count users")
	}

	nextPageToken := buildNextPageToken(int32(len(users)), offset, pageSize, count)

	protoUsers := make([]*pm.User, len(users))
	pageUserIDs := make([]string, len(users))
	for i, u := range users {
		protoUsers[i] = userToProto(u)
		h.populateUserRoles(ctx, protoUsers[i])
		pageUserIDs[i] = u.ID
	}

	// Populate inherited roles from user group memberships. Scope
	// to the page's user IDs so the query cost stays page-bounded
	// instead of linear with system-wide group membership count.
	if len(pageUserIDs) > 0 {
		inheritedRoles, err := h.store.Queries().ListInheritedRolesByUserIDs(ctx, pageUserIDs)
		if err != nil {
			h.logger.Warn("failed to load inherited roles", "error", err)
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

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Emit UserEmailChanged event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.UserEmailChanged),
		Data: payloads.UserEmailChanged{
			Email: &req.Msg.Email,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update email")
	}

	// Read back from projection
	user, err := h.store.Repos().User.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
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

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// If user is updating their own password, verify current password
	if userCtx.ID == req.Msg.Id {
		if req.Msg.CurrentPassword == "" {
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "current_password is required for self-update")
		}

		user, err := h.store.Repos().User.Get(ctx, req.Msg.Id)
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
		EventType:  string(eventtypes.UserPasswordChanged),
		Data: payloads.UserPasswordChanged{
			PasswordHash: &passwordHash,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update password")
	}

	// Read back from projection
	user, err := h.store.Repos().User.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
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

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Emit appropriate event
	eventType := string(eventtypes.UserEnabled)
	if req.Msg.Disabled {
		eventType = string(eventtypes.UserDisabled)
	}

	err = h.store.AppendEvent(ctx, store.Event{
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
	user, err := h.store.Repos().User.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
	}

	// System-action sync runs from the post-commit listener (rc11 #77).

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// DeleteUser deletes a user.
func (h *UserHandler) DeleteUser(ctx context.Context, req *connect.Request[pm.DeleteUserRequest]) (*connect.Response[pm.DeleteUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Load user BEFORE delete to get system action IDs for cleanup
	user, err := h.store.Repos().User.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
	}

	// Emit UserDeleted event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.UserDeleted),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to delete user")
	}

	// Search-index removal is handled by api.SearchListener (post-commit
	// dispatch on UserDeleted) — handler-side enqueue removed in N005.

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

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Emit UserProfileUpdated event
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.Id,
		EventType:  string(eventtypes.UserProfileUpdated),
		Data: payloads.UserProfileUpdated{
			DisplayName:       &req.Msg.DisplayName,
			GivenName:         &req.Msg.GivenName,
			FamilyName:        &req.Msg.FamilyName,
			PreferredUsername: &req.Msg.PreferredUsername,
			Picture:           &req.Msg.Picture,
			Locale:            &req.Msg.Locale,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update profile")
	}

	// Read back from projection
	user, err := h.store.Repos().User.Get(ctx, req.Msg.Id)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
	}

	// System-action sync runs from the post-commit listener (rc11 #77).

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// userToProto converts a database user projection to a protobuf user.
func userToProto(u store.User) *pm.User {
	user := &pm.User{
		Id:                      u.ID,
		Email:                   u.Email,
		Disabled:                u.Disabled,
		TotpEnabled:             u.TotpEnabled,
		HasPassword:             u.HasPassword,
		DisplayName:             u.DisplayName,
		GivenName:               u.GivenName,
		FamilyName:              u.FamilyName,
		PreferredUsername:       u.PreferredUsername,
		Picture:                 u.Picture,
		Locale:                  u.Locale,
		LinuxUsername:           u.LinuxUsername,
		LinuxUid:                u.LinuxUID,
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

	for _, k := range u.SshPublicKeys {
		pk := &pm.SshPublicKey{
			Id:      k.KeyID,
			AddedAt: timestamppb.New(k.AddedAt),
		}
		if k.PublicKey != nil {
			pk.PublicKey = *k.PublicKey
		}
		if k.Comment != nil {
			pk.Comment = *k.Comment
		}
		user.SshPublicKeys = append(user.SshPublicKeys, pk)
	}

	return user
}

// SetUserProvisioningEnabled toggles per-user provisioning.
func (h *UserHandler) SetUserProvisioningEnabled(ctx context.Context, req *connect.Request[pm.SetUserProvisioningEnabledRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	enabled := req.Msg.Enabled
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  string(eventtypes.UserProvisioningSettingsUpdated),
		Data: payloads.UserProvisioningSettingsUpdated{
			UserProvisioningEnabled: &enabled,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update user provisioning settings")
	}

	// System-action sync runs from the post-commit listener (rc11 #77).

	user, err := h.store.Repos().User.Get(ctx, req.Msg.UserId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
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

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Sanitize the username the same way as during creation
	username := deriveLinuxUsername(req.Msg.LinuxUsername, "")
	if username == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid linux username")
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  string(eventtypes.UserLinuxUsernameChanged),
		Data: payloads.UserLinuxUsernameChanged{
			LinuxUsername: &username,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update linux username")
	}

	user, err := h.store.Repos().User.Get(ctx, req.Msg.UserId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
	}

	// System-action sync runs from the post-commit listener (rc11 #77).

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

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	keyID := ulid.Make().String()
	now := time.Now()
	addedAt := now.Format(time.RFC3339Nano)

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  string(eventtypes.UserSshKeyAdded),
		Data: payloads.UserSshKeyAdded{
			KeyID:     &keyID,
			PublicKey: &req.Msg.PublicKey,
			Comment:   &req.Msg.Comment,
			AddedAt:   &addedAt,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to add SSH key")
	}

	// System-action sync runs from the post-commit listener (rc11 #77).

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

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  string(eventtypes.UserSshKeyRemoved),
		Data: payloads.UserSshKeyRemoved{
			KeyID: &req.Msg.KeyId,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to remove SSH key")
	}

	// System-action sync runs from the post-commit listener (rc11 #77).

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

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	sshAccess := req.Msg.SshAccessEnabled
	sshPubkey := req.Msg.SshAllowPubkey
	sshPassword := req.Msg.SshAllowPassword
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   req.Msg.UserId,
		EventType:  string(eventtypes.UserSshSettingsUpdated),
		Data: payloads.UserSshSettingsUpdated{
			SshAccessEnabled: &sshAccess,
			SshAllowPubkey:   &sshPubkey,
			SshAllowPassword: &sshPassword,
		},
		ActorType: "user",
		ActorID:   userCtx.ID,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to update SSH settings")
	}

	user, err := h.store.Repos().User.Get(ctx, req.Msg.UserId)
	if err != nil {
		return nil, handleGetError(ctx, err, ErrUserNotFound, "user not found")
	}

	// System-action sync runs from the post-commit listener (rc11 #77).

	return connect.NewResponse(&pm.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

// populateUserIdentityLinks loads identity links for a user and attaches them to the proto User.
func (h *UserHandler) populateUserIdentityLinks(ctx context.Context, user *pm.User) {
	links, err := h.store.Repos().IdentityLink.ListForUser(ctx, user.Id)
	if err != nil {
		return
	}
	for _, link := range links {
		user.IdentityLinks = append(user.IdentityLinks, identityLinkRowToProto(link))
	}
}

// populateUserRoles loads roles for a user and attaches them to the proto User.
func (h *UserHandler) populateUserRoles(ctx context.Context, user *pm.User) {
	roles, err := h.store.Repos().Role.ListUserRoles(ctx, user.Id)
	if err != nil {
		return
	}
	for _, r := range roles {
		user.Roles = append(user.Roles, roleToProto(r))
	}
}
