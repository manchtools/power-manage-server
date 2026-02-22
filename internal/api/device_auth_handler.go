package api

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/auth/totp"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// DeviceAuthHandler handles device authentication RPCs (PAM/NSS device login).
type DeviceAuthHandler struct {
	store      *store.Store
	jwtManager *auth.JWTManager
	encryptor  *crypto.Encryptor
	// deviceLoginURL is the configurable base URL for the browser-based
	// device login page. Defaults to "{externalURL}/app/device-login".
	deviceLoginURL string
	externalURL    string
}

// NewDeviceAuthHandler creates a new device auth handler.
func NewDeviceAuthHandler(st *store.Store, jwtManager *auth.JWTManager, enc *crypto.Encryptor, deviceLoginURL, externalURL string) *DeviceAuthHandler {
	return &DeviceAuthHandler{
		store:          st,
		jwtManager:     jwtManager,
		encryptor:      enc,
		deviceLoginURL: deviceLoginURL,
		externalURL:    externalURL,
	}
}

// AuthenticateDeviceUser authenticates a user for device login.
// Called by the agent's local auth proxy on behalf of the PAM module.
//
// If the device has no assigned owner, the first user to successfully
// authenticate becomes the device owner automatically.
func (h *DeviceAuthHandler) AuthenticateDeviceUser(ctx context.Context, req *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// 1. Verify the device exists
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{
		ID: req.Msg.DeviceId,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to look up device"))
	}

	// 2. Look up user by email/username
	user, err := h.store.Queries().GetUserByEmail(ctx, req.Msg.Username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Perform dummy hash to prevent timing-based user enumeration
			auth.VerifyPassword(req.Msg.Password, auth.DummyHash)
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success: false,
				Error:   "invalid credentials",
			}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to look up user"))
	}

	// 3. Check if user is disabled
	if user.Disabled {
		return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
			Success: false,
			Error:   "account is disabled",
		}), nil
	}

	// 4. Check if user is authorized for this device.
	// If no owner is assigned, any authenticated user will be accepted
	// and automatically assigned as the device owner (see step 11).
	hasOwner := device.AssignedUserID != nil
	authorized := !hasOwner || *device.AssignedUserID == user.ID
	if !authorized {
		// TODO: Expand authorization to check user-to-device assignments, device groups, user groups
		return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
			Success: false,
			Error:   "user is not authorized for this device",
		}), nil
	}

	// 5. Handle empty password (auth method probe)
	if req.Msg.Password == "" {
		resp := &pm.AuthenticateDeviceUserResponse{Success: false}
		if user.HasPassword {
			resp.PasswordRequired = true
		} else {
			resp.OidcRequired = true
		}
		return connect.NewResponse(resp), nil
	}

	// 6. Check if user has password auth available
	if !user.HasPassword {
		return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
			Success:      false,
			OidcRequired: true,
			Error:        "password login is not available for this account",
		}), nil
	}

	// 7. Check if any linked provider disables password login
	disablingProviders, err := h.store.Queries().GetLinkedProvidersDisablingPassword(ctx, user.ID)
	if err == nil && len(disablingProviders) > 0 {
		return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
			Success:      false,
			OidcRequired: true,
			Error:        "password login is disabled by identity provider",
		}), nil
	}

	// 8. Verify password
	if !auth.VerifyPassword(req.Msg.Password, derefPasswordHash(user.PasswordHash)) {
		return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
			Success: false,
			Error:   "invalid credentials",
		}), nil
	}

	// 9. Check TOTP
	if user.TotpEnabled {
		if req.Msg.TotpCode == "" {
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success:      false,
				TotpRequired: true,
			}), nil
		}
		// Validate TOTP code
		totpRecord, err := h.store.Queries().GetTOTPByUserID(ctx, user.ID)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get TOTP data"))
		}
		secret, err := h.encryptor.Decrypt(totpRecord.SecretEncrypted)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to decrypt TOTP secret"))
		}
		codeValid := false
		if len(req.Msg.TotpCode) == 6 {
			codeValid = totp.ValidateCode(req.Msg.TotpCode, secret)
		}
		if !codeValid {
			idx := totp.VerifyBackupCode(req.Msg.TotpCode, totpRecord.BackupCodesHash, totpRecord.BackupCodesUsed)
			if idx >= 0 {
				codeValid = true
				_ = h.store.AppendEvent(ctx, store.Event{
					StreamType: "totp",
					StreamID:   user.ID,
					EventType:  "TOTPBackupCodeUsed",
					Data:       map[string]any{"index": idx},
					ActorType:  "system",
					ActorID:    "device-auth",
				})
			}
		}
		if !codeValid {
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success: false,
				Error:   "invalid TOTP code",
			}), nil
		}
	}

	// 10. Authentication successful — build response
	userInfo := buildDeviceUserInfo(user.ID, user.Email)

	// 11. If device has no owner, assign this user as the owner
	if !hasOwner {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   req.Msg.DeviceId,
			EventType:  "DeviceAssigned",
			Data:       map[string]any{"user_id": user.ID},
			ActorType:  "system",
			ActorID:    "device-auth",
		}); err != nil {
			slog.Warn("failed to auto-assign device owner on first login",
				"device_id", req.Msg.DeviceId, "user_id", user.ID, "error", err)
		}
	}

	// Generate a device session token
	sessionToken, err := h.jwtManager.GenerateDeviceSessionToken(user.ID, user.Email, req.Msg.DeviceId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate session token"))
	}

	return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
		Success:           true,
		User:              userInfo,
		SessionToken:      sessionToken,
		SessionTtlSeconds: 28800, // 8 hours
	}), nil
}

// GetDeviceLoginURL returns the browser URL for OIDC-only device login.
func (h *DeviceAuthHandler) GetDeviceLoginURL(ctx context.Context, req *connect.Request[pm.GetDeviceLoginURLRequest]) (*connect.Response[pm.GetDeviceLoginURLResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{
		ID: req.Msg.DeviceId,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to look up device"))
	}

	// Build login URL using configurable base URL
	baseURL := h.deviceLoginURL
	if baseURL == "" {
		baseURL = h.externalURL + "/app/device-login"
	}

	// Generate state token
	state := newULID()
	// TODO: Store state in auth_states table for validation on callback

	loginURL := fmt.Sprintf("%s?state=%s&callback_port=%d&device_id=%s",
		baseURL, state, req.Msg.CallbackPort, req.Msg.DeviceId)
	if req.Msg.Username != "" {
		loginURL += "&username=" + req.Msg.Username
	}

	return connect.NewResponse(&pm.GetDeviceLoginURLResponse{
		LoginUrl: loginURL,
	}), nil
}

// DeviceLoginCallback handles the callback after browser-based device login.
func (h *DeviceAuthHandler) DeviceLoginCallback(ctx context.Context, req *connect.Request[pm.DeviceLoginCallbackRequest]) (*connect.Response[pm.DeviceLoginCallbackResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// TODO: Implement callback token validation (post-PoC)
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("device login callback not yet implemented"))
}

// ListDeviceUsers returns all users authorized to log into a device.
func (h *DeviceAuthHandler) ListDeviceUsers(ctx context.Context, req *connect.Request[pm.ListDeviceUsersRequest]) (*connect.Response[pm.ListDeviceUsersResponse], error) {
	if err := Validate(req.Msg); err != nil {
		return nil, err
	}

	// Verify device exists
	device, err := h.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{
		ID: req.Msg.DeviceId,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("device not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to look up device"))
	}

	var users []*pm.DeviceUserInfo

	// For PoC: return the device owner as an authorized user
	if device.AssignedUserID != nil {
		owner, err := h.store.Queries().GetUserByID(ctx, *device.AssignedUserID)
		if err == nil && !owner.Disabled {
			users = append(users, buildDeviceUserInfo(owner.ID, owner.Email))
		}
	}

	// TODO: Expand to include users authorized via assignments, user groups, etc.

	return connect.NewResponse(&pm.ListDeviceUsersResponse{
		Users: users,
	}), nil
}

// buildDeviceUserInfo creates a DeviceUserInfo from a user's PM data.
func buildDeviceUserInfo(userID, email string) *pm.DeviceUserInfo {
	// Derive a local username from email (part before @)
	username := email
	for i, c := range email {
		if c == '@' {
			username = email[:i]
			break
		}
	}

	// Deterministic UID from user ID (ULID → UID in range 60000-64999)
	uid := assignUID(userID)

	return &pm.DeviceUserInfo{
		Username: username,
		Uid:      uid,
		Gid:      uid, // Per-user primary group
		HomeDir:  "/home/" + username,
		Shell:    "/bin/bash",
		Groups:   []string{"pm-users"},
		Gecos:    email,
	}
}

// assignUID deterministically maps a PM user ID (ULID) to a Linux UID
// in the range 60000-64999.
func assignUID(userID string) uint32 {
	h := sha256.Sum256([]byte(userID))
	n := binary.BigEndian.Uint32(h[:4])
	return 60000 + (n % 5000)
}
