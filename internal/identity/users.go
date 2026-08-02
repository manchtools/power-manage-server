package identity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"golang.org/x/crypto/ssh"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// loadUserView reads one subject and everything a User message shows.
func (h *Handlers) loadUserView(ctx context.Context, userID string) (userView, error) {
	row, err := h.store.GetUser(ctx, userID)
	if err != nil {
		return userView{}, err
	}
	view := userView{Row: row}
	if view.SSHKeys, err = h.store.ListUserSSHKeys(ctx, userID); err != nil {
		return userView{}, err
	}
	if view.IdentityLinks, err = h.store.ListIdentityLinksForUser(ctx, userID); err != nil {
		return userView{}, err
	}
	if view.RoleGrants, err = h.store.ListUserRoleGrants(ctx, userID); err != nil {
		return userView{}, err
	}
	if view.InheritedRoles, err = h.store.ListInheritedRolesForUser(ctx, userID); err != nil {
		return userView{}, err
	}
	return view, nil
}

// resolveUserTarget is the shared front half of every user-target
// handler: it validates, authenticates, applies the self/scope tiers
// and resolves the row.
//
// A caller who may not see the target and a target that does not exist
// get the SAME not-found answer. That is the design's rule for
// object-scoped access, and it is enforced here rather than per handler
// so no handler can accidentally return permission-denied and confirm
// the row exists.
func (h *Handlers) resolveUserTarget(ctx context.Context, permission, targetID string) (store.UserRow, error) {
	if _, err := h.requireActor(ctx); err != nil {
		return store.UserRow{}, err
	}

	// Tier 1: the unrestricted or user-group-scoped permission, tier 2:
	// `:self`. EnforceUserScopeOrSelf decides between them, and a
	// principal that cannot own resources can never take the self path.
	if scopeErr := auth.EnforceUserScopeOrSelf(ctx, h.scopeResolver(), permission, targetID); scopeErr != nil {
		var connectErr *connect.Error
		if errors.As(scopeErr, &connectErr) && connectErr.Code() == connect.CodeUnauthenticated {
			return store.UserRow{}, rpcError(ctx, ErrNotAuthenticated, connect.CodeUnauthenticated, "not authenticated")
		}
		// A confined caller must not learn whether the row exists.
		return store.UserRow{}, notFound(ctx, ErrUserNotFound, "user not found")
	}

	row, err := h.store.GetUser(ctx, targetID)
	if err != nil {
		if store.IsNotFound(err) {
			return store.UserRow{}, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return store.UserRow{}, internalError(ctx, "failed to load user")
	}
	return row, nil
}

// scopeResolver answers the group-membership questions the scope
// helpers ask, over the live tables.
func (h *Handlers) scopeResolver() auth.ScopeResolver { return storeScopeResolver{h.store} }

type storeScopeResolver struct{ store Store }

func (r storeScopeResolver) UserGroupsForUser(ctx context.Context, userID string) ([]string, error) {
	return r.store.ListUserGroupIDsForUser(ctx, userID)
}

// DeviceGroupsForDevice is not answerable from the identity store. No
// identity handler asks a device-scope question, so returning an error
// fails closed rather than pretending the device is in no group, which
// the scope helpers would read as "denied" only by accident.
func (r storeScopeResolver) DeviceGroupsForDevice(context.Context, string) ([]string, error) {
	return nil, errors.New("identity: device scope is not resolvable here")
}

// GetUser returns one subject.
func (h *Handlers) GetUser(ctx context.Context, req *connect.Request[pmv1.GetUserRequest]) (*connect.Response[pmv1.GetUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.resolveUserTarget(ctx, PermGetUser, req.Msg.Id); err != nil {
		return nil, err
	}
	view, err := h.loadUserView(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to load user")
	}
	return connect.NewResponse(&pmv1.GetUserResponse{User: userToProto(view)}), nil
}

// ListUsers pages the subject list.
//
// A caller confined to user groups sees only subjects in those groups.
// The narrowing happens here, on rows already read, because the scope
// set comes from the caller's token and the page is bounded.
func (h *Handlers) ListUsers(ctx context.Context, req *connect.Request[pmv1.ListUsersRequest]) (*connect.Response[pmv1.ListUsersResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermListUsers, ""); err != nil {
		return nil, err
	}

	scopeGroups, restricted := auth.UserScopeListFilter(ctx, PermListUsers)
	limit := pageLimit(req.Msg.PageSize)
	rows, err := h.store.ListUsers(ctx, req.Msg.PageToken, limit)
	if err != nil {
		return nil, internalError(ctx, "failed to list users")
	}

	resp := &pmv1.ListUsersResponse{}
	for _, row := range rows {
		if restricted {
			visible, err := h.userInGroups(ctx, row.ID, scopeGroups)
			if err != nil {
				return nil, internalError(ctx, "failed to resolve user scope")
			}
			if !visible {
				continue
			}
		}
		resp.Users = append(resp.Users, userToProto(userView{Row: row}))
	}
	if len(rows) == int(limit) {
		resp.NextPageToken = rows[len(rows)-1].ID
	}
	total, err := h.store.CountUsers(ctx)
	if err != nil {
		return nil, internalError(ctx, "failed to count users")
	}
	// A confined caller is told how many rows THEY can see, not how
	// many exist: a fleet-wide total is itself information about rows
	// outside their scope.
	if restricted {
		resp.TotalCount = int32(len(resp.Users))
	} else {
		resp.TotalCount = int32(total)
	}
	return connect.NewResponse(resp), nil
}

func (h *Handlers) userInGroups(ctx context.Context, userID string, groups []string) (bool, error) {
	if len(groups) == 0 {
		return false, nil
	}
	member, err := h.store.ListUserGroupIDsForUser(ctx, userID)
	if err != nil {
		return false, err
	}
	want := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		want[g] = struct{}{}
	}
	for _, g := range member {
		if _, ok := want[g]; ok {
			return true, nil
		}
	}
	return false, nil
}

// EraseJITUser removes a subject created by optional OIDC JIT. SCIM-created
// subjects fail closed because their lifecycle remains owned by SCIM.
func (h *Handlers) EraseJITUser(ctx context.Context, req *connect.Request[pmv1.EraseJITUserRequest]) (*connect.Response[pmv1.EraseJITUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	before, err := h.resolveUserTarget(ctx, PermEraseJITUser, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	if before.ProvisioningSource != store.UserProvisioningSourceOIDCJIT {
		return nil, rpcError(ctx, ErrSCIMManagedResource, connect.CodeFailedPrecondition,
			"SCIM-created users are erased through SCIM")
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}

	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermEraseJITUser),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			return store.EraseUser(ctx, tx, rec, before)
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		h.logger.Error("failed to erase JIT user", "error", err, "user_id", before.ID)
		return nil, internalError(ctx, "failed to erase user")
	}
	return connect.NewResponse(&pmv1.EraseJITUserResponse{}), nil
}

// UpdateUserEmail changes a subject's address.
//
// The old and new addresses are the evidence, and an address is
// personal data, so both go into the audit record as class-three detail
// sealed under the subject's own key: erasing the subject destroys the
// key and with it the readable form, while the attribution survives.
func (h *Handlers) UpdateUserEmail(ctx context.Context, req *connect.Request[pmv1.UpdateUserEmailRequest]) (*connect.Response[pmv1.UpdateUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	before, err := h.resolveUserTarget(ctx, PermUpdateUserEmail, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}

	email := normalizeEmail(req.Msg.Email)
	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermUpdateUserEmail),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			n, err := tx.UpdateUserEmail(ctx, db.UpdateUserEmailParams{ID: before.ID, Email: email, UpdatedAt: &at})
			if err != nil {
				return err
			}
			if n == 0 {
				return store.ErrNotFound
			}
			sealed, err := h.sealSubjectTransition(ctx, tx, before.ID, "email", before.Email, email)
			if err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType:        "user",
				ResourceID:          before.ID,
				Action:              "UPDATE_EMAIL",
				Outcome:             store.EffectApplied,
				ChangedFields:       []string{"email"},
				EvidenceKind:        "email_sha256",
				EvidenceFingerprint: fingerprint(email),
				SealedDetail:        sealed,
				SealedDetailSubject: before.ID,
			})
			return nil
		})
	if err != nil {
		if store.IsConflict(err) {
			return nil, rpcError(ctx, ErrEmailAlreadyExists, connect.CodeAlreadyExists, "a user with that email already exists")
		}
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to update email")
	}
	return h.updatedUserResponse(ctx, before.ID)
}

// SetUserDisabled retires or restores a subject's ability to hold a
// session. The statement bumps session_version, so every token already
// issued to them stops validating at the next refresh.
func (h *Handlers) SetUserDisabled(ctx context.Context, req *connect.Request[pmv1.SetUserDisabledRequest]) (*connect.Response[pmv1.UpdateUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	// SetUserDisabled is privilege-granting (re-enabling restores every
	// authority the subject held), so it is global-only: no scope tier
	// and no self tier.
	if err := h.authorize(ctx, PermSetUserDisabled, ""); err != nil {
		return nil, err
	}
	before, err := h.store.GetUser(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to load user")
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermSetUserDisabled),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if err := tx.LockLastAdminGuard(ctx); err != nil {
				return err
			}
			current, err := tx.GetUser(ctx, before.ID)
			if err != nil {
				return err
			}
			if req.Msg.Disabled && !current.Disabled {
				admin, err := tx.UserHoldsUnscopedAdmin(ctx, before.ID)
				if err != nil {
					return err
				}
				if admin {
					remains, err := tx.EnabledAdminExistsExcludingUser(ctx, before.ID)
					if err != nil {
						return err
					}
					if !remains {
						return errLastAdmin
					}
				}
			}
			n, err := tx.SetUserDisabled(ctx, db.SetUserDisabledParams{
				ID: before.ID, Disabled: req.Msg.Disabled, UpdatedAt: &at,
			})
			if err != nil {
				return err
			}
			outcome := store.EffectApplied
			if n == 0 {
				// The statement is conditional on the flag actually
				// changing, so no row means it already held that value.
				outcome = store.EffectRejected
			}
			wasDisabled := current.Disabled
			rec.Effect(store.AuditEffect{
				ResourceType:  "user",
				ResourceID:    before.ID,
				Action:        "SET_DISABLED",
				Outcome:       outcome,
				ChangedFields: []string{"disabled", "session_version"},
				BeforeFlag:    &wasDisabled,
				AfterFlag:     &req.Msg.Disabled,
			})
			return nil
		})
	if err != nil {
		if errors.Is(err, errLastAdmin) {
			return nil, rpcError(ctx, ErrCannotRemoveLastAdmin, connect.CodeFailedPrecondition, "cannot remove the last enabled administrator")
		}
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to update user")
	}
	return h.updatedUserResponse(ctx, before.ID)
}

// UpdateUserProfile writes the OIDC profile fields.
func (h *Handlers) UpdateUserProfile(ctx context.Context, req *connect.Request[pmv1.UpdateUserProfileRequest]) (*connect.Response[pmv1.UpdateUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	before, err := h.resolveUserTarget(ctx, PermUpdateUserProfile, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermUpdateUserProfile),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.UpdateUserProfile(ctx, db.UpdateUserProfileParams{
				ID:                before.ID,
				DisplayName:       req.Msg.DisplayName,
				GivenName:         req.Msg.GivenName,
				FamilyName:        req.Msg.FamilyName,
				PreferredUsername: req.Msg.PreferredUsername,
				Picture:           req.Msg.Picture,
				Locale:            req.Msg.Locale,
				UpdatedAt:         &at,
			}); err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType:  "user",
				ResourceID:    before.ID,
				Action:        "UPDATE_PROFILE",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"display_name", "given_name", "family_name", "preferred_username", "picture", "locale"},
			})
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to update profile")
	}
	return h.updatedUserResponse(ctx, before.ID)
}

// UpdateUserLinuxUsername changes the account name provisioned on
// managed devices.
//
// There is deliberately no self tier: the name keys sudo policy and
// terminal accounts on every device the subject can reach, so letting a
// subject choose their own would let them collide with an existing
// privileged account.
func (h *Handlers) UpdateUserLinuxUsername(ctx context.Context, req *connect.Request[pmv1.UpdateUserLinuxUsernameRequest]) (*connect.Response[pmv1.UpdateUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if !auth.HasPermission(ctx, PermUpdateUserLinuxUsername) {
		return nil, rpcError(ctx, ErrPermissionDenied, connect.CodePermissionDenied, "permission denied")
	}
	before, err := h.resolveUserTarget(ctx, PermUpdateUserLinuxUsername, req.Msg.UserId)
	if err != nil {
		return nil, err
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermUpdateUserLinuxUsername),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.UpdateUserLinuxUsername(ctx, db.UpdateUserLinuxUsernameParams{
				ID:            before.ID,
				LinuxUsername: req.Msg.LinuxUsername,
				UpdatedAt:     &at,
			}); err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType:        "user",
				ResourceID:          before.ID,
				Action:              "UPDATE_LINUX_USERNAME",
				Outcome:             store.EffectApplied,
				ChangedFields:       []string{"linux_username"},
				EvidenceKind:        "linux_username_sha256",
				EvidenceFingerprint: fingerprint(req.Msg.LinuxUsername),
			})
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to update linux username")
	}
	return h.updatedUserResponse(ctx, before.ID)
}

// UpdateUserSshSettings writes a subject's SSH access flags.
func (h *Handlers) UpdateUserSshSettings(ctx context.Context, req *connect.Request[pmv1.UpdateUserSshSettingsRequest]) (*connect.Response[pmv1.UpdateUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	before, err := h.resolveUserTarget(ctx, PermUpdateUserSshSettings, req.Msg.UserId)
	if err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermUpdateUserSshSettings),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.UpdateUserSshSettings(ctx, db.UpdateUserSshSettingsParams{
				ID:               before.ID,
				SshAccessEnabled: req.Msg.SshAccessEnabled,
				SshAllowPubkey:   req.Msg.SshAllowPubkey,
				SshAllowPassword: req.Msg.SshAllowPassword,
				UpdatedAt:        &at,
			}); err != nil {
				return err
			}
			wasEnabled := before.SshAccessEnabled
			rec.Effect(store.AuditEffect{
				ResourceType:  "user",
				ResourceID:    before.ID,
				Action:        "UPDATE_SSH_SETTINGS",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"ssh_access_enabled", "ssh_allow_pubkey", "ssh_allow_password"},
				BeforeFlag:    &wasEnabled,
				AfterFlag:     &req.Msg.SshAccessEnabled,
			})
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to update ssh settings")
	}
	return h.updatedUserResponse(ctx, before.ID)
}

// SetUserProvisioningEnabled toggles whether the subject's OS account
// is provisioned on managed devices.
func (h *Handlers) SetUserProvisioningEnabled(ctx context.Context, req *connect.Request[pmv1.SetUserProvisioningEnabledRequest]) (*connect.Response[pmv1.UpdateUserResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	before, err := h.resolveUserTarget(ctx, PermSetUserProvisioningEnabled, req.Msg.UserId)
	if err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}

	at := h.now().UTC()
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermSetUserProvisioningEnabled),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if _, err := tx.SetUserProvisioningEnabled(ctx, db.SetUserProvisioningEnabledParams{
				ID:                      before.ID,
				UserProvisioningEnabled: req.Msg.Enabled,
				UpdatedAt:               &at,
			}); err != nil {
				return err
			}
			wasEnabled := before.UserProvisioningEnabled
			rec.Effect(store.AuditEffect{
				ResourceType:  "user",
				ResourceID:    before.ID,
				Action:        "SET_PROVISIONING",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"user_provisioning_enabled"},
				BeforeFlag:    &wasEnabled,
				AfterFlag:     &req.Msg.Enabled,
			})
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "user not found")
		}
		return nil, internalError(ctx, "failed to update provisioning")
	}
	return h.updatedUserResponse(ctx, before.ID)
}

// AddUserSshKey authorizes an SSH public key for a subject.
//
// The key is parsed before it is stored: an unparsable value would be
// written to every managed device's authorized_keys and silently do
// nothing, and the fingerprint the audit record needs comes from the
// parse.
func (h *Handlers) AddUserSshKey(ctx context.Context, req *connect.Request[pmv1.AddUserSshKeyRequest]) (*connect.Response[pmv1.AddUserSshKeyResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	before, err := h.resolveUserTarget(ctx, PermAddUserSshKey, req.Msg.UserId)
	if err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}

	parsed, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(req.Msg.PublicKey))
	if parseErr != nil {
		return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "public_key is not a valid SSH authorized key")
	}
	keyFingerprint := ssh.FingerprintSHA256(parsed)

	keyID := ulid.Make().String()
	at := h.now().UTC()
	var stored store.UserSSHKeyRow
	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermAddUserSshKey),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			pub := req.Msg.PublicKey
			comment := req.Msg.Comment
			var err error
			stored, err = tx.InsertUserSshKey(ctx, db.InsertUserSshKeyParams{
				UserID:    before.ID,
				KeyID:     keyID,
				PublicKey: &pub,
				Comment:   &comment,
				AddedAt:   at,
			})
			if err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "user_ssh_key",
				ResourceID:   keyID,
				Action:       "ADD",
				Outcome:      store.EffectApplied,
				AfterRef:     &before.ID,
				// The public key is not a secret, but its digest is the
				// stable, bounded identifier an investigator matches
				// against a device's authorized_keys.
				EvidenceKind:        "ssh_public_key_sha256",
				EvidenceFingerprint: sshFingerprintHex(keyFingerprint),
			})
			return nil
		})
	if err != nil {
		return nil, internalError(ctx, "failed to add ssh key")
	}
	return connect.NewResponse(&pmv1.AddUserSshKeyResponse{Key: sshKeyToProto(stored)}), nil
}

// RemoveUserSshKey withdraws an authorized key.
func (h *Handlers) RemoveUserSshKey(ctx context.Context, req *connect.Request[pmv1.RemoveUserSshKeyRequest]) (*connect.Response[pmv1.RemoveUserSshKeyResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	before, err := h.resolveUserTarget(ctx, PermRemoveUserSshKey, req.Msg.UserId)
	if err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}

	_, err = h.store.WithAudit(ctx, h.mutationOp(req, actor, PermRemoveUserSshKey),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			removed, err := tx.DeleteUserSshKey(ctx, db.DeleteUserSshKeyParams{
				UserID: before.ID, KeyID: req.Msg.KeyId,
			})
			if err != nil {
				return err
			}
			effect := store.AuditEffect{
				ResourceType: "user_ssh_key",
				ResourceID:   removed.KeyID,
				Action:       "REMOVE",
				Outcome:      store.EffectApplied,
				BeforeRef:    &before.ID,
			}
			if removed.PublicKey != nil {
				if parsed, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(*removed.PublicKey)); perr == nil {
					effect.EvidenceKind = "ssh_public_key_sha256"
					effect.EvidenceFingerprint = sshFingerprintHex(ssh.FingerprintSHA256(parsed))
				}
			}
			rec.Effect(effect)
			return nil
		})
	if err != nil {
		if store.IsNotFound(err) {
			return nil, notFound(ctx, ErrUserNotFound, "ssh key not found")
		}
		return nil, internalError(ctx, "failed to remove ssh key")
	}
	return connect.NewResponse(&pmv1.RemoveUserSshKeyResponse{}), nil
}

// updatedUserResponse re-reads the subject after a write so the caller
// sees committed state rather than what the handler believed it wrote.
func (h *Handlers) updatedUserResponse(ctx context.Context, userID string) (*connect.Response[pmv1.UpdateUserResponse], error) {
	view, err := h.loadUserView(ctx, userID)
	if err != nil {
		return nil, internalError(ctx, "failed to load user")
	}
	return connect.NewResponse(&pmv1.UpdateUserResponse{User: userToProto(view)}), nil
}

// sealSubjectTransition seals a before→after pair under the subject's
// own data-encryption key.
//
// The key is read INSIDE the caller's transaction: a subject erased
// concurrently would leave no key, and the seal must fail rather than
// silently fall back to recording the values in a readable form.
func (h *Handlers) sealSubjectTransition(ctx context.Context, tx *store.Tx, subjectID, field, before, after string) ([]byte, error) {
	key, err := tx.GetUserEncryptionKey(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	return h.sealForSubject(subjectID, key.WrappedDek, field, before+" -> "+after)
}

// normalizeEmail lowercases and trims an address so the unique index
// and every later lookup agree on what "the same address" means.
func normalizeEmail(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// fingerprint is the class-two digest form: SHA-256, lowercase hex.
func fingerprint(v string) string {
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// sshFingerprintHex converts x/crypto/ssh's "SHA256:<base64>" form into
// the lowercase hex the audit log accepts. The digest is the same
// bytes; only the presentation differs.
func sshFingerprintHex(sshForm string) string {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sshForm, "SHA256:"))
	if err != nil || len(raw) != sha256.Size {
		return ""
	}
	return hex.EncodeToString(raw)
}
