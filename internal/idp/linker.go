package idp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ErrNoMatchingAccount is what an external identity that cannot be
// resolved to a local account gets. It is deliberately the same answer
// for "no such account", "auto-link refused" and "auto-create
// disabled": the caller is unauthenticated, and distinguishing those
// cases would report whether an address exists locally.
var ErrNoMatchingAccount = errors.New("no matching account found; contact an administrator to link your identity")

// SystemActorSSO is the actor the linker attributes its writes to when
// it provisions on an unauthenticated caller's behalf.
const SystemActorSSO = "sso"

// LinkResult is the outcome of resolving an external identity.
type LinkResult struct {
	UserID string
	// IsNew reports that the subject was provisioned by this call.
	IsNew bool
}

// Linker resolves an external identity to a local subject, creating the
// binding — and, when the provider is configured for it, the subject —
// as it goes.
//
// Every write happens on the transaction handle the caller passes in,
// and every write records its effect on the caller's audit recorder. A
// login that provisions a user and a login that merely refreshes a
// timestamp therefore both commit atomically with their evidence.
type Linker struct {
	kek *crypto.Encryptor
	now func() time.Time
}

// NewLinker creates a linker. The KEK is required: provisioning a
// subject means minting its data-encryption key, and a subject without
// one has no place to put class-three audit detail.
func NewLinker(kek *crypto.Encryptor, now func() time.Time) *Linker {
	if now == nil {
		now = time.Now
	}
	return &Linker{kek: kek, now: now}
}

// LinkOrCreate resolves claims against provider, in this order:
//
//  1. an existing binding for (provider, external subject) — refresh
//     its login timestamp and return the subject it names;
//  2. auto-link by email, when the provider is configured for it and
//     the takeover guard below allows it;
//  3. auto-create, when the provider is configured for it.
//
// Anything else is ErrNoMatchingAccount.
func (l *Linker) LinkOrCreate(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	provider store.IdentityProviderRow,
	claims *UserClaims,
) (*LinkResult, error) {
	at := l.now().UTC()

	// Normalize the asserted email once. A blank or whitespace-only claim folds
	// to "" and is then treated as no email by both the auto-link and JIT
	// branches below: an existing (provider, subject) binding still resolves
	// without one, but a subject is never provisioned or looked up on an empty
	// address.
	email := normalizeEmail(claims.Email)

	link, err := tx.GetIdentityLinkByProviderAndExternalID(ctx, db.GetIdentityLinkByProviderAndExternalIDParams{
		ProviderID: provider.ID,
		ExternalID: claims.Subject,
	})
	switch {
	case err == nil:
		// A binding exists. It may still name a subject that has since
		// been erased, in which case the binding is stale and is
		// cleared so the flow can fall through to link or create.
		_, userErr := tx.GetUser(ctx, link.UserID)
		if userErr == nil {
			updated, err := tx.TouchIdentityLinkLogin(ctx, db.TouchIdentityLinkLoginParams{
				ID:            link.ID,
				LastLoginAt:   &at,
				ExternalEmail: claims.Email,
				ExternalName:  claims.Name,
			})
			if err != nil {
				return nil, fmt.Errorf("refresh identity link: %w", err)
			}
			rec.Effect(store.AuditEffect{
				ResourceType:  "identity_link",
				ResourceID:    updated.ID,
				Action:        "LOGIN",
				Outcome:       store.EffectApplied,
				ChangedFields: []string{"last_login_at"},
				AfterRef:      &updated.UserID,
			})
			return &LinkResult{UserID: link.UserID}, nil
		}
		if !store.IsNotFound(userErr) {
			return nil, fmt.Errorf("resolve linked subject: %w", userErr)
		}
		removed, err := tx.DeleteIdentityLink(ctx, link.ID)
		if err != nil && !store.IsNotFound(err) {
			return nil, fmt.Errorf("clear stale identity link: %w", err)
		}
		if err == nil {
			rec.Effect(store.AuditEffect{
				ResourceType: "identity_link",
				ResourceID:   removed.ID,
				Action:       "UNLINK_STALE",
				Outcome:      store.EffectApplied,
				BeforeRef:    &removed.UserID,
			})
		}
	case store.IsNotFound(err):
		// No binding yet; fall through.
	default:
		return nil, fmt.Errorf("look up identity link: %w", err)
	}

	if provider.AutoLinkByEmail && email != "" {
		user, err := tx.GetUserByEmail(ctx, email)
		switch {
		case err == nil:
			// Cross-provider takeover guard. An account that is ALREADY
			// bound to some identity provider must not be silently
			// re-bound because a second provider asserts the same
			// address: the asserting provider is the very party the
			// guard defends against, so its own email_verified claim is
			// not a backstop. An account with no binding yet is the
			// ordinary invite flow and links freely.
			linked, err := tx.CountIdentityLinksForUser(ctx, user.ID)
			if err != nil {
				return nil, fmt.Errorf("count existing identity links: %w", err)
			}
			if linked > 0 && !provider.TrustEmailAssertions {
				slog.Warn("SSO: refusing to auto-link an already-bound account by asserted email",
					"provider_id", provider.ID, "provider_slug", provider.Slug)
				return nil, ErrNoMatchingAccount
			}
			if err := l.createLink(ctx, tx, rec, provider, user.ID, claims, at); err != nil {
				return nil, err
			}
			slog.Info("SSO: linked an external identity to an existing subject by asserted email",
				"provider_id", provider.ID, "provider_slug", provider.Slug)
			return &LinkResult{UserID: user.ID}, nil
		case store.IsNotFound(err):
			// Fall through to auto-create.
		default:
			return nil, fmt.Errorf("look up subject by email: %w", err)
		}
	}

	if provider.AutoCreateUsers && email != "" {
		userID, err := l.createUser(ctx, tx, rec, provider, claims, email, at)
		if err != nil {
			return nil, err
		}
		if err := l.createLink(ctx, tx, rec, provider, userID, claims, at); err != nil {
			return nil, err
		}
		return &LinkResult{UserID: userID, IsNew: true}, nil
	}

	// Name the gate that stopped the login: a disabled flag and a missing
	// trusted email are different deployment mistakes with different fixes,
	// and the operator reading this log cannot see which operand was false.
	// The wrapped sentinel keeps the client-visible answer opaque.
	reason := "auto_create_users is disabled on the provider"
	if provider.AutoCreateUsers {
		reason = "the identity carried no trusted email claim (missing or not email_verified)"
	}
	slog.Warn("SSO: no local account matched an external identity",
		"provider_id", provider.ID, "provider_slug", provider.Slug, "reason", reason)
	return nil, fmt.Errorf("%w: %s", ErrNoMatchingAccount, reason)
}

// createUser provisions a subject for an external identity.
//
// The subject's data-encryption key is minted FIRST: it is what makes
// class-three audit detail about the subject erasable, so a subject
// that exists without one would produce evidence that erasure cannot
// reach.
func (l *Linker) createUser(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	provider store.IdentityProviderRow,
	claims *UserClaims,
	email string,
	at time.Time,
) (string, error) {
	userID := ulid.Make().String()

	wrapped, err := crypto.GenerateWrappedDEK(l.kek, userID)
	if err != nil {
		return "", fmt.Errorf("mint subject encryption key: %w", err)
	}
	if _, err := tx.InsertUserEncryptionKey(ctx, db.InsertUserEncryptionKeyParams{
		UserID:     userID,
		WrappedDek: wrapped,
	}); err != nil {
		return "", fmt.Errorf("store subject encryption key: %w", err)
	}

	linuxUID, err := tx.GetNextLinuxUID(ctx)
	if err != nil {
		return "", fmt.Errorf("assign linux uid: %w", err)
	}
	if linuxUID > 2147483647 {
		return "", errors.New("assign linux uid: int32 range exhausted")
	}
	linuxUsername := DeriveLinuxUsername(email, claims.PreferredUsername)
	if linuxUsername == "" {
		linuxUsername = "user_" + strings.ToLower(userID[:8])
	}

	if _, err := tx.InsertUser(ctx, db.InsertUserParams{
		ID:                 userID,
		Email:              email,
		DisplayName:        claims.Name,
		GivenName:          claims.GivenName,
		FamilyName:         claims.FamilyName,
		PreferredUsername:  claims.PreferredUsername,
		LinuxUsername:      linuxUsername,
		LinuxUid:           int32(linuxUID),
		ProvisioningSource: store.UserProvisioningSourceOIDCJIT,
		CreatedAt:          &at,
	}); err != nil {
		return "", fmt.Errorf("create subject: %w", err)
	}
	rec.Effect(store.AuditEffect{
		ResourceType:        "user",
		ResourceID:          userID,
		Action:              "PROVISION",
		Outcome:             store.EffectApplied,
		ChangedFields:       []string{"email", "linux_username", "linux_uid"},
		AfterRef:            &provider.ID,
		EvidenceKind:        "email_sha256",
		EvidenceFingerprint: fingerprint(claims.Email),
	})

	if provider.DefaultRoleID != "" {
		grantID := ulid.Make().String()
		if _, err := tx.InsertUserRoleGrant(ctx, db.InsertUserRoleGrantParams{
			GrantID:    grantID,
			UserID:     userID,
			RoleID:     provider.DefaultRoleID,
			AssignedAt: at,
			AssignedBy: SystemActorSSO,
		}); err != nil {
			return "", fmt.Errorf("assign provider default role: %w", err)
		}
		rec.Effect(store.AuditEffect{
			ResourceType: "user_role",
			ResourceID:   grantID,
			Action:       "GRANT",
			Outcome:      store.EffectApplied,
			BeforeRef:    &userID,
			AfterRef:     &provider.DefaultRoleID,
		})
	}

	settings, err := tx.GetServerSettings(ctx)
	if err != nil {
		return "", fmt.Errorf("read server settings: %w", err)
	}
	if settings.UserProvisioningEnabled {
		if _, err := tx.SetUserProvisioningEnabled(ctx, db.SetUserProvisioningEnabledParams{
			ID:                      userID,
			UserProvisioningEnabled: true,
			UpdatedAt:               &at,
		}); err != nil {
			return "", fmt.Errorf("apply provisioning default: %w", err)
		}
		yes := true
		rec.Effect(store.AuditEffect{
			ResourceType:  "user",
			ResourceID:    userID,
			Action:        "SET_PROVISIONING",
			Outcome:       store.EffectApplied,
			ChangedFields: []string{"user_provisioning_enabled"},
			AfterFlag:     &yes,
		})
	}
	if settings.SshAccessForAll {
		if _, err := tx.UpdateUserSshSettings(ctx, db.UpdateUserSshSettingsParams{
			ID:               userID,
			SshAccessEnabled: true,
			SshAllowPubkey:   true,
			SshAllowPassword: false,
			UpdatedAt:        &at,
		}); err != nil {
			return "", fmt.Errorf("apply ssh default: %w", err)
		}
		yes := true
		rec.Effect(store.AuditEffect{
			ResourceType:  "user",
			ResourceID:    userID,
			Action:        "SET_SSH_SETTINGS",
			Outcome:       store.EffectApplied,
			ChangedFields: []string{"ssh_access_enabled", "ssh_allow_pubkey", "ssh_allow_password"},
			AfterFlag:     &yes,
		})
	}

	return userID, nil
}

func (l *Linker) createLink(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	provider store.IdentityProviderRow,
	userID string,
	claims *UserClaims,
	at time.Time,
) error {
	linkID := ulid.Make().String()
	if _, err := tx.InsertIdentityLink(ctx, db.InsertIdentityLinkParams{
		ID:            linkID,
		UserID:        userID,
		ProviderID:    provider.ID,
		ExternalID:    claims.Subject,
		ExternalEmail: claims.Email,
		ExternalName:  claims.Name,
		LinkedAt:      at,
	}); err != nil {
		return fmt.Errorf("create identity link: %w", err)
	}
	rec.Effect(store.AuditEffect{
		ResourceType:        "identity_link",
		ResourceID:          linkID,
		Action:              "LINK",
		Outcome:             store.EffectApplied,
		BeforeRef:           &provider.ID,
		AfterRef:            &userID,
		EvidenceKind:        "external_subject_sha256",
		EvidenceFingerprint: fingerprint(claims.Subject),
	})
	return nil
}

// SyncGroupMemberships reconciles a subject's membership of the mapped
// groups against the provider's group claim.
//
// Only groups the operator has explicitly mapped are touched: a group
// the mapping does not name is never joined or left because of a claim.
// Group membership confers the group's role grants, so each change is
// recorded as its own effect.
func (l *Linker) SyncGroupMemberships(
	ctx context.Context,
	tx *store.Tx,
	rec *store.AuditRecorder,
	userID string,
	externalGroups []string,
	groupMapping map[string]string,
) error {
	if len(groupMapping) == 0 {
		return nil
	}
	at := l.now().UTC()

	desired := make(map[string]bool, len(externalGroups))
	for _, ext := range externalGroups {
		if internalID, ok := groupMapping[ext]; ok {
			desired[internalID] = true
		}
	}

	// Iterate the mapping's distinct targets in a stable order so two
	// runs against the same claim produce the same effect sequence.
	targets := make([]string, 0, len(groupMapping))
	seen := make(map[string]bool, len(groupMapping))
	for _, groupID := range groupMapping {
		if groupID == "" || seen[groupID] {
			continue
		}
		seen[groupID] = true
		targets = append(targets, groupID)
	}
	slices.Sort(targets)

	for _, groupID := range targets {
		if desired[groupID] {
			n, err := tx.InsertUserGroupMember(ctx, db.InsertUserGroupMemberParams{
				GroupID: groupID,
				UserID:  userID,
				AddedAt: at,
				AddedBy: SystemActorSSO,
			})
			if err != nil {
				return fmt.Errorf("add subject to mapped group: %w", err)
			}
			if n == 0 {
				continue // already a member; nothing changed
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "user_group_member",
				ResourceID:   groupID,
				Action:       "JOIN",
				Outcome:      store.EffectApplied,
				AfterRef:     &userID,
			})
			rec.RefreshSearch("user_group", groupID)
			rec.RefreshSearch("user", userID)
			continue
		}
		n, err := tx.DeleteUserGroupMember(ctx, db.DeleteUserGroupMemberParams{
			GroupID: groupID,
			UserID:  userID,
		})
		if err != nil {
			return fmt.Errorf("remove subject from mapped group: %w", err)
		}
		if n == 0 {
			continue
		}
		rec.Effect(store.AuditEffect{
			ResourceType: "user_group_member",
			ResourceID:   groupID,
			Action:       "LEAVE",
			Outcome:      store.EffectApplied,
			BeforeRef:    &userID,
		})
		rec.RefreshSearch("user_group", groupID)
		rec.RefreshSearch("user", userID)
	}
	return nil
}

// ParseGroupMapping decodes the provider's stored group mapping.
func ParseGroupMapping(data []byte) map[string]string {
	if len(data) == 0 {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

// normalizeEmail folds an email to the canonical form the SCIM and
// manual lookup paths store and query by. The active-unique email index
// is COLLATE NOCASE, so a JIT write that skipped this would be unfindable
// by a normalized lookup yet still block re-insert. Semantics match the
// scim and identity packages' own normalizeEmail exactly.
func normalizeEmail(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// fingerprint reduces a value to its SHA-256 hex digest, which is what
// the audit log accepts as class-two evidence. The value itself never
// reaches an audit row.
func fingerprint(v string) string {
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

var linuxUsernameSanitizeRe = regexp.MustCompile(`[^a-z0-9_.\-]`)

// DeriveLinuxUsername derives a Linux account name from the preferred
// username, falling back to the local part of the email.
func DeriveLinuxUsername(email, preferredUsername string) string {
	var username string
	switch {
	case preferredUsername != "":
		username = preferredUsername
	case strings.Contains(email, "@"):
		username = email[:strings.Index(email, "@")]
	default:
		username = email
	}
	username = strings.ToLower(username)
	username = linuxUsernameSanitizeRe.ReplaceAllString(username, "_")
	if len(username) > 32 {
		username = username[:32]
	}
	return username
}
