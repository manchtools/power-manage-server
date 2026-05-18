package idp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// ErrNoMatchingAccount is returned when no local account could be found or created for the external identity.
var ErrNoMatchingAccount = errors.New("no matching account found; contact an administrator to link your identity")

// LinkResult represents the outcome of an identity linking attempt.
type LinkResult struct {
	UserID string
	IsNew  bool // true if the user was auto-created
}

// Linker handles the logic of linking external identities to local users.
type Linker struct {
	queries  Querier
	appender EventAppender
}

// Querier is the interface for database queries needed by the linker.
type Querier interface {
	GetIdentityLinkByProviderAndExternalID(ctx context.Context, arg db.GetIdentityLinkByProviderAndExternalIDParams) (db.IdentityLinksProjection, error)
	GetUserByEmail(ctx context.Context, email string) (db.UsersProjection, error)
	GetUserByID(ctx context.Context, id string) (db.UsersProjection, error)
	GetServerSettings(ctx context.Context) (db.ServerSettingsProjection, error)
	GetNextLinuxUID(ctx context.Context) (int32, error)
}

// EventAppender is the interface for appending events.
type EventAppender interface {
	AppendEvent(ctx context.Context, event EventInput) error
}

// EventInput is a simplified event structure for the linker. Data is
// typed as `any` so callers can pass either a typed payload struct
// (preferred — see internal/eventtypes/payloads) or the legacy
// map[string]any literal during transitional emit-site migrations.
type EventInput struct {
	StreamType string
	StreamID   string
	EventType  string
	Data       any
	ActorType  string
	ActorID    string
}

// NewLinker creates a new identity linker.
func NewLinker(queries Querier, appender EventAppender) *Linker {
	return &Linker{
		queries:  queries,
		appender: appender,
	}
}

// LinkOrCreate attempts to link an external identity to a local user.
// It follows this algorithm:
// 1. Look up by (provider_id, external_id) → found: update last_login, return linked user
// 2. If auto_link_by_email: find user by email → create link, return user
// 3. If auto_create_users: create user (no password), assign default role, create link
// 4. Otherwise: error
func (l *Linker) LinkOrCreate(ctx context.Context, provider store.IdentityProvider, claims *UserClaims) (*LinkResult, error) {
	slog.Debug("SSO linker: starting LinkOrCreate",
		"provider_id", provider.ID,
		"provider_slug", provider.Slug,
		"subject", claims.Subject,
		"email", claims.Email,
		"auto_link_by_email", provider.AutoLinkByEmail,
		"auto_create_users", provider.AutoCreateUsers,
	)

	// Step 1: Check for existing link
	link, err := l.queries.GetIdentityLinkByProviderAndExternalID(ctx, db.GetIdentityLinkByProviderAndExternalIDParams{
		ProviderID: provider.ID,
		ExternalID: claims.Subject,
	})
	if err == nil {
		slog.Debug("SSO linker: found existing identity link",
			"link_id", link.ID,
			"user_id", link.UserID,
			"external_id", link.ExternalID,
		)

		// Verify the linked user still exists (not soft-deleted)
		_, userErr := l.queries.GetUserByID(ctx, link.UserID)
		if store.IsNotFound(userErr) {
			// User is soft-deleted — clean up the stale identity link and fall through
			slog.Warn("SSO linker: linked user is deleted, cleaning up stale identity link",
				"link_id", link.ID,
				"user_id", link.UserID,
			)
			if err := l.appender.AppendEvent(ctx, EventInput{
				StreamType: "identity_provider",
				StreamID:   link.ID,
				EventType:  string(eventtypes.IdentityUnlinked),
				Data:       map[string]any{},
				ActorType:  "system",
				ActorID:    "sso",
			}); err != nil {
				slog.Warn("failed to append IdentityUnlinked event", "link_id", link.ID, "error", err)
			}
			// Fall through to Step 2/3
		} else if userErr != nil {
			return nil, fmt.Errorf("verify linked user: %w", userErr)
		} else {
			// User exists — update last login and return
			err = l.appender.AppendEvent(ctx, EventInput{
				StreamType: "identity_provider",
				StreamID:   link.ID,
				EventType:  string(eventtypes.IdentityLinkLoginUpdated),
				Data: payloads.IdentityLinkLoginUpdated{
					ProviderID:    provider.ID,
					ExternalID:    claims.Subject,
					ExternalEmail: claims.Email,
					ExternalName:  claims.Name,
				},
				ActorType: "system",
				ActorID:   "sso",
			})
			if err != nil {
				return nil, fmt.Errorf("update identity link login: %w", err)
			}
			return &LinkResult{UserID: link.UserID, IsNew: false}, nil
		}
	}
	if !store.IsNotFound(err) {
		return nil, fmt.Errorf("lookup identity link: %w", err)
	}
	slog.Debug("SSO linker: no existing identity link found", "provider_id", provider.ID, "subject", claims.Subject)

	// Step 2: Auto-link by email
	if provider.AutoLinkByEmail && claims.Email != "" {
		slog.Debug("SSO linker: trying auto-link by email", "email", claims.Email)
		user, err := l.queries.GetUserByEmail(ctx, claims.Email)
		if err == nil {
			// Info-level log on the actual link (audit F-28) — this
			// is a trust-boundary event: the IdP's email-verification
			// posture is what gates account hijack via this path, and
			// an operator looking at boot logs after enabling
			// auto-link-by-email must be able to see who gets linked.
			slog.Info("SSO linker: auto-linked SSO identity to existing local user by email",
				"user_id", user.ID,
				"user_email", user.Email,
				"provider_id", provider.ID,
				"provider_slug", provider.Slug,
				"external_subject", claims.Subject,
			)
			// Found user by email — create link
			linkID := newULID()
			err = l.appender.AppendEvent(ctx, EventInput{
				StreamType: "identity_provider",
				StreamID:   linkID,
				EventType:  string(eventtypes.IdentityLinked),
				Data: payloads.IdentityLinked{
					UserID:        user.ID,
					ProviderID:    provider.ID,
					ExternalID:    claims.Subject,
					ExternalEmail: claims.Email,
					ExternalName:  claims.Name,
				},
				ActorType: "system",
				ActorID:   "sso",
			})
			if err != nil {
				return nil, fmt.Errorf("create identity link: %w", err)
			}
			return &LinkResult{UserID: user.ID, IsNew: false}, nil
		}
		if !store.IsNotFound(err) {
			return nil, fmt.Errorf("lookup user by email: %w", err)
		}
		slog.Debug("SSO linker: no user found by email", "email", claims.Email)
	} else if !provider.AutoLinkByEmail {
		slog.Debug("SSO linker: auto_link_by_email is disabled, skipping email lookup")
	} else if claims.Email == "" {
		slog.Debug("SSO linker: email claim is empty, skipping email lookup")
	}

	// Step 3: Auto-create user
	if provider.AutoCreateUsers && claims.Email != "" {
		slog.Debug("SSO linker: auto-creating new user", "email", claims.Email)
		userID := newULID()

		linuxUID, err := l.queries.GetNextLinuxUID(ctx)
		if err != nil {
			return nil, fmt.Errorf("assign linux uid: %w", err)
		}
		linuxUsername := deriveLinuxUsernameFromEmail(claims.Email, claims.PreferredUsername)
		if linuxUsername == "" {
			linuxUsername = "user_" + userID[:8]
		}

		// Resolve the role ID set BEFORE emitting the event so the
		// user INSERT and the per-role INSERT land atomically inside
		// the projector's WithTx (issue #135). SSO only ever assigns
		// the provider's configured default role on auto-create; if
		// no default is configured the slice stays empty and the
		// projector skips the per-role INSERT loop.
		var roleIDs []string
		if provider.DefaultRoleID != "" {
			roleIDs = []string{provider.DefaultRoleID}
		}

		// Create user without password (compound event lands the
		// user row AND its role assignments in one tx).
		role := "user"
		err = l.appender.AppendEvent(ctx, EventInput{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserCreatedWithRoles),
			Data: payloads.UserCreatedWithRoles{
				Email:             ptrStr(claims.Email),
				Role:              &role,
				DisplayName:       ptrStr(claims.Name),
				GivenName:         ptrStr(claims.GivenName),
				FamilyName:        ptrStr(claims.FamilyName),
				PreferredUsername: ptrStr(claims.PreferredUsername),
				Picture:           ptrStr(claims.Picture),
				Locale:            ptrStr(claims.Locale),
				LinuxUsername:     ptrStr(linuxUsername),
				LinuxUID:          &linuxUID,
				RoleIDs:           roleIDs,
			},
			ActorType: "system",
			ActorID:   "sso",
		})
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}

		// Auto-enable provisioning/SSH if global server settings are on
		if settings, err := l.queries.GetServerSettings(ctx); err == nil {
			if settings.UserProvisioningEnabled {
				enabled := true
				if err := l.appender.AppendEvent(ctx, EventInput{
					StreamType: "user",
					StreamID:   userID,
					EventType:  string(eventtypes.UserProvisioningSettingsUpdated),
					Data:       payloads.UserProvisioningSettingsUpdated{UserProvisioningEnabled: &enabled},
					ActorType:  "system",
					ActorID:    "sso",
				}); err != nil {
					slog.Warn("failed to auto-enable provisioning for SSO user", "user_id", userID, "error", err)
				}
			}
			if settings.SshAccessForAll {
				yes := true
				no := false
				if err := l.appender.AppendEvent(ctx, EventInput{
					StreamType: "user",
					StreamID:   userID,
					EventType:  string(eventtypes.UserSshSettingsUpdated),
					Data: payloads.UserSshSettingsUpdated{
						SshAccessEnabled: &yes,
						SshAllowPubkey:   &yes,
						SshAllowPassword: &no,
					},
					ActorType: "system",
					ActorID:   "sso",
				}); err != nil {
					slog.Warn("failed to auto-enable SSH for SSO user", "user_id", userID, "error", err)
				}
			}
		} else {
			slog.Warn("failed to check server settings for SSO user defaults", "error", err)
		}

		// Create identity link
		linkID := newULID()
		err = l.appender.AppendEvent(ctx, EventInput{
			StreamType: "identity_provider",
			StreamID:   linkID,
			EventType:  string(eventtypes.IdentityLinked),
			Data: payloads.IdentityLinked{
				UserID:        userID,
				ProviderID:    provider.ID,
				ExternalID:    claims.Subject,
				ExternalEmail: claims.Email,
				ExternalName:  claims.Name,
			},
			ActorType: "system",
			ActorID:   "sso",
		})
		if err != nil {
			return nil, fmt.Errorf("create identity link: %w", err)
		}

		return &LinkResult{UserID: userID, IsNew: true}, nil
	}

	slog.Warn("SSO linker: no matching account found",
		"provider_id", provider.ID,
		"provider_slug", provider.Slug,
		"subject", claims.Subject,
		"email", claims.Email,
		"auto_link_by_email", provider.AutoLinkByEmail,
		"auto_create_users", provider.AutoCreateUsers,
	)
	return nil, ErrNoMatchingAccount
}

// SyncGroupMemberships synchronizes a user's group memberships based on OIDC group claims.
// It adds the user to mapped groups they belong to and removes them from mapped groups they don't.
func (l *Linker) SyncGroupMemberships(ctx context.Context, userID string, externalGroups []string, groupMapping map[string]string) error {
	if len(groupMapping) == 0 {
		return nil
	}

	// Parse group mapping from JSON bytes
	// groupMapping maps external group names → internal user_group_ids

	// Determine which internal groups the user should be in
	desiredGroups := make(map[string]bool)
	for _, extGroup := range externalGroups {
		if internalGroupID, ok := groupMapping[extGroup]; ok {
			desiredGroups[internalGroupID] = true
		}
	}

	// For each mapped group, add/remove the user
	for _, groupID := range groupMapping {
		if desiredGroups[groupID] {
			// Add user to group (idempotent via ON CONFLICT DO NOTHING in projector)
			if err := l.appender.AppendEvent(ctx, EventInput{
				StreamType: "user_group",
				StreamID:   groupID,
				EventType:  string(eventtypes.UserGroupMemberAdded),
				Data: payloads.UserGroupMemberAdded{
					GroupID: groupID,
					UserID:  userID,
				},
				ActorType: "system",
				ActorID:   "sso",
			}); err != nil {
				slog.Warn("failed to add user to SSO group", "user_id", userID, "group_id", groupID, "error", err)
			}
		} else {
			// Remove user from group
			if err := l.appender.AppendEvent(ctx, EventInput{
				StreamType: "user_group",
				StreamID:   groupID,
				EventType:  string(eventtypes.UserGroupMemberRemoved),
				Data: payloads.UserGroupMemberRemoved{
					GroupID: groupID,
					UserID:  userID,
				},
				ActorType: "system",
				ActorID:   "sso",
			}); err != nil {
				slog.Warn("failed to remove user from SSO group", "user_id", userID, "group_id", groupID, "error", err)
			}
		}
	}

	return nil
}

// ParseGroupMapping parses the JSONB group_mapping from the database into a map.
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

func newULID() string {
	entropy := ulid.Monotonic(rand.Reader, 0)
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}

var linuxUsernameSanitizeRe = regexp.MustCompile(`[^a-z0-9_.\-]`)

// deriveLinuxUsernameFromEmail derives a Linux username from email/preferred_username.
func deriveLinuxUsernameFromEmail(email, preferredUsername string) string {
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

// ptrStr returns a *string for the value. Used by the typed-payload
// emit sites that take pointer fields with omitempty — wrapping the
// claim/computed value here keeps the call site readable.
func ptrStr(s string) *string {
	return &s
}
