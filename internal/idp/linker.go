package idp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"

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
	queries Querier
	appender EventAppender
}

// Querier is the interface for database queries needed by the linker.
type Querier interface {
	GetIdentityLinkByProviderAndExternalID(ctx context.Context, arg db.GetIdentityLinkByProviderAndExternalIDParams) (db.IdentityLinksProjection, error)
	GetUserByEmail(ctx context.Context, email string) (db.UsersProjection, error)
	GetUserByID(ctx context.Context, id string) (db.UsersProjection, error)
	GetServerSettings(ctx context.Context) (db.ServerSettingsProjection, error)
}

// EventAppender is the interface for appending events.
type EventAppender interface {
	AppendEvent(ctx context.Context, event EventInput) error
}

// EventInput is a simplified event structure for the linker.
type EventInput struct {
	StreamType string
	StreamID   string
	EventType  string
	Data       map[string]any
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
func (l *Linker) LinkOrCreate(ctx context.Context, provider db.IdentityProvidersProjection, claims *UserClaims) (*LinkResult, error) {
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
		if errors.Is(userErr, pgx.ErrNoRows) {
			// User is soft-deleted — clean up the stale identity link and fall through
			slog.Warn("SSO linker: linked user is deleted, cleaning up stale identity link",
				"link_id", link.ID,
				"user_id", link.UserID,
			)
			if err := l.appender.AppendEvent(ctx, EventInput{
				StreamType: "identity_provider",
				StreamID:   link.ID,
				EventType:  "IdentityUnlinked",
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
				EventType:  "IdentityLinkLoginUpdated",
				Data: map[string]any{
					"provider_id":    provider.ID,
					"external_id":    claims.Subject,
					"external_email": claims.Email,
					"external_name":  claims.Name,
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
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("lookup identity link: %w", err)
	}
	slog.Debug("SSO linker: no existing identity link found", "provider_id", provider.ID, "subject", claims.Subject)

	// Step 2: Auto-link by email
	if provider.AutoLinkByEmail && claims.Email != "" {
		slog.Debug("SSO linker: trying auto-link by email", "email", claims.Email)
		user, err := l.queries.GetUserByEmail(ctx, claims.Email)
		if err == nil {
			slog.Debug("SSO linker: found user by email, creating link",
				"user_id", user.ID,
				"user_email", user.Email,
			)
			// Found user by email — create link
			linkID := newULID()
			err = l.appender.AppendEvent(ctx, EventInput{
				StreamType: "identity_provider",
				StreamID:   linkID,
				EventType:  "IdentityLinked",
				Data: map[string]any{
					"user_id":        user.ID,
					"provider_id":    provider.ID,
					"external_id":    claims.Subject,
					"external_email": claims.Email,
					"external_name":  claims.Name,
				},
				ActorType: "system",
				ActorID:   "sso",
			})
			if err != nil {
				return nil, fmt.Errorf("create identity link: %w", err)
			}
			return &LinkResult{UserID: user.ID, IsNew: false}, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
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

		// Create user without password
		err = l.appender.AppendEvent(ctx, EventInput{
			StreamType: "user",
			StreamID:   userID,
			EventType:  "UserCreated",
			Data: map[string]any{
				"email":              claims.Email,
				"role":               "user",
				"display_name":       claims.Name,
				"given_name":         claims.GivenName,
				"family_name":        claims.FamilyName,
				"preferred_username": claims.PreferredUsername,
				"picture":            claims.Picture,
				"locale":             claims.Locale,
			},
			ActorType: "system",
			ActorID:   "sso",
		})
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}

		// Assign default role if configured
		if provider.DefaultRoleID != "" {
			if err := l.appender.AppendEvent(ctx, EventInput{
				StreamType: "user_role",
				StreamID:   userID + ":" + provider.DefaultRoleID,
				EventType:  "UserRoleAssigned",
				Data: map[string]any{
					"user_id": userID,
					"role_id": provider.DefaultRoleID,
				},
				ActorType: "system",
				ActorID:   "sso",
			}); err != nil {
				slog.Warn("failed to assign default role to SSO user", "user_id", userID, "role_id", provider.DefaultRoleID, "error", err)
			}
		}

		// Auto-enable provisioning/SSH if global server settings are on
		if settings, err := l.queries.GetServerSettings(ctx); err == nil {
			if settings.UserProvisioningEnabled {
				if err := l.appender.AppendEvent(ctx, EventInput{
					StreamType: "user",
					StreamID:   userID,
					EventType:  "UserProvisioningSettingsUpdated",
					Data:       map[string]any{"user_provisioning_enabled": true},
					ActorType:  "system",
					ActorID:    "sso",
				}); err != nil {
					slog.Warn("failed to auto-enable provisioning for SSO user", "user_id", userID, "error", err)
				}
			}
			if settings.SshAccessForAll {
				if err := l.appender.AppendEvent(ctx, EventInput{
					StreamType: "user",
					StreamID:   userID,
					EventType:  "UserSshSettingsUpdated",
					Data: map[string]any{
						"ssh_access_enabled": true,
						"ssh_allow_pubkey":   true,
						"ssh_allow_password": true,
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
			EventType:  "IdentityLinked",
			Data: map[string]any{
				"user_id":        userID,
				"provider_id":    provider.ID,
				"external_id":    claims.Subject,
				"external_email": claims.Email,
				"external_name":  claims.Name,
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
				EventType:  "UserGroupMemberAdded",
				Data: map[string]any{
					"group_id": groupID,
					"user_id":  userID,
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
				EventType:  "UserGroupMemberRemoved",
				Data: map[string]any{
					"group_id": groupID,
					"user_id":  userID,
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
