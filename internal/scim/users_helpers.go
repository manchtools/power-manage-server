// SCIM user-flow helpers extracted from users.go (audit F009 / #149,
// slice 2). Keeps users.go focused on the per-RPC HTTP handlers
// (list / get / create / replace / patch / delete) by lifting the
// support functions they share — sync helpers, patch-op extractors,
// linux-username derivation, and small request-shape helpers — into
// this sibling file.
package scim

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// newULID returns a monotonic-clock ULID string. Used for new event
// stream IDs that the SCIM handlers append.
func newULID() string {
	entropy := ulid.Monotonic(rand.Reader, 0)
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}

// ptr lifts a value into a pointer for the payloads structs whose
// pointer fields mean "explicitly present on the wire" — SCIM is the
// source of truth and always emits the field, even when empty.
func ptr[T any](v T) *T { return &v }

// syncUserFromSCIM syncs email, active status, profile, and identity link data from SCIM.
// SCIM is treated as the source of truth — any differences are overwritten. Fails
// closed (audit L7): a read or append failure is returned so the caller answers
// 500 and the IdP retries. The per-difference appends are idempotent (each is
// gated on "changed"), so a retry converges without duplicating state.
func (h *Handler) syncUserFromSCIM(ctx context.Context, provider store.IdentityProvider, userID, email string, active *bool, name *SCIMName) error {
	user, err := h.store.Repos().User.Get(ctx, userID)
	if err != nil {
		h.logger.Error("failed to get user for SCIM sync", "user_id", userID, "error", err)
		return err
	}

	// Sync email
	if email != "" && email != user.Email {
		if err := h.appendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserEmailChanged),
			Data:       payloads.UserEmailChanged{Email: &email},
			ActorType:  "scim",
			ActorID:    provider.ID,
		}); err != nil {
			return err
		}
	}

	// Sync active status (nil = not provided, default to true per SCIM RFC 7643)
	isActive := active == nil || *active
	if !isActive && !user.Disabled {
		if err := h.appendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserDisabled),
			Data:       payloads.UserDisabled{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		}); err != nil {
			return err
		}
	} else if isActive && user.Disabled {
		if err := h.appendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserEnabled),
			Data:       payloads.UserEnabled{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		}); err != nil {
			return err
		}
	}

	// Sync profile fields (display_name, given_name, family_name)
	newDisplayName := formatExternalName(name)
	newGivenName := safeNameField(name, "given")
	newFamilyName := safeNameField(name, "family")
	// Gate on "name object asserted" rather than "any value non-empty":
	// SCIM is the source of truth, so an explicitly empty name object
	// clears the profile ("" overwrite), while an omitted one preserves
	// it. The old any-non-empty gate made an explicit clear impossible.
	if name != nil {
		if err := h.appendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserProfileUpdated),
			// Pointers always set: SCIM is the source of truth, so an
			// empty field is an explicit "" on the wire (overwrite,
			// matching the legacy map emit) — never nil (preserve).
			Data: payloads.UserProfileUpdated{
				DisplayName: &newDisplayName,
				GivenName:   &newGivenName,
				FamilyName:  &newFamilyName,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		}); err != nil {
			return err
		}
	}

	// Sync identity link (external_email + external_name)
	return h.syncIdentityLink(ctx, provider, userID, email, name)
}

// syncIdentityLink updates the identity link's external_email and external_name
// to reflect the latest data from the SCIM provider (source of truth). Fails
// closed (audit L7).
func (h *Handler) syncIdentityLink(ctx context.Context, provider store.IdentityProvider, userID, email string, name *SCIMName) error {
	link, err := h.store.Queries().GetIdentityLinkByProviderAndUser(ctx, db.GetIdentityLinkByProviderAndUserParams{
		ProviderID: provider.ID,
		UserID:     userID,
	})
	if err != nil {
		h.logger.Error("failed to get identity link for SCIM sync", "user_id", userID, "provider_id", provider.ID, "error", err)
		return err
	}

	return h.appendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   link.ID,
		EventType:  string(eventtypes.IdentityLinkLoginUpdated),
		Data: payloads.IdentityLinkLoginUpdated{
			UserID:        userID,
			ProviderID:    provider.ID,
			ExternalID:    link.ExternalID,
			ExternalEmail: email,
			ExternalName:  formatExternalName(name),
		},
		ActorType: "scim",
		ActorID:   provider.ID,
	})
}

// extractNameFromPatchOps scans PATCH operations for name-related changes and
// returns a SCIMName if any were found, or nil if none.
func extractNameFromPatchOps(ops []SCIMPatchOp) *SCIMName {
	var name SCIMName
	found := false

	for _, op := range ops {
		if op.Op.Normalize() != SCIMPatchOpReplace {
			continue
		}
		path := strings.ToLower(op.Path)

		switch path {
		case "name":
			// Value is a name object
			if m, ok := op.Value.(map[string]any); ok {
				if v, ok := m["givenName"].(string); ok {
					name.GivenName = v
					found = true
				}
				if v, ok := m["familyName"].(string); ok {
					name.FamilyName = v
					found = true
				}
				if v, ok := m["formatted"].(string); ok {
					name.Formatted = v
					found = true
				}
			}
		case "name.givenname":
			if v, ok := op.Value.(string); ok {
				name.GivenName = v
				found = true
			}
		case "name.familyname":
			if v, ok := op.Value.(string); ok {
				name.FamilyName = v
				found = true
			}
		case "name.formatted":
			if v, ok := op.Value.(string); ok {
				name.Formatted = v
				found = true
			}
		}
	}

	if !found {
		return nil
	}
	return &name
}

// formatExternalName extracts a display name from SCIM name fields.
func formatExternalName(name *SCIMName) string {
	if name == nil {
		return ""
	}
	if name.Formatted != "" {
		return name.Formatted
	}
	parts := []string{}
	if name.GivenName != "" {
		parts = append(parts, name.GivenName)
	}
	if name.FamilyName != "" {
		parts = append(parts, name.FamilyName)
	}
	return strings.Join(parts, " ")
}

// verifyProviderOwnership checks that the user has an identity link to the
// given SCIM provider. This prevents one provider from accessing or modifying
// users provisioned by a different provider.
func (h *Handler) verifyProviderOwnership(ctx context.Context, providerID, userID string) error {
	_, err := h.store.Queries().GetIdentityLinkByProviderAndUser(ctx, db.GetIdentityLinkByProviderAndUserParams{
		ProviderID: providerID,
		UserID:     userID,
	})
	return err
}

// baseURLFromRequest constructs the SCIM base URL from the request.
func baseURLFromRequest(r *http.Request, slug string) string {
	scheme := "https"
	if r.TLS == nil {
		if fwd := r.Header.Get("X-Forwarded-Proto"); fwd == "https" || fwd == "http" {
			scheme = fwd
		} else {
			scheme = "http"
		}
	}
	return fmt.Sprintf("%s://%s/scim/v2/%s", scheme, r.Host, slug)
}

var linuxUsernameSanitizeRe = regexp.MustCompile(`[^a-z0-9_.\-]`)

// deriveLinuxUsername picks a system-username from the SCIM payload.
// Preference order: explicit preferredUsername → email local-part →
// the email itself. Sanitisation lowercases then replaces any
// non-allowlisted byte with `_` (Linux useradd rejects shell-meta
// characters in usernames). Capped at 32 bytes — the longest
// historically-portable useradd-accepted length.
func deriveLinuxUsername(email, preferredUsername string) string {
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
