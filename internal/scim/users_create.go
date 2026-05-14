// SCIM createUser handler. Extracted from users.go (audit F009 / #149,
// slice 4) so users.go stays under the issue's <500 LOC bar.
//
// createUser is the mutationally-richest SCIM handler: four distinct
// outcomes per call:
//  1. SCIM client retried POST for an externalID that's already linked
//     → sync data + return 200 (idempotency, NOT 409)
//  2. AutoLinkByEmail flag on, email matches an already-linked user
//     → sync + return 200
//  3. AutoLinkByEmail flag on, email matches an unlinked user
//     → emit IdentityLinked event, return 201 with the existing user
//  4. Truly new user → emit UserCreatedWithRoles + IdentityLinked,
//     auto-enable provisioning/SSH if the global flags are on
package scim

import (
	"encoding/json"
	"net/http"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// createUser handles POST /scim/v2/{slug}/Users
func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM createUser called")
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var scimUser SCIMUser
	limitBody(r)
	if err := json.NewDecoder(r.Body).Decode(&scimUser); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Extract email: prefer userName, fall back to emails[0].value
	email := scimUser.UserName
	if email == "" && len(scimUser.Emails) > 0 {
		email = scimUser.Emails[0].Value
	}
	if email == "" {
		writeError(w, http.StatusBadRequest, "userName or emails[0].value is required")
		return
	}

	externalID := scimUser.ExternalID

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Check if a user with this external ID already exists for this provider
	if externalID != "" {
		existing, err := h.store.Queries().FindSCIMUserByExternalID(ctx, db.FindSCIMUserByExternalIDParams{
			ProviderID: provider.ID,
			ExternalID: externalID,
		})
		if err == nil {
			// User already linked with this external ID — sync data from SCIM
			h.logger.Debug("SCIM createUser: user already exists by external ID, syncing", "user_id", existing.ID, "external_id", externalID)
			// (source of truth) and return existing resource. Using 200 instead
			// of 409 makes POST idempotent for SCIM clients that re-POST on
			// every sync cycle.
			h.syncUserFromSCIM(ctx, provider, existing.ID, email, scimUser.Active, scimUser.Name)
			user, err := h.store.Queries().GetUserByID(ctx, existing.ID)
			if err != nil {
				writeJSON(w, http.StatusOK, findExternalIDUserRowToSCIM(existing, baseURL))
			} else {
				writeJSON(w, http.StatusOK, userToSCIM(user, existing.ScimExternalID, baseURL))
			}
			return
		}
		if !store.IsNotFound(err) {
			h.logger.Error("failed to check existing SCIM user", "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	// Check if we should link to an existing user by email
	if provider.AutoLinkByEmail {
		existing, err := h.store.Queries().FindSCIMUserByEmail(ctx, db.FindSCIMUserByEmailParams{
			ProviderID: provider.ID,
			Email:      email,
		})
		if err == nil {
			// Already linked — sync data from SCIM (source of truth) and return
			h.syncUserFromSCIM(ctx, provider, existing.ID, email, scimUser.Active, scimUser.Name)
			user, readErr := h.store.Queries().GetUserByID(ctx, existing.ID)
			if readErr != nil {
				writeJSON(w, http.StatusOK, findUserRowToSCIM(existing, baseURL))
			} else {
				writeJSON(w, http.StatusOK, userToSCIM(user, existing.ScimExternalID, baseURL))
			}
			return
		}

		// Check if user exists but is not yet linked
		existingUser, err := h.store.Queries().GetUserByEmail(ctx, email)
		if err == nil {
			// User exists — create identity link
			h.logger.Debug("SCIM createUser: linking existing user by email", "user_id", existingUser.ID, "email", email)
			linkID := newULID()
			err = h.store.AppendEvent(ctx, store.Event{
				StreamType: "identity_provider",
				StreamID:   linkID,
				EventType:  string(eventtypes.IdentityLinked),
				Data: map[string]any{
					"user_id":        existingUser.ID,
					"provider_id":    provider.ID,
					"external_id":    externalID,
					"external_email": email,
					"external_name":  formatExternalName(scimUser.Name),
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
			if err != nil {
				h.logger.Error("failed to link existing user via SCIM", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to link user")
				return
			}

			writeJSON(w, http.StatusCreated, userToSCIM(existingUser, externalID, baseURL))
			return
		}
		if !store.IsNotFound(err) {
			h.logger.Error("failed to look up user by email", "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	// Create new user
	h.logger.Debug("SCIM createUser: creating new user", "email", email, "external_id", externalID)
	userID := newULID()

	linuxUID, err := h.store.Queries().GetNextLinuxUID(ctx)
	if err != nil {
		h.logger.Error("failed to assign linux uid via SCIM", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to assign linux uid")
		return
	}
	linuxUsername := deriveLinuxUsername(email, scimUser.UserName)
	if linuxUsername == "" {
		linuxUsername = "user_" + userID[:8]
	}

	// Resolve the role ID set BEFORE emitting the event so the user
	// INSERT and the per-role INSERT land atomically inside the
	// projector's WithTx (issue #135). SCIM only ever assigns the
	// provider's configured default role at creation time; if no
	// default is configured the slice stays empty and the projector
	// skips the per-role INSERT loop.
	var roleIDs []string
	if provider.DefaultRoleID != "" {
		roleIDs = []string{provider.DefaultRoleID}
	}

	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  string(eventtypes.UserCreatedWithRoles),
		Data: map[string]any{
			"email":          email,
			"display_name":   formatExternalName(scimUser.Name),
			"given_name":     safeNameField(scimUser.Name, "given"),
			"family_name":    safeNameField(scimUser.Name, "family"),
			"linux_username": linuxUsername,
			"linux_uid":      linuxUID,
			"role_ids":       roleIDs,
		},
		ActorType: "scim",
		ActorID:   provider.ID,
	})
	if err != nil {
		h.logger.Error("failed to create user via SCIM", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Create identity link
	linkID := newULID()
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   linkID,
		EventType:  string(eventtypes.IdentityLinked),
		Data: map[string]any{
			"user_id":        userID,
			"provider_id":    provider.ID,
			"external_id":    externalID,
			"external_email": email,
			"external_name":  formatExternalName(scimUser.Name),
		},
		ActorType: "scim",
		ActorID:   provider.ID,
	})
	if err != nil {
		h.logger.Error("failed to create identity link via SCIM", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to link user")
		return
	}

	// Auto-enable provisioning/SSH if global server settings are on
	if settings, err := h.store.Queries().GetServerSettings(ctx); err == nil {
		if settings.UserProvisioningEnabled {
			if err := h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserProvisioningSettingsUpdated),
				Data:       map[string]any{"user_provisioning_enabled": true},
				ActorType:  "system",
				ActorID:    "scim",
			}); err != nil {
				h.logger.Warn("failed to auto-enable provisioning for SCIM user", "user_id", userID, "error", err)
			}
		}
		if settings.SshAccessForAll {
			if err := h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserSshSettingsUpdated),
				Data: map[string]any{
					"ssh_access_enabled": true,
					"ssh_allow_pubkey":   true,
					"ssh_allow_password": false,
				},
				ActorType: "system",
				ActorID:   "scim",
			}); err != nil {
				h.logger.Warn("failed to auto-enable SSH for SCIM user", "user_id", userID, "error", err)
			}
		}
	} else {
		h.logger.Warn("failed to check server settings for SCIM user defaults", "error", err)
	}

	// Read back created user
	user, err := h.store.Queries().GetUserByID(ctx, userID)
	if err != nil {
		h.logger.Error("failed to read back created user", "error", err)
		writeError(w, http.StatusInternalServerError, "user created but failed to read back")
		return
	}

	writeJSON(w, http.StatusCreated, userToSCIM(user, externalID, baseURL))
}
