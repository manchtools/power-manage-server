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
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
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
			if err := h.syncUserFromSCIM(ctx, provider, existing.ID, email, scimUser.Active, scimUser.Name); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to sync user")
				return
			}
			user, err := h.store.Repos().User.Get(ctx, existing.ID)
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
			if err := h.syncUserFromSCIM(ctx, provider, existing.ID, email, scimUser.Active, scimUser.Name); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to sync user")
				return
			}
			user, readErr := h.store.Repos().User.Get(ctx, existing.ID)
			if readErr != nil {
				writeJSON(w, http.StatusOK, findUserRowToSCIM(existing, baseURL))
			} else {
				writeJSON(w, http.StatusOK, userToSCIM(user, existing.ScimExternalID, baseURL))
			}
			return
		}

		// Check if user exists but is not yet linked
		existingUser, err := h.store.Repos().User.GetByEmail(ctx, email)
		if err == nil {
			// WS5 #2 — account-takeover guard. A SCIM provider can assert any
			// email; binding an asserted email to a pre-existing LOCAL PASSWORD
			// account would let a compromised/over-trusted IdP seize that
			// account (e.g. a local admin). Refuse unless the operator has
			// knowingly delegated identity to this provider via
			// trust_email_assertions. Passwordless / already-SSO-provisioned
			// accounts are fine to link (no local credential to hijack).
			if existingUser.HasPassword && !provider.TrustEmailAssertions {
				h.logger.Warn("SCIM: refusing auto-link to local password account by unverified email",
					"user_id", existingUser.ID, "provider_id", provider.ID)
				writeError(w, http.StatusConflict, "email already belongs to a local account; cannot auto-link")
				return
			}
			// User exists — create identity link
			h.logger.Debug("SCIM createUser: linking existing user by email", "user_id", existingUser.ID, "email", email)
			linkID := newULID()
			err = h.store.AppendEvent(ctx, store.Event{
				StreamType: "identity_provider",
				StreamID:   linkID,
				EventType:  string(eventtypes.IdentityLinked),
				Data: payloads.IdentityLinked{
					UserID:        existingUser.ID,
					ProviderID:    provider.ID,
					ExternalID:    externalID,
					ExternalEmail: email,
					ExternalName:  formatExternalName(scimUser.Name),
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

	linuxUID, err := h.store.Repos().User.NextLinuxUID(ctx)
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

	// Spec 19 AC 1: mint the user's DEK BEFORE the creation event —
	// the sealer fails closed without it.
	if err := h.store.MintUserDEK(ctx, userID); err != nil {
		h.logger.Error("failed to mint user encryption key via SCIM", "user_id", userID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Create the user as one atomic unit (audit L7): the UserCreatedWithRoles,
	// IdentityLinked, and any auto-enable events either all commit or none do.
	// A mid-sequence failure on independent appends left an orphan user with no
	// identity link; the IdP's next POST then missed the externalID-keyed dedup
	// and — with auto-link off — minted a *duplicate* user under a fresh ULID.
	// Batching makes a failed create roll back fully, so the IdP's retry is
	// clean. Array order = apply order (user first, then its link/settings).
	events := []store.Event{
		{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserCreatedWithRoles),
			// Pointers always set (possibly to ""): SCIM asserts every
			// field, mirroring the legacy always-present map keys.
			Data: payloads.UserCreatedWithRoles{
				Email:         &email,
				DisplayName:   ptr(formatExternalName(scimUser.Name)),
				GivenName:     ptr(safeNameField(scimUser.Name, "given")),
				FamilyName:    ptr(safeNameField(scimUser.Name, "family")),
				LinuxUsername: &linuxUsername,
				LinuxUID:      &linuxUID,
				RoleIDs:       roleIDs,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		},
		{
			StreamType: "identity_provider",
			StreamID:   newULID(),
			EventType:  string(eventtypes.IdentityLinked),
			Data: payloads.IdentityLinked{
				UserID:        userID,
				ProviderID:    provider.ID,
				ExternalID:    externalID,
				ExternalEmail: email,
				ExternalName:  formatExternalName(scimUser.Name),
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		},
	}

	// Auto-enable provisioning/SSH if global server settings are on. These join
	// the same atomic batch — a settings read failure only skips the auto-enable
	// (not fatal: the user is still created), but a failed append rolls the whole
	// create back so the IdP retries rather than leaving a half-provisioned user.
	if settings, err := h.store.Queries().GetServerSettings(ctx); err == nil {
		if settings.UserProvisioningEnabled {
			events = append(events, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserProvisioningSettingsUpdated),
				Data:       payloads.UserProvisioningSettingsUpdated{UserProvisioningEnabled: ptr(true)},
				ActorType:  "system",
				ActorID:    "scim",
			})
		}
		if settings.SshAccessForAll {
			events = append(events, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserSshSettingsUpdated),
				Data: payloads.UserSshSettingsUpdated{
					SshAccessEnabled: ptr(true),
					SshAllowPubkey:   ptr(true),
					SshAllowPassword: ptr(false),
				},
				ActorType: "system",
				ActorID:   "scim",
			})
		}
	} else {
		h.logger.Warn("failed to check server settings for SCIM user defaults", "error", err)
	}

	if err := h.store.AppendEvents(ctx, events); err != nil {
		h.logger.Error("failed to create user via SCIM", "error", err)
		// The DEK minted above is now orphaned — its user rolled back with the
		// batch. Best-effort shred it so a persistent create failure can't leak a
		// wrapped key on every IdP retry (each retry mints a fresh userID). The
		// key sealed nothing (the batch never committed), so this destroys an
		// inert row. ponytail: bounded cleanup; the full fix is minting the DEK
		// inside the event transaction, which needs the minter to join AppendEvents.
		if _, serr := h.store.Repos().UserEncryptionKey.Shred(ctx, userID); serr != nil {
			h.logger.Warn("failed to shred orphaned user DEK after SCIM create rollback", "user_id", userID, "error", serr)
		}
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Read back created user
	user, err := h.store.Repos().User.Get(ctx, userID)
	if err != nil {
		h.logger.Error("failed to read back created user", "error", err)
		writeError(w, http.StatusInternalServerError, "user created but failed to read back")
		return
	}

	writeJSON(w, http.StatusCreated, userToSCIM(user, externalID, baseURL))
}
