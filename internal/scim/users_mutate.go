// SCIM replaceUser / patchUser / handleUserPatchReplace handlers.
// Extracted from users.go (audit F009 / #149, slice 4) so users.go
// stays under the issue's <500 LOC bar.
package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// replaceUser handles PUT /scim/v2/{slug}/Users/{id}
func (h *Handler) replaceUser(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM replaceUser called")
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	userID := r.PathValue("id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "missing user id")
		return
	}

	// Verify this provider owns the user
	if err := h.verifyProviderOwnership(r.Context(), provider.ID, userID); err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	var scimUser SCIMUser
	limitBody(r)
	if err := json.NewDecoder(r.Body).Decode(&scimUser); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Verify user exists
	existingUser, err := h.store.Repos().User.Get(ctx, userID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("failed to get user for replace", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	// Collect every field mutation into one atomic batch (spec 28). All
	// target the user/<id> stream, so an email change can no longer land
	// while a profile update in the same PUT fails — the request either
	// applies every change or none, and a 500 leaves PM unchanged instead
	// of half-synced from the IdP. Conditions are evaluated against the
	// user read above; syncIdentityLink stays a separate concern below.
	var events []store.Event

	// Email
	newEmail := scimUser.UserName
	if newEmail == "" && len(scimUser.Emails) > 0 {
		newEmail = scimUser.Emails[0].Value
	}
	if newEmail != "" && newEmail != existingUser.Email {
		events = append(events, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserEmailChanged),
			Data:       payloads.UserEmailChanged{Email: &newEmail},
			ActorType:  "scim",
			ActorID:    provider.ID,
		})
	}

	// Active status
	if !scimUser.IsActive() && !existingUser.Disabled {
		events = append(events, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserDisabled),
			Data:       payloads.UserDisabled{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		})
	} else if scimUser.IsActive() && existingUser.Disabled {
		events = append(events, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserEnabled),
			Data:       payloads.UserEnabled{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		})
	}

	// Profile — gate on "name object asserted" rather than "any value
	// non-empty": SCIM is the source of truth, so an explicitly empty
	// name object clears the profile ("" overwrite), while an omitted one
	// preserves it. The old any-non-empty gate made an explicit clear
	// impossible.
	if scimUser.Name != nil {
		newDisplayName := formatExternalName(scimUser.Name)
		newGivenName := safeNameField(scimUser.Name, "given")
		newFamilyName := safeNameField(scimUser.Name, "family")
		events = append(events, store.Event{
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
		})
	}

	if err := h.store.AppendEvents(ctx, events); err != nil {
		// A 500 after a dropped source-of-truth update would silently
		// desync PM from the IdP; atomicity means nothing applied here.
		h.logger.Error("failed to apply SCIM user replace", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	// Sync identity link (external_email + external_name) from SCIM source of truth
	effectiveEmail := newEmail
	if effectiveEmail == "" {
		effectiveEmail = existingUser.Email
	}
	if err := h.syncIdentityLink(ctx, provider, userID, effectiveEmail, scimUser.Name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sync identity link")
		return
	}

	// Read back updated user
	user, err := h.store.Repos().User.Get(ctx, userID)
	if err != nil {
		h.logger.Error("failed to read back updated user", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read user")
		return
	}

	externalID := scimUser.ExternalID
	if externalID == "" {
		// Try to look up existing external ID
		linked, linkErr := h.store.Queries().FindSCIMUserByEmail(ctx, db.FindSCIMUserByEmailParams{
			ProviderID: provider.ID,
			Email:      user.Email,
		})
		if linkErr == nil {
			externalID = linked.ScimExternalID
		}
	}

	writeJSON(w, http.StatusOK, userToSCIM(user, externalID, baseURL))
}

// patchUser handles PATCH /scim/v2/{slug}/Users/{id}
func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM patchUser called")
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	userID := r.PathValue("id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "missing user id")
		return
	}

	// Verify this provider owns the user
	if err := h.verifyProviderOwnership(r.Context(), provider.ID, userID); err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	limitBody(r)
	var patch SCIMPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Verify user exists
	existingUser, err := h.store.Repos().User.Get(ctx, userID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("failed to get user for patch", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	for _, op := range patch.Operations {
		// Pre-validate per RFC 7644 §3.5.2 so the user patch path
		// rejects unknown verbs with a 400 even though add/remove
		// fall through to the catch-all default below — they are
		// not implemented for users today, but they ARE valid SCIM
		// ops, and a 400 with the precise error is the right
		// response (vs. a 501 for the implementation gap).
		if !op.Op.IsValid() {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported patch op: %s", op.Op))
			return
		}
		switch op.Op.Normalize() {
		case SCIMPatchOpReplace:
			if err := h.handleUserPatchReplace(ctx, provider, userID, existingUser, op); err != nil {
				h.logger.Error("failed to apply SCIM patch op", "op", op.Op, "path", op.Path, "error", err)
				writeError(w, http.StatusInternalServerError, "failed to apply patch operation")
				return
			}
		default:
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported patch op: %s", op.Op))
			return
		}
	}

	// Sync identity link with any name/email changes from PATCH ops
	patchedUser, err := h.store.Repos().User.Get(ctx, userID)
	if err != nil {
		h.logger.Error("failed to read back patched user", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read user")
		return
	}
	if err := h.syncIdentityLink(ctx, provider, userID, patchedUser.Email, extractNameFromPatchOps(patch.Operations)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sync identity link")
		return
	}

	// Look up external ID
	externalID := ""
	linked, linkErr := h.store.Queries().FindSCIMUserByEmail(ctx, db.FindSCIMUserByEmailParams{
		ProviderID: provider.ID,
		Email:      patchedUser.Email,
	})
	if linkErr == nil {
		externalID = linked.ScimExternalID
	}

	writeJSON(w, http.StatusOK, userToSCIM(patchedUser, externalID, baseURL))
}

// handleUserPatchReplace processes a single "replace" patch operation on a user.
func (h *Handler) handleUserPatchReplace(ctx context.Context, provider store.IdentityProvider, userID string, existingUser store.User, op SCIMPatchOp) error {
	path := strings.ToLower(op.Path)

	switch path {
	case "active":
		active, ok := op.Value.(bool)
		if !ok {
			// Try string conversion
			if s, ok := op.Value.(string); ok {
				active = strings.EqualFold(s, "true")
			}
		}
		if !active && !existingUser.Disabled {
			return h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserDisabled),
				Data:       payloads.UserDisabled{},
				ActorType:  "scim",
				ActorID:    provider.ID,
			})
		} else if active && existingUser.Disabled {
			return h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserEnabled),
				Data:       payloads.UserEnabled{},
				ActorType:  "scim",
				ActorID:    provider.ID,
			})
		}

	case "username":
		email, ok := op.Value.(string)
		if !ok || email == "" {
			return fmt.Errorf("invalid userName value")
		}
		if email != existingUser.Email {
			return h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserEmailChanged),
				Data:       payloads.UserEmailChanged{Email: &email},
				ActorType:  "scim",
				ActorID:    provider.ID,
			})
		}

	case "emails":
		// Value should be an array of email objects
		emailsRaw, ok := op.Value.([]any)
		if !ok || len(emailsRaw) == 0 {
			return fmt.Errorf("invalid emails value")
		}
		emailObj, ok := emailsRaw[0].(map[string]any)
		if !ok {
			return fmt.Errorf("invalid email object")
		}
		email, ok := emailObj["value"].(string)
		if !ok || email == "" {
			return fmt.Errorf("invalid email value")
		}
		if email != existingUser.Email {
			return h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserEmailChanged),
				Data:       payloads.UserEmailChanged{Email: &email},
				ActorType:  "scim",
				ActorID:    provider.ID,
			})
		}

	case "name":
		// Update profile fields from name object
		nameMap, ok := op.Value.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid name value")
		}
		// Partial update: only the supplied fields get pointers, so
		// omitted keys stay off the wire (projector preserves them).
		var data payloads.UserProfileUpdated
		if gn, ok := nameMap["givenName"].(string); ok {
			data.GivenName = &gn
		}
		if fn, ok := nameMap["familyName"].(string); ok {
			data.FamilyName = &fn
		}
		if fm, ok := nameMap["formatted"].(string); ok {
			data.DisplayName = &fm
		}
		if data != (payloads.UserProfileUpdated{}) {
			return h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserProfileUpdated),
				Data:       data,
				ActorType:  "scim",
				ActorID:    provider.ID,
			})
		}
		// Identity link sync happens in patchUser after all ops.

	case "name.givenname", "name.familyname", "name.formatted":
		// Sub-path name changes — handled via identity link sync in patchUser.

	case "":
		// No path — the value is a map of attributes to replace
		valueMap, ok := op.Value.(map[string]any)
		if !ok {
			return fmt.Errorf("replace without path requires object value")
		}
		for key, val := range valueMap {
			subOp := SCIMPatchOp{
				Op:    SCIMPatchOpReplace,
				Path:  key,
				Value: val,
			}
			if err := h.handleUserPatchReplace(ctx, provider, userID, existingUser, subOp); err != nil {
				return err
			}
		}
	}

	return nil
}
