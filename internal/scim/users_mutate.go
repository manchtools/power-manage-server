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
	existingUser, err := h.store.Queries().GetUserByID(ctx, userID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("failed to get user for replace", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	// Update email if changed
	newEmail := scimUser.UserName
	if newEmail == "" && len(scimUser.Emails) > 0 {
		newEmail = scimUser.Emails[0].Value
	}
	if newEmail != "" && newEmail != existingUser.Email {
		err = h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserEmailChanged),
			Data: map[string]any{
				"email": newEmail,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		})
		if err != nil {
			h.logger.Error("failed to update user email", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to update user email")
			return
		}
	}

	// Update active status
	if !scimUser.IsActive() && !existingUser.Disabled {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserDisabled),
			Data:       map[string]any{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		}); err != nil {
			h.logger.Error("failed to disable user via SCIM", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to update user status")
			return
		}
	} else if scimUser.IsActive() && existingUser.Disabled {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserEnabled),
			Data:       map[string]any{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		}); err != nil {
			h.logger.Error("failed to enable user via SCIM", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to update user status")
			return
		}
	}

	// Update profile if name fields provided
	newDisplayName := formatExternalName(scimUser.Name)
	newGivenName := safeNameField(scimUser.Name, "given")
	newFamilyName := safeNameField(scimUser.Name, "family")
	if newDisplayName != "" || newGivenName != "" || newFamilyName != "" {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserProfileUpdated),
			Data: map[string]any{
				"display_name": newDisplayName,
				"given_name":   newGivenName,
				"family_name":  newFamilyName,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		}); err != nil {
			h.logger.Warn("failed to update user profile via SCIM", "error", err)
		}
	}

	// Sync identity link (external_email + external_name) from SCIM source of truth
	effectiveEmail := newEmail
	if effectiveEmail == "" {
		effectiveEmail = existingUser.Email
	}
	h.syncIdentityLink(ctx, provider, userID, effectiveEmail, scimUser.Name)

	// Read back updated user
	user, err := h.store.Queries().GetUserByID(ctx, userID)
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
	existingUser, err := h.store.Queries().GetUserByID(ctx, userID)
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
	patchedUser, err := h.store.Queries().GetUserByID(ctx, userID)
	if err != nil {
		h.logger.Error("failed to read back patched user", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read user")
		return
	}
	h.syncIdentityLink(ctx, provider, userID, patchedUser.Email, extractNameFromPatchOps(patch.Operations))

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
func (h *Handler) handleUserPatchReplace(ctx context.Context, provider db.IdentityProvidersProjection, userID string, existingUser db.UsersProjection, op SCIMPatchOp) error {
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
				Data:       map[string]any{},
				ActorType:  "scim",
				ActorID:    provider.ID,
			})
		} else if active && existingUser.Disabled {
			return h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  string(eventtypes.UserEnabled),
				Data:       map[string]any{},
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
				Data: map[string]any{
					"email": email,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
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
				Data: map[string]any{
					"email": email,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
		}

	case "name":
		// Update profile fields from name object
		nameMap, ok := op.Value.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid name value")
		}
		data := map[string]any{}
		if gn, ok := nameMap["givenName"].(string); ok {
			data["given_name"] = gn
		}
		if fn, ok := nameMap["familyName"].(string); ok {
			data["family_name"] = fn
		}
		if fm, ok := nameMap["formatted"].(string); ok {
			data["display_name"] = fm
		}
		if len(data) > 0 {
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
