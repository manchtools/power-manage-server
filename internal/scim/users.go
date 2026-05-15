package scim

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// newULID + Linux-username derivation + sync/patch helpers all live
// in users_helpers.go. SCIM-resource shapers live in users_translation.go.

// listUsers handles GET /scim/v2/{slug}/Users
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM listUsers called")
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	// Parse pagination parameters (SCIM uses 1-based startIndex)
	startIndex := 1
	if s := r.URL.Query().Get("startIndex"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			startIndex = v
		}
	}

	count := 100
	if c := r.URL.Query().Get("count"); c != "" {
		if v, err := strconv.Atoi(c); err == nil && v >= 0 {
			count = v
		}
	}
	if count > 200 {
		count = 200
	}

	baseURL := baseURLFromRequest(r, provider.Slug)

	// Check for filter parameter
	if filterStr := r.URL.Query().Get("filter"); filterStr != "" {
		h.listUsersFiltered(w, r, provider, filterStr, startIndex, count, baseURL)
		return
	}

	// Get total count
	totalCount, err := h.store.Queries().CountSCIMUsers(r.Context(), provider.ID)
	if err != nil {
		h.logger.Error("failed to count SCIM users", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to count users")
		return
	}

	// List users with pagination (convert 1-based startIndex to 0-based offset)
	offset := int32(startIndex - 1)
	if offset < 0 {
		offset = 0
	}

	users, err := h.store.Queries().ListSCIMUsers(r.Context(), db.ListSCIMUsersParams{
		ProviderID: provider.ID,
		Limit:      int32(count),
		Offset:     offset,
	})
	if err != nil {
		h.logger.Error("failed to list SCIM users", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	resources := make([]any, len(users))
	for i, u := range users {
		resources[i] = userRowToSCIM(u, baseURL)
	}

	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: int(totalCount),
		StartIndex:   startIndex,
		ItemsPerPage: len(users),
		Resources:    resources,
	})
}

// listUsersFiltered handles filtered user list requests.
func (h *Handler) listUsersFiltered(w http.ResponseWriter, r *http.Request, provider store.IdentityProvider, filterStr string, startIndex, count int, baseURL string) {
	f, err := parseFilter(filterStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid filter: %s", err))
		return
	}

	var resources []any

	switch f.Attribute {
	case "userName":
		user, err := h.store.Queries().FindSCIMUserByEmail(r.Context(), db.FindSCIMUserByEmailParams{
			ProviderID: provider.ID,
			Email:      f.Value,
		})
		if err != nil {
			if store.IsNotFound(err) {
				resources = []any{}
			} else {
				h.logger.Error("failed to find SCIM user by email", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to search users")
				return
			}
		} else {
			resources = []any{findUserRowToSCIM(user, baseURL)}
		}

	case "externalId":
		user, err := h.store.Queries().FindSCIMUserByExternalID(r.Context(), db.FindSCIMUserByExternalIDParams{
			ProviderID: provider.ID,
			ExternalID: f.Value,
		})
		if err != nil {
			if store.IsNotFound(err) {
				resources = []any{}
			} else {
				h.logger.Error("failed to find SCIM user by external ID", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to search users")
				return
			}
		} else {
			resources = []any{findExternalIDUserRowToSCIM(user, baseURL)}
		}

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported filter attribute: %s", f.Attribute))
		return
	}

	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: len(resources),
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// createUser handles POST /scim/v2/{slug}/Users

// getUser handles GET /scim/v2/{slug}/Users/{id}
func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM getUser called")
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

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Verify this provider owns the user (has an identity link)
	if err := h.verifyProviderOwnership(ctx, provider.ID, userID); err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	user, err := h.store.Repos().User.Get(ctx, userID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("failed to get user", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	// Look up the external ID for this user+provider
	externalID := ""
	scimUser, err := h.store.Queries().FindSCIMUserByEmail(ctx, db.FindSCIMUserByEmailParams{
		ProviderID: provider.ID,
		Email:      user.Email,
	})
	if err == nil {
		externalID = scimUser.ScimExternalID
	}

	writeJSON(w, http.StatusOK, userToSCIM(user, externalID, baseURL))
}

// replaceUser handles PUT /scim/v2/{slug}/Users/{id}
// deleteUser handles DELETE /scim/v2/{slug}/Users/{id}
func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM deleteUser called")
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

	ctx := r.Context()

	// Verify this provider owns the user
	link, err := h.store.Queries().GetIdentityLinkByProviderAndUser(ctx, db.GetIdentityLinkByProviderAndUserParams{
		ProviderID: provider.ID,
		UserID:     userID,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	// Unlink identity from this provider
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "identity_provider",
		StreamID:   link.ID,
		EventType:  string(eventtypes.IdentityUnlinked),
		Data:       map[string]any{},
		ActorType:  "scim",
		ActorID:    provider.ID,
	}); err != nil {
		h.logger.Error("failed to unlink identity for SCIM delete", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}

	// Only delete the user if this was their last identity link.
	// If the user is linked to other providers, just unlink — don't destroy the account.
	linkCount, err := h.store.Queries().CountIdentityLinksForUser(ctx, userID)
	if err != nil {
		h.logger.Error("failed to count identity links", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}

	// linkCount reflects state after the IdentityUnlinked event projection.
	// If 0 remaining links, safe to delete the user.
	if linkCount == 0 {
		// Load the user projection BEFORE emitting UserDeleted so
		// CleanupDeletedUserActions can read the system_*_action_id
		// columns that the deletion projector will clear. rc11 #77 —
		// SCIM was previously bypassing this cleanup entirely,
		// leaving orphan pm-tty-* and USER provision actions on
		// every device the deleted user was assigned to.
		user, loadErr := h.store.Repos().User.Get(ctx, userID)

		err = h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  string(eventtypes.UserDeleted),
			Data:       map[string]any{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		})
		if err != nil {
			h.logger.Error("failed to delete user via SCIM", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to delete user")
			return
		}

		// Best-effort cleanup. If the projection load above failed
		// we have nothing to feed the cleaner; log and let the
		// periodic reconciler eventually GC orphan actions via the
		// is_deleted projection column. systemActions can be nil in
		// tests.
		if h.systemActions != nil && loadErr == nil {
			if err := h.systemActions.CleanupDeletedUserActions(ctx, user); err != nil {
				h.logger.Error("failed to cleanup system actions for SCIM-deleted user",
					"user_id", userID, "error", err)
			}
		} else if loadErr != nil {
			h.logger.Warn("could not load user projection for SCIM delete cleanup; orphan actions may remain",
				"user_id", userID, "error", loadErr)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// userToSCIM converts a UsersProjection to a SCIM user resource.
// SCIM user-resource shapers (userToSCIM, userRowToSCIM, etc.) +
// safeNameField live in users_translation.go.

// SCIM user sync helpers (syncUserFromSCIM, syncIdentityLink),
// patch-op extractors (extractNameFromPatchOps, formatExternalName),
// provider-ownership guard, request-shape helpers, and Linux-username
// derivation live in users_helpers.go.
