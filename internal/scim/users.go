package scim

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

func newULID() string {
	entropy := ulid.Monotonic(rand.Reader, 0)
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}

// listUsers handles GET /scim/v2/{slug}/Users
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
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
func (h *Handler) listUsersFiltered(w http.ResponseWriter, r *http.Request, provider db.IdentityProvidersProjection, filterStr string, startIndex, count int, baseURL string) {
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
			if errors.Is(err, pgx.ErrNoRows) {
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
			if errors.Is(err, pgx.ErrNoRows) {
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
func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
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
			// User already linked with this external ID — return existing resource.
			// Using 200 instead of 409 makes POST idempotent for SCIM clients that
			// re-POST on every sync cycle.
			writeJSON(w, http.StatusOK, findExternalIDUserRowToSCIM(existing, baseURL))
			return
		}
		if !errors.Is(err, pgx.ErrNoRows) {
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
			// Already linked — return existing resource
			writeJSON(w, http.StatusOK, findUserRowToSCIM(existing, baseURL))
			return
		}

		// Check if user exists but is not yet linked
		existingUser, err := h.store.Queries().GetUserByEmail(ctx, email)
		if err == nil {
			// User exists — create identity link
			linkID := newULID()
			err = h.store.AppendEvent(ctx, store.Event{
				StreamType: "identity_provider",
				StreamID:   linkID,
				EventType:  "IdentityLinked",
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
		if !errors.Is(err, pgx.ErrNoRows) {
			h.logger.Error("failed to look up user by email", "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	// Create new user
	userID := newULID()

	err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user",
		StreamID:   userID,
		EventType:  "UserCreated",
		Data: map[string]any{
			"email": email,
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
		EventType:  "IdentityLinked",
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

	// Assign default role if configured
	if provider.DefaultRoleID != "" {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "user_role",
			StreamID:   userID + ":" + provider.DefaultRoleID,
			EventType:  "UserRoleAssigned",
			Data: map[string]any{
				"user_id": userID,
				"role_id": provider.DefaultRoleID,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		}); err != nil {
			h.logger.Error("failed to assign default role via SCIM", "error", err)
		}
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

// getUser handles GET /scim/v2/{slug}/Users/{id}
func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
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

	user, err := h.store.Queries().GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
func (h *Handler) replaceUser(w http.ResponseWriter, r *http.Request) {
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
		if errors.Is(err, pgx.ErrNoRows) {
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
			EventType:  "UserEmailChanged",
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
	if !scimUser.Active && !existingUser.Disabled {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  "UserDisabled",
			Data:       map[string]any{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		}); err != nil {
			h.logger.Error("failed to disable user via SCIM", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to update user status")
			return
		}
	} else if scimUser.Active && existingUser.Disabled {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  "UserEnabled",
			Data:       map[string]any{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		}); err != nil {
			h.logger.Error("failed to enable user via SCIM", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to update user status")
			return
		}
	}

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
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("failed to get user for patch", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	for _, op := range patch.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
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

	// Read back patched user
	user, err := h.store.Queries().GetUserByID(ctx, userID)
	if err != nil {
		h.logger.Error("failed to read back patched user", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to read user")
		return
	}

	// Look up external ID
	externalID := ""
	linked, linkErr := h.store.Queries().FindSCIMUserByEmail(ctx, db.FindSCIMUserByEmailParams{
		ProviderID: provider.ID,
		Email:      user.Email,
	})
	if linkErr == nil {
		externalID = linked.ScimExternalID
	}

	writeJSON(w, http.StatusOK, userToSCIM(user, externalID, baseURL))
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
				EventType:  "UserDisabled",
				Data:       map[string]any{},
				ActorType:  "scim",
				ActorID:    provider.ID,
			})
		} else if active && existingUser.Disabled {
			return h.store.AppendEvent(ctx, store.Event{
				StreamType: "user",
				StreamID:   userID,
				EventType:  "UserEnabled",
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
				EventType:  "UserEmailChanged",
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
				EventType:  "UserEmailChanged",
				Data: map[string]any{
					"email": email,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
		}

	case "":
		// No path — the value is a map of attributes to replace
		valueMap, ok := op.Value.(map[string]any)
		if !ok {
			return fmt.Errorf("replace without path requires object value")
		}
		for key, val := range valueMap {
			subOp := SCIMPatchOp{
				Op:    "replace",
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

// deleteUser handles DELETE /scim/v2/{slug}/Users/{id}
func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
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
		EventType:  "IdentityUnlinked",
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
		err = h.store.AppendEvent(ctx, store.Event{
			StreamType: "user",
			StreamID:   userID,
			EventType:  "UserDeleted",
			Data:       map[string]any{},
			ActorType:  "scim",
			ActorID:    provider.ID,
		})
		if err != nil {
			h.logger.Error("failed to delete user via SCIM", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to delete user")
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// userToSCIM converts a UsersProjection to a SCIM user resource.
func userToSCIM(user db.UsersProjection, externalID, baseURL string) SCIMUser {
	su := SCIMUser{
		Schemas:    []string{UserSchema},
		ID:         user.ID,
		ExternalID: externalID,
		UserName:   user.Email,
		Active:     !user.Disabled,
		Emails: []SCIMEmail{
			{
				Value:   user.Email,
				Type:    "work",
				Primary: true,
			},
		},
		Meta: &SCIMMeta{
			ResourceType: "User",
			Location:     baseURL + "/Users/" + user.ID,
		},
	}

	if user.CreatedAt.Valid {
		su.Meta.Created = user.CreatedAt.Time.Format(time.RFC3339)
	}
	if user.UpdatedAt.Valid {
		su.Meta.LastModified = user.UpdatedAt.Time.Format(time.RFC3339)
	}

	return su
}

// userRowToSCIM converts a ListSCIMUsersRow to a SCIM user resource.
func userRowToSCIM(row db.ListSCIMUsersRow, baseURL string) SCIMUser {
	su := SCIMUser{
		Schemas:    []string{UserSchema},
		ID:         row.ID,
		ExternalID: row.ScimExternalID,
		UserName:   row.Email,
		Active:     !row.Disabled,
		Emails: []SCIMEmail{
			{
				Value:   row.Email,
				Type:    "work",
				Primary: true,
			},
		},
		Meta: &SCIMMeta{
			ResourceType: "User",
			Location:     baseURL + "/Users/" + row.ID,
		},
	}

	if row.CreatedAt.Valid {
		su.Meta.Created = row.CreatedAt.Time.Format(time.RFC3339)
	}
	if row.UpdatedAt.Valid {
		su.Meta.LastModified = row.UpdatedAt.Time.Format(time.RFC3339)
	}

	return su
}

// findUserRowToSCIM converts a FindSCIMUserByEmailRow to a SCIM user resource.
func findUserRowToSCIM(row db.FindSCIMUserByEmailRow, baseURL string) SCIMUser {
	su := SCIMUser{
		Schemas:    []string{UserSchema},
		ID:         row.ID,
		ExternalID: row.ScimExternalID,
		UserName:   row.Email,
		Active:     !row.Disabled,
		Emails: []SCIMEmail{
			{
				Value:   row.Email,
				Type:    "work",
				Primary: true,
			},
		},
		Meta: &SCIMMeta{
			ResourceType: "User",
			Location:     baseURL + "/Users/" + row.ID,
		},
	}

	if row.CreatedAt.Valid {
		su.Meta.Created = row.CreatedAt.Time.Format(time.RFC3339)
	}
	if row.UpdatedAt.Valid {
		su.Meta.LastModified = row.UpdatedAt.Time.Format(time.RFC3339)
	}

	return su
}

// findExternalIDUserRowToSCIM converts a FindSCIMUserByExternalIDRow to a SCIM user resource.
func findExternalIDUserRowToSCIM(row db.FindSCIMUserByExternalIDRow, baseURL string) SCIMUser {
	su := SCIMUser{
		Schemas:    []string{UserSchema},
		ID:         row.ID,
		ExternalID: row.ScimExternalID,
		UserName:   row.Email,
		Active:     !row.Disabled,
		Emails: []SCIMEmail{
			{
				Value:   row.Email,
				Type:    "work",
				Primary: true,
			},
		},
		Meta: &SCIMMeta{
			ResourceType: "User",
			Location:     baseURL + "/Users/" + row.ID,
		},
	}

	if row.CreatedAt.Valid {
		su.Meta.Created = row.CreatedAt.Time.Format(time.RFC3339)
	}
	if row.UpdatedAt.Valid {
		su.Meta.LastModified = row.UpdatedAt.Time.Format(time.RFC3339)
	}

	return su
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
