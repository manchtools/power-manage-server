package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// listGroups handles GET /scim/v2/{slug}/Groups
func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	startIndex := 1
	if s := r.URL.Query().Get("startIndex"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			startIndex = v
		}
	}

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Check for filter parameter
	if filterStr := r.URL.Query().Get("filter"); filterStr != "" {
		h.listGroupsFiltered(w, r, provider, filterStr, startIndex, baseURL)
		return
	}

	// List all SCIM group mappings for this provider
	mappings, err := h.store.Queries().ListSCIMGroupMappings(ctx, provider.ID)
	if err != nil {
		h.logger.Error("failed to list SCIM group mappings", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}

	resources := make([]any, 0, len(mappings))
	for _, m := range mappings {
		group, err := h.buildGroupResource(ctx, m, baseURL)
		if err != nil {
			h.logger.Error("failed to build group resource", "mapping_id", m.ID, "error", err)
			continue
		}
		resources = append(resources, group)
	}

	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: len(resources),
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// listGroupsFiltered handles filtered group list requests.
func (h *Handler) listGroupsFiltered(w http.ResponseWriter, r *http.Request, provider db.IdentityProvidersProjection, filterStr string, startIndex int, baseURL string) {
	f, err := parseFilter(filterStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid filter: %s", err))
		return
	}

	ctx := r.Context()
	var resources []any

	switch f.Attribute {
	case "displayName":
		// Search by display name — iterate through mappings
		mappings, err := h.store.Queries().ListSCIMGroupMappings(ctx, provider.ID)
		if err != nil {
			h.logger.Error("failed to list SCIM group mappings for filter", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to search groups")
			return
		}

		for _, m := range mappings {
			if m.ScimDisplayName == f.Value {
				group, err := h.buildGroupResource(ctx, m, baseURL)
				if err != nil {
					continue
				}
				resources = append(resources, group)
			}
		}

	case "externalId":
		mapping, err := h.store.Queries().GetSCIMGroupMapping(ctx, db.GetSCIMGroupMappingParams{
			ProviderID:  provider.ID,
			ScimGroupID: f.Value,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				resources = []any{}
			} else {
				h.logger.Error("failed to find SCIM group mapping", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to search groups")
				return
			}
		} else {
			group, err := h.buildGroupResource(ctx, mapping, baseURL)
			if err != nil {
				h.logger.Error("failed to build group resource", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to build group")
				return
			}
			resources = []any{group}
		}

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported filter attribute for groups: %s", f.Attribute))
		return
	}

	if resources == nil {
		resources = []any{}
	}

	writeJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: len(resources),
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// createGroup handles POST /scim/v2/{slug}/Groups
func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var scimGroup SCIMGroup
	if err := json.NewDecoder(r.Body).Decode(&scimGroup); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if scimGroup.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "displayName is required")
		return
	}

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	scimGroupID := scimGroup.ExternalID
	if scimGroupID == "" {
		// Use the SCIM-generated ID as the SCIM group ID if no external ID
		scimGroupID = scimGroup.ID
	}
	if scimGroupID == "" {
		scimGroupID = newULID()
	}

	// Check if this SCIM group is already mapped
	existing, err := h.store.Queries().GetSCIMGroupMapping(ctx, db.GetSCIMGroupMappingParams{
		ProviderID:  provider.ID,
		ScimGroupID: scimGroupID,
	})
	if err == nil {
		// Already exists — update display name if changed and return existing resource.
		// This makes POST idempotent, which handles SCIM clients that re-POST on every sync.
		if existing.ScimDisplayName != scimGroup.DisplayName {
			h.appendEvent(ctx, store.Event{
				StreamType: "scim_group_mapping",
				StreamID:   existing.ID,
				EventType:  "SCIMGroupMappingUpdated",
				Data: map[string]any{
					"provider_id":       provider.ID,
					"scim_group_id":     scimGroupID,
					"scim_display_name": scimGroup.DisplayName,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
			h.appendEvent(ctx, store.Event{
				StreamType: "user_group",
				StreamID:   existing.UserGroupID,
				EventType:  "UserGroupUpdated",
				Data: map[string]any{
					"name": scimGroup.DisplayName,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
		}

		// Reconcile members if provided
		if len(scimGroup.Members) > 0 {
			h.reconcileGroupMembers(ctx, provider, existing.UserGroupID, scimGroup.Members)
		}

		group, err := h.buildGroupResource(ctx, existing, baseURL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to build group resource")
			return
		}
		writeJSON(w, http.StatusOK, group)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		h.logger.Error("failed to check existing SCIM group mapping", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Create the user group
	userGroupID := newULID()
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   userGroupID,
		EventType:  "UserGroupCreated",
		Data: map[string]any{
			"name":        scimGroup.DisplayName,
			"description": fmt.Sprintf("SCIM-provisioned group from %s", provider.Name),
		},
		ActorType: "scim",
		ActorID:   provider.ID,
	})
	if err != nil {
		h.logger.Error("failed to create user group via SCIM", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create group")
		return
	}

	// Create the SCIM group mapping
	mappingID := newULID()
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping",
		StreamID:   mappingID,
		EventType:  "SCIMGroupMapped",
		Data: map[string]any{
			"provider_id":       provider.ID,
			"scim_group_id":     scimGroupID,
			"scim_display_name": scimGroup.DisplayName,
			"user_group_id":     userGroupID,
		},
		ActorType: "scim",
		ActorID:   provider.ID,
	})
	if err != nil {
		h.logger.Error("failed to create SCIM group mapping", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to map SCIM group")
		return
	}

	// Add members if provided
	for _, member := range scimGroup.Members {
		if member.Value == "" {
			continue
		}
		streamID := userGroupID + ":" + member.Value
		h.appendEvent(ctx, store.Event{
			StreamType: "user_group",
			StreamID:   streamID,
			EventType:  "UserGroupMemberAdded",
			Data: map[string]any{
				"group_id": userGroupID,
				"user_id":  member.Value,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		})
	}

	// Build response
	mapping, err := h.store.Queries().GetSCIMGroupMapping(ctx, db.GetSCIMGroupMappingParams{
		ProviderID:  provider.ID,
		ScimGroupID: scimGroupID,
	})
	if err != nil {
		// Fall back to a minimal response
		writeJSON(w, http.StatusCreated, SCIMGroup{
			Schemas:     []string{GroupSchema},
			ID:          userGroupID,
			ExternalID:  scimGroupID,
			DisplayName: scimGroup.DisplayName,
			Meta: &SCIMMeta{
				ResourceType: "Group",
				Location:     baseURL + "/Groups/" + userGroupID,
			},
		})
		return
	}

	group, err := h.buildGroupResource(ctx, mapping, baseURL)
	if err != nil {
		h.logger.Error("failed to build group resource after create", "error", err)
		writeJSON(w, http.StatusCreated, SCIMGroup{
			Schemas:     []string{GroupSchema},
			ID:          userGroupID,
			ExternalID:  scimGroupID,
			DisplayName: scimGroup.DisplayName,
		})
		return
	}

	writeJSON(w, http.StatusCreated, group)
}

// getGroup handles GET /scim/v2/{slug}/Groups/{id}
func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	groupID := r.PathValue("id")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing group id")
		return
	}

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Look up the SCIM group mapping by user_group_id
	mapping, err := h.store.Queries().GetSCIMGroupMappingByUserGroup(ctx, db.GetSCIMGroupMappingByUserGroupParams{
		ProviderID:  provider.ID,
		UserGroupID: groupID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("failed to get SCIM group mapping", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	group, err := h.buildGroupResource(ctx, mapping, baseURL)
	if err != nil {
		h.logger.Error("failed to build group resource", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to build group")
		return
	}

	writeJSON(w, http.StatusOK, group)
}

// replaceGroup handles PUT /scim/v2/{slug}/Groups/{id}
func (h *Handler) replaceGroup(w http.ResponseWriter, r *http.Request) {
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	groupID := r.PathValue("id")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing group id")
		return
	}

	var scimGroup SCIMGroup
	if err := json.NewDecoder(r.Body).Decode(&scimGroup); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Look up the SCIM group mapping
	mapping, err := h.store.Queries().GetSCIMGroupMappingByUserGroup(ctx, db.GetSCIMGroupMappingByUserGroupParams{
		ProviderID:  provider.ID,
		UserGroupID: groupID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("failed to get SCIM group mapping for replace", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	// Update display name if changed
	if scimGroup.DisplayName != "" && scimGroup.DisplayName != mapping.ScimDisplayName {
		h.appendEvent(ctx, store.Event{
			StreamType: "scim_group_mapping",
			StreamID:   mapping.ID,
			EventType:  "SCIMGroupMappingUpdated",
			Data: map[string]any{
				"provider_id":       provider.ID,
				"scim_group_id":     mapping.ScimGroupID,
				"scim_display_name": scimGroup.DisplayName,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		})

		h.appendEvent(ctx, store.Event{
			StreamType: "user_group",
			StreamID:   groupID,
			EventType:  "UserGroupUpdated",
			Data: map[string]any{
				"name": scimGroup.DisplayName,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		})
	}

	// Reconcile members
	h.reconcileGroupMembers(ctx, provider, groupID, scimGroup.Members)

	// Read back and return
	updatedMapping, err := h.store.Queries().GetSCIMGroupMappingByUserGroup(ctx, db.GetSCIMGroupMappingByUserGroupParams{
		ProviderID:  provider.ID,
		UserGroupID: groupID,
	})
	if err != nil {
		updatedMapping = mapping
	}

	group, err := h.buildGroupResource(ctx, updatedMapping, baseURL)
	if err != nil {
		h.logger.Error("failed to build group resource after replace", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to build group")
		return
	}

	writeJSON(w, http.StatusOK, group)
}

// patchGroup handles PATCH /scim/v2/{slug}/Groups/{id}
func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request) {
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	groupID := r.PathValue("id")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing group id")
		return
	}

	var patch SCIMPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Verify group exists
	mapping, err := h.store.Queries().GetSCIMGroupMappingByUserGroup(ctx, db.GetSCIMGroupMappingByUserGroupParams{
		ProviderID:  provider.ID,
		UserGroupID: groupID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("failed to get SCIM group mapping for patch", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	for _, op := range patch.Operations {
		switch strings.ToLower(op.Op) {
		case "add":
			h.handleGroupPatchAdd(ctx, provider, groupID, op)
		case "remove":
			h.handleGroupPatchRemove(ctx, provider, groupID, op)
		case "replace":
			h.handleGroupPatchReplace(ctx, provider, groupID, mapping, op)
		default:
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported patch op: %s", op.Op))
			return
		}
	}

	// Read back and return
	updatedMapping, err := h.store.Queries().GetSCIMGroupMappingByUserGroup(ctx, db.GetSCIMGroupMappingByUserGroupParams{
		ProviderID:  provider.ID,
		UserGroupID: groupID,
	})
	if err != nil {
		updatedMapping = mapping
	}

	group, err := h.buildGroupResource(ctx, updatedMapping, baseURL)
	if err != nil {
		h.logger.Error("failed to build group resource after patch", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to build group")
		return
	}

	writeJSON(w, http.StatusOK, group)
}

// handleGroupPatchAdd processes an "add" patch operation on a group.
func (h *Handler) handleGroupPatchAdd(ctx context.Context, provider db.IdentityProvidersProjection, groupID string, op SCIMPatchOp) {
	path := strings.ToLower(op.Path)
	if path != "members" && path != "" {
		return
	}

	members := extractMembers(op.Value)
	for _, userID := range members {
		streamID := groupID + ":" + userID
		h.appendEvent(ctx, store.Event{
			StreamType: "user_group",
			StreamID:   streamID,
			EventType:  "UserGroupMemberAdded",
			Data: map[string]any{
				"group_id": groupID,
				"user_id":  userID,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		})
	}
}

// handleGroupPatchRemove processes a "remove" patch operation on a group.
func (h *Handler) handleGroupPatchRemove(ctx context.Context, provider db.IdentityProvidersProjection, groupID string, op SCIMPatchOp) {
	path := strings.ToLower(op.Path)

	// Handle path like: members[value eq "userId"]
	if strings.HasPrefix(path, "members[") {
		// Extract user ID from the ORIGINAL path to preserve case
		userID := extractUserIDFromMemberFilter(op.Path)
		if userID != "" {
			streamID := groupID + ":" + userID
			h.appendEvent(ctx, store.Event{
				StreamType: "user_group",
				StreamID:   streamID,
				EventType:  "UserGroupMemberRemoved",
				Data: map[string]any{
					"group_id": groupID,
					"user_id":  userID,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
		}
		return
	}

	// Handle path "members" with value containing member list
	if path == "members" || path == "" {
		members := extractMembers(op.Value)
		for _, userID := range members {
			streamID := groupID + ":" + userID
			h.appendEvent(ctx, store.Event{
				StreamType: "user_group",
				StreamID:   streamID,
				EventType:  "UserGroupMemberRemoved",
				Data: map[string]any{
					"group_id": groupID,
					"user_id":  userID,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
		}
	}
}

// handleGroupPatchReplace processes a "replace" patch operation on a group.
func (h *Handler) handleGroupPatchReplace(ctx context.Context, provider db.IdentityProvidersProjection, groupID string, mapping db.ScimGroupMappingProjection, op SCIMPatchOp) {
	path := strings.ToLower(op.Path)

	switch path {
	case "displayname":
		name, ok := op.Value.(string)
		if !ok || name == "" {
			return
		}

		h.appendEvent(ctx, store.Event{
			StreamType: "scim_group_mapping",
			StreamID:   mapping.ID,
			EventType:  "SCIMGroupMappingUpdated",
			Data: map[string]any{
				"provider_id":       provider.ID,
				"scim_group_id":     mapping.ScimGroupID,
				"scim_display_name": name,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		})

		h.appendEvent(ctx, store.Event{
			StreamType: "user_group",
			StreamID:   groupID,
			EventType:  "UserGroupUpdated",
			Data: map[string]any{
				"name": name,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		})

	case "members":
		// Full member replacement
		members := extractMembers(op.Value)
		requestedSet := make(map[string]bool, len(members))
		for _, id := range members {
			requestedSet[id] = true
		}

		currentMemberIDs, err := h.store.Queries().ListUserGroupMemberIDs(ctx, groupID)
		if err != nil {
			return
		}

		currentSet := make(map[string]bool, len(currentMemberIDs))
		for _, id := range currentMemberIDs {
			currentSet[id] = true
		}

		// Add new members
		for _, userID := range members {
			if !currentSet[userID] {
				streamID := groupID + ":" + userID
				h.appendEvent(ctx, store.Event{
					StreamType: "user_group",
					StreamID:   streamID,
					EventType:  "UserGroupMemberAdded",
					Data: map[string]any{
						"group_id": groupID,
						"user_id":  userID,
					},
					ActorType: "scim",
					ActorID:   provider.ID,
				})
			}
		}

		// Remove old members
		for _, userID := range currentMemberIDs {
			if !requestedSet[userID] {
				streamID := groupID + ":" + userID
				h.appendEvent(ctx, store.Event{
					StreamType: "user_group",
					StreamID:   streamID,
					EventType:  "UserGroupMemberRemoved",
					Data: map[string]any{
						"group_id": groupID,
						"user_id":  userID,
					},
					ActorType: "scim",
					ActorID:   provider.ID,
				})
			}
		}
	}
}

// deleteGroup handles DELETE /scim/v2/{slug}/Groups/{id}
func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	groupID := r.PathValue("id")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing group id")
		return
	}

	ctx := r.Context()

	// Look up the mapping
	mapping, err := h.store.Queries().GetSCIMGroupMappingByUserGroup(ctx, db.GetSCIMGroupMappingByUserGroupParams{
		ProviderID:  provider.ID,
		UserGroupID: groupID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("failed to get SCIM group mapping for delete", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	// Remove the SCIM group mapping (do NOT delete the user group itself)
	err = h.store.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping",
		StreamID:   mapping.ID,
		EventType:  "SCIMGroupUnmapped",
		Data: map[string]any{
			"provider_id":   provider.ID,
			"scim_group_id": mapping.ScimGroupID,
		},
		ActorType: "scim",
		ActorID:   provider.ID,
	})
	if err != nil {
		h.logger.Error("failed to unmap SCIM group", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete group mapping")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// reconcileGroupMembers diffs the requested members against current members and
// emits add/remove events as needed.
func (h *Handler) reconcileGroupMembers(ctx context.Context, provider db.IdentityProvidersProjection, groupID string, requestedMembers []SCIMMember) {
	currentMemberIDs, err := h.store.Queries().ListUserGroupMemberIDs(ctx, groupID)
	if err != nil {
		h.logger.Error("failed to list current group members for reconciliation", "error", err)
		return
	}

	currentSet := make(map[string]bool, len(currentMemberIDs))
	for _, id := range currentMemberIDs {
		currentSet[id] = true
	}

	requestedSet := make(map[string]bool, len(requestedMembers))
	for _, m := range requestedMembers {
		if m.Value != "" {
			requestedSet[m.Value] = true
		}
	}

	// Add new members
	for userID := range requestedSet {
		if !currentSet[userID] {
			streamID := groupID + ":" + userID
			h.appendEvent(ctx, store.Event{
				StreamType: "user_group",
				StreamID:   streamID,
				EventType:  "UserGroupMemberAdded",
				Data: map[string]any{
					"group_id": groupID,
					"user_id":  userID,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
		}
	}

	// Remove old members
	for _, userID := range currentMemberIDs {
		if !requestedSet[userID] {
			streamID := groupID + ":" + userID
			h.appendEvent(ctx, store.Event{
				StreamType: "user_group",
				StreamID:   streamID,
				EventType:  "UserGroupMemberRemoved",
				Data: map[string]any{
					"group_id": groupID,
					"user_id":  userID,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
		}
	}
}

// buildGroupResource constructs a SCIMGroup from a mapping and its associated user group.
func (h *Handler) buildGroupResource(ctx context.Context, mapping db.ScimGroupMappingProjection, baseURL string) (SCIMGroup, error) {
	group, err := h.store.Queries().GetUserGroupWithMembers(ctx, mapping.UserGroupID)
	if err != nil {
		return SCIMGroup{}, fmt.Errorf("get user group: %w", err)
	}

	memberIDs, err := h.store.Queries().ListUserGroupMemberIDs(ctx, mapping.UserGroupID)
	if err != nil {
		return SCIMGroup{}, fmt.Errorf("list group members: %w", err)
	}

	members := make([]SCIMMember, 0, len(memberIDs))
	for _, uid := range memberIDs {
		member := SCIMMember{
			Value: uid,
			Ref:   baseURL + "/Users/" + uid,
		}
		// Try to get display name (email)
		u, err := h.store.Queries().GetUserByID(ctx, uid)
		if err == nil {
			member.Display = u.Email
		}
		members = append(members, member)
	}

	sg := SCIMGroup{
		Schemas:     []string{GroupSchema},
		ID:          mapping.UserGroupID,
		ExternalID:  mapping.ScimGroupID,
		DisplayName: group.Name,
		Members:     members,
		Meta: &SCIMMeta{
			ResourceType: "Group",
			Location:     baseURL + "/Groups/" + mapping.UserGroupID,
		},
	}

	if mapping.CreatedAt.Valid {
		sg.Meta.Created = mapping.CreatedAt.Time.Format(time.RFC3339)
	}
	if group.UpdatedAt.Valid {
		sg.Meta.LastModified = group.UpdatedAt.Time.Format(time.RFC3339)
	}

	return sg, nil
}

// extractMembers extracts user IDs from a SCIM members value.
// The value can be a single member object or an array of member objects.
func extractMembers(value any) []string {
	if value == nil {
		return nil
	}

	var userIDs []string

	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if uid, ok := m["value"].(string); ok && uid != "" {
					userIDs = append(userIDs, uid)
				}
			}
		}
	case map[string]any:
		if uid, ok := v["value"].(string); ok && uid != "" {
			userIDs = append(userIDs, uid)
		}
	}

	return userIDs
}

// extractUserIDFromMemberFilter extracts a user ID from a SCIM member filter path.
// Example: members[value eq "userId"] -> "userId"
// The function matches structural parts case-insensitively but preserves the value case.
func extractUserIDFromMemberFilter(path string) string {
	lower := strings.ToLower(path)
	if !strings.HasPrefix(lower, "members[") {
		return ""
	}

	// Use original path (not lowercased) to preserve user ID case
	inner := path[len("members["):]
	inner = strings.TrimSuffix(inner, "]")

	// Case-insensitive split on " eq "
	lowerInner := strings.ToLower(inner)
	idx := strings.Index(lowerInner, " eq ")
	if idx < 0 {
		return ""
	}

	value := strings.TrimSpace(inner[idx+4:])
	value = strings.Trim(value, "\"")
	return value
}
