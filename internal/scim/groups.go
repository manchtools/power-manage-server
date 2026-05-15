package scim

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// listGroups handles GET /scim/v2/{slug}/Groups
func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM listGroups called")
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
	mappings, err := h.store.Repos().SCIM.ListGroupMappings(ctx, provider.ID)
	if err != nil {
		h.logger.Error("failed to list SCIM group mappings", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}

	resources := make([]any, 0, len(mappings))
	for _, m := range mappings {
		group, err := h.buildGroupResource(ctx, provider.ID, m, baseURL)
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
func (h *Handler) listGroupsFiltered(w http.ResponseWriter, r *http.Request, provider store.IdentityProvider, filterStr string, startIndex int, baseURL string) {
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
		mappings, err := h.store.Repos().SCIM.ListGroupMappings(ctx, provider.ID)
		if err != nil {
			h.logger.Error("failed to list SCIM group mappings for filter", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to search groups")
			return
		}

		for _, m := range mappings {
			if m.SCIMDisplayName == f.Value {
				group, err := h.buildGroupResource(ctx, provider.ID, m, baseURL)
				if err != nil {
					h.logger.Error("failed to build group resource", "mapping_id", m.ID, "error", err)
					continue
				}
				resources = append(resources, group)
			}
		}

	case "externalId":
		mapping, err := h.store.Repos().SCIM.GetGroupMapping(ctx, store.SCIMGroupMappingKey{ProviderID: provider.ID, SCIMGroupID: f.Value})
		if err != nil {
			if store.IsNotFound(err) {
				resources = []any{}
			} else {
				h.logger.Error("failed to find SCIM group mapping", "error", err)
				writeError(w, http.StatusInternalServerError, "failed to search groups")
				return
			}
		} else {
			group, err := h.buildGroupResource(ctx, provider.ID, mapping, baseURL)
			if err != nil {
				resources = []any{}
				h.logger.Error("failed to build group resource", "mapping_id", mapping.ID, "error", err)
			} else {
				resources = []any{group}
			}
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
// getGroup handles GET /scim/v2/{slug}/Groups/{id}
func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM getGroup called")
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
	mapping, err := h.store.Repos().SCIM.GetGroupMappingByUserGroup(ctx, store.SCIMGroupMappingByUserGroupKey{ProviderID: provider.ID, UserGroupID: groupID})
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("failed to get SCIM group mapping", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	group, err := h.buildGroupResource(ctx, provider.ID, mapping, baseURL)
	if err != nil {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}

	writeJSON(w, http.StatusOK, group)
}

// replaceGroup handles PUT /scim/v2/{slug}/Groups/{id}
// deleteGroup handles DELETE /scim/v2/{slug}/Groups/{id}
func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM deleteGroup called")
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
	mapping, err := h.store.Repos().SCIM.GetGroupMappingByUserGroup(ctx, store.SCIMGroupMappingByUserGroupKey{ProviderID: provider.ID, UserGroupID: groupID})
	if err != nil {
		if store.IsNotFound(err) {
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
		EventType:  string(eventtypes.SCIMGroupUnmapped),
		Data: map[string]any{
			"provider_id":   provider.ID,
			"scim_group_id": mapping.SCIMGroupID,
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
// reconcileGroupMembers / buildGroupResource / restoreOrphanedGroup +
// extractMembers / extractUserIDFromMemberFilter live in groups_helpers.go.
