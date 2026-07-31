package scim

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
)

// A directory group is a MAPPING onto a local user group, not a group
// of its own. The local group is what carries role grants, so the two
// are kept as separate rows: unmapping a directory group must not
// destroy the authority an operator attached to it.

// listGroups handles GET /Groups.
func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	baseURL := baseURLFromRequest(r, s.provider.Slug)
	startIndex, _ := pageWindow(r)

	mappings, err := h.store.ListSCIMGroupMappings(ctx, s.provider.ID)
	if err != nil {
		h.logger.Error("scim: failed to list group mappings", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}

	if expr := r.URL.Query().Get("filter"); expr != "" {
		mappings, err = filterGroupMappings(mappings, expr)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid filter: %s", err))
			return
		}
	}

	resources := make([]any, 0, len(mappings))
	for _, m := range mappings {
		resource, err := h.groupResource(ctx, m, baseURL)
		if err != nil {
			if store.IsNotFound(err) {
				// The local group was retired outside this surface. The
				// mapping is stale and is reported as absent; the
				// directory's next create re-establishes the pair.
				continue
			}
			h.logger.Error("scim: failed to build group resource", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to list groups")
			return
		}
		resources = append(resources, resource)
	}

	if !h.recordListRead(ctx, w, s, "LIST_GROUPS", int64(len(resources))) {
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

// filterGroupMappings applies the equality filters a directory uses to
// find a group it may already have mapped.
func filterGroupMappings(mappings []store.SCIMGroupMappingRow, expr string) ([]store.SCIMGroupMappingRow, error) {
	f, err := parseFilter(expr)
	if err != nil {
		return nil, err
	}
	var match func(store.SCIMGroupMappingRow) bool
	switch f.Attribute {
	case "displayName":
		match = func(m store.SCIMGroupMappingRow) bool { return m.ScimDisplayName == f.Value }
	case "externalId":
		match = func(m store.SCIMGroupMappingRow) bool { return m.ScimGroupID == f.Value }
	default:
		return nil, fmt.Errorf("unsupported filter attribute for groups: %s", f.Attribute)
	}
	out := make([]store.SCIMGroupMappingRow, 0, len(mappings))
	for _, m := range mappings {
		if match(m) {
			out = append(out, m)
		}
	}
	return out, nil
}

// getGroup handles GET /Groups/{id}.
func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	mapping, ok := h.resolveGroup(ctx, w, s, r.PathValue("id"))
	if !ok {
		return
	}
	resource, err := h.groupResource(ctx, mapping, baseURLFromRequest(r, s.provider.Slug))
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("scim: failed to build group resource", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	members := int64(len(resource.Members))
	if _, err := h.store.RecordOperation(ctx, h.sensitiveReadOp(s), store.AuditEffect{
		ResourceType: "user_group",
		ResourceID:   mapping.UserGroupID,
		Action:       "READ",
		Outcome:      store.EffectApplied,
		BeforeRef:    &s.provider.ID,
		AfterCount:   &members,
	}); err != nil {
		h.logger.Error("scim: failed to record sensitive read", "route", s.descriptor, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to record the read")
		return
	}
	writeJSON(w, http.StatusOK, resource)
}

// resolveGroup resolves the mapping this directory holds on a local
// group.
//
// A group mapped by a DIFFERENT directory and a group that does not
// exist get the same not-found answer, so the id space cannot be probed
// for another directory's groups.
func (h *Handler) resolveGroup(ctx context.Context, w http.ResponseWriter, s *session, groupID string) (store.SCIMGroupMappingRow, bool) {
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing group id")
		return store.SCIMGroupMappingRow{}, false
	}
	mapping, err := h.store.GetSCIMGroupMappingByUserGroup(ctx, s.provider.ID, groupID)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "group not found")
			return store.SCIMGroupMappingRow{}, false
		}
		h.logger.Error("scim: failed to resolve group mapping", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return store.SCIMGroupMappingRow{}, false
	}
	return mapping, true
}

// groupResource shapes a mapping and its local group as a SCIM group.
// ErrNotFound when the local group has been retired.
func (h *Handler) groupResource(ctx context.Context, mapping store.SCIMGroupMappingRow, baseURL string) (SCIMGroup, error) {
	group, err := h.store.GetUserGroup(ctx, mapping.UserGroupID)
	if err != nil {
		return SCIMGroup{}, err
	}
	memberIDs, err := h.store.ListUserGroupMemberIDs(ctx, mapping.UserGroupID)
	if err != nil {
		return SCIMGroup{}, err
	}

	members := make([]SCIMMember, 0, len(memberIDs))
	for _, userID := range memberIDs {
		member := SCIMMember{Value: userID, Ref: baseURL + "/Users/" + userID}
		if row, err := h.store.GetUser(ctx, userID); err == nil {
			member.Display = row.Email
		}
		members = append(members, member)
	}

	out := SCIMGroup{
		Schemas:     []string{GroupSchema},
		ID:          mapping.UserGroupID,
		ExternalID:  mapping.ScimGroupID,
		DisplayName: group.Name,
		Members:     members,
		Meta: &SCIMMeta{
			ResourceType: "Group",
			Location:     baseURL + "/Groups/" + mapping.UserGroupID,
			Created:      mapping.CreatedAt.Format(time.RFC3339),
			LastModified: group.UpdatedAt.Format(time.RFC3339),
		},
	}
	return out, nil
}
