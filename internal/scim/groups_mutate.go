// SCIM replaceGroup / patchGroup / handleGroupPatch{Add,Remove,Replace}
// handlers. Extracted from groups.go (audit F009 / #149, slice 5) so
// groups.go stays under the issue's <500 LOC bar.
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
)

// replaceGroup handles PUT /scim/v2/{slug}/Groups/{id}
func (h *Handler) replaceGroup(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM replaceGroup called")
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
	limitBody(r)
	if err := json.NewDecoder(r.Body).Decode(&scimGroup); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Look up the SCIM group mapping
	mapping, err := h.store.Repos().SCIM.GetGroupMappingByUserGroup(ctx, store.SCIMGroupMappingByUserGroupKey{ProviderID: provider.ID, UserGroupID: groupID})
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("failed to get SCIM group mapping for replace", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	// Update display name if changed. The mapping-rename and user_group-rename
	// commit atomically (audit L7): the change guard reads the *mapping's* name,
	// so a partial apply (mapping renamed, user_group not) would let the retry
	// see equal names, skip the rename, and leave the user_group name stale
	// forever. AppendEvents makes both land or neither.
	if scimGroup.DisplayName != "" && scimGroup.DisplayName != mapping.SCIMDisplayName {
		if err := h.store.AppendEvents(ctx, []store.Event{
			{
				StreamType: "scim_group_mapping",
				StreamID:   mapping.ID,
				EventType:  string(eventtypes.SCIMGroupMappingUpdated),
				Data: payloads.SCIMGroupMappingUpdated{
					ProviderID:      provider.ID,
					SCIMGroupID:     mapping.SCIMGroupID,
					SCIMDisplayName: &scimGroup.DisplayName,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			},
			{
				StreamType: "user_group",
				StreamID:   groupID,
				EventType:  string(eventtypes.UserGroupUpdated),
				// nil Description = preserve the existing one (SCIM
				// only renames; the description is server-owned).
				Data: payloads.UserGroupUpdated{
					Name: scimGroup.DisplayName,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			},
		}); err != nil {
			h.logger.Error("failed to rename SCIM group", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to update group")
			return
		}
	}

	// Reconcile members if the field was present in the JSON body.
	// nil means the field was omitted (don't touch members).
	// Empty slice means explicitly empty (remove all members).
	// SCIM is treated as the source of truth for group membership.
	if scimGroup.Members != nil {
		if err := h.reconcileGroupMembers(ctx, provider, groupID, scimGroup.Members); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update group members")
			return
		}
	}

	// Read back and return
	updatedMapping, err := h.store.Repos().SCIM.GetGroupMappingByUserGroup(ctx, store.SCIMGroupMappingByUserGroupKey{ProviderID: provider.ID, UserGroupID: groupID})
	if err != nil {
		updatedMapping = mapping
	}

	group, err := h.buildGroupResource(ctx, provider.ID, updatedMapping, baseURL)
	if err != nil {
		h.logger.Error("failed to build group resource after replace", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to build group")
		return
	}

	writeJSON(w, http.StatusOK, group)
}

// patchGroup handles PATCH /scim/v2/{slug}/Groups/{id}
func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM patchGroup called")
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

	limitBody(r)
	var patch SCIMPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	baseURL := baseURLFromRequest(r, provider.Slug)

	// Verify group exists
	mapping, err := h.store.Repos().SCIM.GetGroupMappingByUserGroup(ctx, store.SCIMGroupMappingByUserGroupKey{ProviderID: provider.ID, UserGroupID: groupID})
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("failed to get SCIM group mapping for patch", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get group")
		return
	}

	for _, op := range patch.Operations {
		// Pre-validate per RFC 7644 §3.5.2 — `op` must be one of
		// add | remove | replace. Reject up front so unknown verbs
		// never silently fall through to a per-op switch default
		// elsewhere in the codebase.
		if !op.Op.IsValid() {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported patch op: %s", op.Op))
			return
		}
		var opErr error
		switch op.Op.Normalize() {
		case SCIMPatchOpAdd:
			opErr = h.handleGroupPatchAdd(ctx, provider, groupID, op)
		case SCIMPatchOpRemove:
			opErr = h.handleGroupPatchRemove(ctx, provider, groupID, op)
		case SCIMPatchOpReplace:
			opErr = h.handleGroupPatchReplace(ctx, provider, groupID, mapping, op)
		default:
			// Unreachable: IsValid above guards this switch.
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported patch op: %s", op.Op))
			return
		}
		if opErr != nil {
			h.logger.Error("failed to apply SCIM group patch op", "op", op.Op, "path", op.Path, "error", opErr)
			writeError(w, http.StatusInternalServerError, "failed to apply patch operation")
			return
		}
	}

	// Read back and return
	updatedMapping, err := h.store.Repos().SCIM.GetGroupMappingByUserGroup(ctx, store.SCIMGroupMappingByUserGroupKey{ProviderID: provider.ID, UserGroupID: groupID})
	if err != nil {
		updatedMapping = mapping
	}

	group, err := h.buildGroupResource(ctx, provider.ID, updatedMapping, baseURL)
	if err != nil {
		h.logger.Error("failed to build group resource after patch", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to build group")
		return
	}

	writeJSON(w, http.StatusOK, group)
}

// handleGroupPatchAdd processes an "add" patch operation on a group. Fails
// closed (audit L7); per-member appends are ON CONFLICT-idempotent so a retry
// after a partial apply converges.
func (h *Handler) handleGroupPatchAdd(ctx context.Context, provider store.IdentityProvider, groupID string, op SCIMPatchOp) error {
	path := strings.ToLower(op.Path)
	if path != "members" && path != "" {
		return nil
	}

	members := extractMembers(op.Value)
	for _, userID := range members {
		if !h.mayAddMemberToGroup(ctx, provider.ID, groupID, userID) {
			continue
		}
		streamID := groupID + ":" + userID
		if err := h.appendEvent(ctx, store.Event{
			StreamType: "user_group",
			StreamID:   streamID,
			EventType:  string(eventtypes.UserGroupMemberAdded),
			Data: payloads.UserGroupMemberAdded{
				GroupID: groupID,
				UserID:  userID,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		}); err != nil {
			return err
		}
	}
	return nil
}

// handleGroupPatchRemove processes a "remove" patch operation on a group. Fails
// closed (audit L7); per-member removals are idempotent so a retry converges.
func (h *Handler) handleGroupPatchRemove(ctx context.Context, provider store.IdentityProvider, groupID string, op SCIMPatchOp) error {
	path := strings.ToLower(op.Path)

	// Handle path like: members[value eq "userId"]
	if strings.HasPrefix(path, "members[") {
		// Extract user ID from the ORIGINAL path to preserve case
		userID := extractUserIDFromMemberFilter(op.Path)
		if userID != "" {
			streamID := groupID + ":" + userID
			return h.appendEvent(ctx, store.Event{
				StreamType: "user_group",
				StreamID:   streamID,
				EventType:  string(eventtypes.UserGroupMemberRemoved),
				Data: payloads.UserGroupMemberRemoved{
					GroupID: groupID,
					UserID:  userID,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			})
		}
		return nil
	}

	// Handle path "members" with value containing member list
	if path == "members" || path == "" {
		members := extractMembers(op.Value)
		for _, userID := range members {
			streamID := groupID + ":" + userID
			if err := h.appendEvent(ctx, store.Event{
				StreamType: "user_group",
				StreamID:   streamID,
				EventType:  string(eventtypes.UserGroupMemberRemoved),
				Data: payloads.UserGroupMemberRemoved{
					GroupID: groupID,
					UserID:  userID,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// handleGroupPatchReplace processes a "replace" patch operation on a group.
// Fails closed (audit L7). The displayname rename commits its mapping+user_group
// events atomically via AppendEvents (same reason as replaceGroup); the member
// add/remove appends are ON CONFLICT-idempotent so a retry converges.
func (h *Handler) handleGroupPatchReplace(ctx context.Context, provider store.IdentityProvider, groupID string, mapping store.SCIMGroupMapping, op SCIMPatchOp) error {
	path := strings.ToLower(op.Path)

	switch path {
	case "displayname":
		name, ok := op.Value.(string)
		if !ok || name == "" {
			return nil
		}

		return h.store.AppendEvents(ctx, []store.Event{
			{
				StreamType: "scim_group_mapping",
				StreamID:   mapping.ID,
				EventType:  string(eventtypes.SCIMGroupMappingUpdated),
				Data: payloads.SCIMGroupMappingUpdated{
					ProviderID:      provider.ID,
					SCIMGroupID:     mapping.SCIMGroupID,
					SCIMDisplayName: &name,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			},
			{
				StreamType: "user_group",
				StreamID:   groupID,
				EventType:  string(eventtypes.UserGroupUpdated),
				// nil Description = preserve (SCIM only renames).
				Data: payloads.UserGroupUpdated{
					Name: name,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			},
		})

	case "members":
		// Full member replacement
		members := extractMembers(op.Value)
		requestedSet := make(map[string]bool, len(members))
		for _, id := range members {
			requestedSet[id] = true
		}

		currentMemberIDs, err := h.store.Repos().UserGroup.ListMemberIDs(ctx, groupID)
		if err != nil {
			h.logger.Error("failed to list group members for patch replace", "group_id", groupID, "error", err)
			return err
		}

		currentSet := make(map[string]bool, len(currentMemberIDs))
		for _, id := range currentMemberIDs {
			currentSet[id] = true
		}

		// Add new members
		for _, userID := range members {
			if !currentSet[userID] {
				if !h.mayAddMemberToGroup(ctx, provider.ID, groupID, userID) {
					continue
				}
				h.logger.Debug("SCIM adding member to group", "group_id", groupID, "user_id", userID)
				streamID := groupID + ":" + userID
				if err := h.appendEvent(ctx, store.Event{
					StreamType: "user_group",
					StreamID:   streamID,
					EventType:  string(eventtypes.UserGroupMemberAdded),
					Data: payloads.UserGroupMemberAdded{
						GroupID: groupID,
						UserID:  userID,
					},
					ActorType: "scim",
					ActorID:   provider.ID,
				}); err != nil {
					return err
				}
			}
		}

		// Remove old members
		for _, userID := range currentMemberIDs {
			if !requestedSet[userID] {
				h.logger.Debug("SCIM removing member from group", "group_id", groupID, "user_id", userID)
				streamID := groupID + ":" + userID
				if err := h.appendEvent(ctx, store.Event{
					StreamType: "user_group",
					StreamID:   streamID,
					EventType:  string(eventtypes.UserGroupMemberRemoved),
					Data: payloads.UserGroupMemberRemoved{
						GroupID: groupID,
						UserID:  userID,
					},
					ActorType: "scim",
					ActorID:   provider.ID,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
