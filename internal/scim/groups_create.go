// SCIM createGroup handler. Extracted from groups.go (audit F009 /
// #149, slice 5) so groups.go stays under the issue's <500 LOC bar.
//
// createGroup is the most-branched group handler — handles SCIM
// clients that re-POST on every sync cycle by syncing display name
// + members on idempotent re-POST instead of returning 409.
package scim

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// createGroup handles POST /scim/v2/{slug}/Groups
func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("SCIM createGroup called")
	provider, ok := providerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var scimGroup SCIMGroup
	limitBody(r)
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
	existing, err := h.store.Repos().SCIM.GetGroupMapping(ctx, store.SCIMGroupMappingKey{ProviderID: provider.ID, SCIMGroupID: scimGroupID})
	if err == nil {
		// Already exists — update display name if changed and return existing resource.
		h.logger.Debug("SCIM createGroup: group already exists, syncing", "scim_group_id", scimGroupID, "user_group_id", existing.UserGroupID)
		// This makes POST idempotent, which handles SCIM clients that re-POST on every sync.
		// The mapping-rename and user_group-rename commit atomically (audit L7):
		// the change guard reads the *mapping's* name, so a partial apply would
		// let the retry see equal names, skip, and leave the user_group name stale
		// forever. AppendEvents makes both land or neither.
		if existing.SCIMDisplayName != scimGroup.DisplayName {
			if err := h.store.AppendEvents(ctx, []store.Event{
				{
					StreamType: "scim_group_mapping",
					StreamID:   existing.ID,
					EventType:  string(eventtypes.SCIMGroupMappingUpdated),
					Data: payloads.SCIMGroupMappingUpdated{
						ProviderID:      provider.ID,
						SCIMGroupID:     scimGroupID,
						SCIMDisplayName: &scimGroup.DisplayName,
					},
					ActorType: "scim",
					ActorID:   provider.ID,
				},
				{
					StreamType: "user_group",
					StreamID:   existing.UserGroupID,
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
		if scimGroup.Members != nil {
			if err := h.reconcileGroupMembers(ctx, provider, existing.UserGroupID, scimGroup.Members); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to update group members")
				return
			}
		}

		group, err := h.buildGroupResource(ctx, provider.ID, existing, baseURL)
		if err != nil {
			// User group referenced by mapping no longer exists.
			// Remove the orphaned mapping and fall through to create
			// a fresh group+mapping pair below. Fail closed on the unmap
			// (audit L7): swallowing it and falling through would create a
			// SECOND mapping for the same scim_group_id alongside the stale
			// one — two mappings for one SCIM group.
			h.logger.Warn("orphaned SCIM group mapping, removing and recreating",
				"mapping_id", existing.ID, "user_group_id", existing.UserGroupID, "error", err)
			if err := h.appendEvent(ctx, store.Event{
				StreamType: "scim_group_mapping",
				StreamID:   existing.ID,
				EventType:  string(eventtypes.SCIMGroupUnmapped),
				Data: payloads.SCIMGroupUnmapped{
					ProviderID:  provider.ID,
					SCIMGroupID: existing.SCIMGroupID,
				},
				ActorType: "scim",
				ActorID:   provider.ID,
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to remove orphaned group mapping")
				return
			}
			// Fall through to create a new group below
		} else {
			writeJSON(w, http.StatusOK, group)
			return
		}
	}
	if !store.IsNotFound(err) && err != nil {
		h.logger.Error("failed to check existing SCIM group mapping", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Create the group as one atomic unit (spec 28): the UserGroupCreated,
	// SCIMGroupMapped and per-member events either all commit or none do.
	// Independent appends could leave an orphan user_group with no
	// mapping if the mapping append failed — the IdP's next sync then
	// misses the mapping-keyed dedup, creates a *second* group, and
	// leaks the first permanently.
	h.logger.Debug("SCIM createGroup: creating new group", "scim_group_id", scimGroupID, "display_name", scimGroup.DisplayName)
	userGroupID := newULID()
	mappingID := newULID()
	events := []store.Event{
		{
			StreamType: "user_group",
			StreamID:   userGroupID,
			EventType:  string(eventtypes.UserGroupCreated),
			Data: payloads.UserGroupCreated{
				Name:        scimGroup.DisplayName,
				Description: fmt.Sprintf("SCIM-provisioned group from %s", provider.Name),
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		},
		{
			StreamType: "scim_group_mapping",
			StreamID:   mappingID,
			EventType:  string(eventtypes.SCIMGroupMapped),
			Data: payloads.SCIMGroupMapped{
				ProviderID:      provider.ID,
				SCIMGroupID:     scimGroupID,
				SCIMDisplayName: &scimGroup.DisplayName,
				UserGroupID:     userGroupID,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		},
	}

	// Members join the same atomic batch — a group provisioned without
	// its requested members is also partial state. Validity checks
	// (empty-skip, cross-provider) run here, before the batch, so only a
	// genuine DB failure rolls the whole create back.
	for _, member := range scimGroup.Members {
		if member.Value == "" {
			continue
		}
		if !h.mayAddMemberToGroup(ctx, provider.ID, userGroupID, member.Value) {
			continue
		}
		events = append(events, store.Event{
			StreamType: "user_group",
			StreamID:   userGroupID + ":" + member.Value,
			EventType:  string(eventtypes.UserGroupMemberAdded),
			Data: payloads.UserGroupMemberAdded{
				GroupID: userGroupID,
				UserID:  member.Value,
			},
			ActorType: "scim",
			ActorID:   provider.ID,
		})
	}

	if err := h.store.AppendEvents(ctx, events); err != nil {
		h.logger.Error("failed to create SCIM group", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create group")
		return
	}

	// Build response
	mapping, err := h.store.Repos().SCIM.GetGroupMapping(ctx, store.SCIMGroupMappingKey{ProviderID: provider.ID, SCIMGroupID: scimGroupID})
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

	group, err := h.buildGroupResource(ctx, provider.ID, mapping, baseURL)
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
