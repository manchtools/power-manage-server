// SCIM group-flow helpers extracted from groups.go (audit F009 / #149,
// slice 3). Lifts the per-RPC support functions out of groups.go into
// this sibling file so groups.go stays focused on the per-RPC HTTP
// handlers (list / get / create / replace / patch / delete).
package scim

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// reconcileGroupMembers diff's the requested member set against the
// current member set and emits per-user UserGroupMemberAdded /
// UserGroupMemberRemoved events. Idempotent — calling with the same
// member set twice produces no second-round events.
func (h *Handler) reconcileGroupMembers(ctx context.Context, provider store.IdentityProvider, groupID string, requestedMembers []SCIMMember) {
	h.logger.Debug("SCIM reconcileGroupMembers", "group_id", groupID, "requested_count", len(requestedMembers))
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

	h.logger.Debug("SCIM reconcileGroupMembers diff", "group_id", groupID, "current_count", len(currentMemberIDs), "requested_count", len(requestedSet))
	// Add new members
	for userID := range requestedSet {
		if !currentSet[userID] {
			h.logger.Debug("SCIM adding member to group", "group_id", groupID, "user_id", userID)
			streamID := groupID + ":" + userID
			h.appendEvent(ctx, store.Event{
				StreamType: "user_group",
				StreamID:   streamID,
				EventType:  string(eventtypes.UserGroupMemberAdded),
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
			h.logger.Debug("SCIM removing member from group", "group_id", groupID, "user_id", userID)
			streamID := groupID + ":" + userID
			h.appendEvent(ctx, store.Event{
				StreamType: "user_group",
				StreamID:   streamID,
				EventType:  string(eventtypes.UserGroupMemberRemoved),
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
// If the user group was deleted but the mapping still exists (orphaned), it re-creates
// the user group and updates the mapping to restore consistency.
func (h *Handler) buildGroupResource(ctx context.Context, providerID string, mapping db.ScimGroupMappingProjection, baseURL string) (SCIMGroup, error) {
	group, err := h.store.Queries().GetUserGroupWithMembers(ctx, mapping.UserGroupID)
	if store.IsNotFound(err) {
		// User group was deleted but SCIM mapping still exists — restore it.
		mapping, err = h.restoreOrphanedGroup(ctx, providerID, mapping)
		if err != nil {
			return SCIMGroup{}, fmt.Errorf("restore orphaned group: %w", err)
		}
		group, err = h.store.Queries().GetUserGroupWithMembers(ctx, mapping.UserGroupID)
	}
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

	sg.Meta.Created = mapping.CreatedAt.Format(time.RFC3339)
	sg.Meta.LastModified = group.UpdatedAt.Format(time.RFC3339)

	return sg, nil
}

// restoreOrphanedGroup re-creates the user group and updates the SCIM mapping
// when the original user group was deleted but the SCIM mapping still exists.
func (h *Handler) restoreOrphanedGroup(ctx context.Context, providerID string, m db.ScimGroupMappingProjection) (db.ScimGroupMappingProjection, error) {
	h.logger.Warn("restoring orphaned SCIM group: re-creating user group",
		"mapping_id", m.ID, "user_group_id", m.UserGroupID, "display_name", m.ScimDisplayName)

	newGroupID := newULID()
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "user_group",
		StreamID:   newGroupID,
		EventType:  string(eventtypes.UserGroupCreated),
		Data: map[string]any{
			"name":        m.ScimDisplayName,
			"description": "SCIM-provisioned group (restored)",
		},
		ActorType: "scim",
		ActorID:   providerID,
	}); err != nil {
		return m, fmt.Errorf("create user group: %w", err)
	}

	// Remove old mapping
	h.appendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping",
		StreamID:   m.ID,
		EventType:  string(eventtypes.SCIMGroupUnmapped),
		Data: map[string]any{
			"provider_id":   providerID,
			"scim_group_id": m.ScimGroupID,
		},
		ActorType: "scim",
		ActorID:   providerID,
	})

	// Create new mapping pointing to the new user group
	newMappingID := newULID()
	if err := h.store.AppendEvent(ctx, store.Event{
		StreamType: "scim_group_mapping",
		StreamID:   newMappingID,
		EventType:  string(eventtypes.SCIMGroupMapped),
		Data: map[string]any{
			"provider_id":       providerID,
			"scim_group_id":     m.ScimGroupID,
			"scim_display_name": m.ScimDisplayName,
			"user_group_id":     newGroupID,
		},
		ActorType: "scim",
		ActorID:   providerID,
	}); err != nil {
		return m, fmt.Errorf("create mapping: %w", err)
	}

	newMapping, err := h.store.Queries().GetSCIMGroupMapping(ctx, db.GetSCIMGroupMappingParams{
		ProviderID:  providerID,
		ScimGroupID: m.ScimGroupID,
	})
	if err != nil {
		return m, fmt.Errorf("read new mapping: %w", err)
	}

	return newMapping, nil
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
