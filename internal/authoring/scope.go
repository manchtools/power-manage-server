package authoring

import (
	"context"
	"fmt"
)

func (h *Handlers) directScopeGroups(ctx context.Context, objectType, id string) ([]string, error) {
	targets, err := h.store.ListAuthoringAssignmentTargets(ctx, objectType, id)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		var ids []string
		switch target.TargetType {
		case "device_group", "user_group":
			ids = []string{target.TargetID}
		case "device":
			ids, err = h.store.ListDeviceGroupIDs(ctx, target.TargetID)
		case "user":
			ids, err = h.store.ListUserGroupIDsForUser(ctx, target.TargetID)
		default:
			return nil, fmt.Errorf("authoring: unknown assignment target type %q", target.TargetType)
		}
		if err != nil {
			return nil, err
		}
		for _, groupID := range ids {
			if groupID != "" {
				seen[groupID] = struct{}{}
			}
		}
	}
	groups := make([]string, 0, len(seen))
	for id := range seen {
		groups = append(groups, id)
	}
	return groups, nil
}

func (h *Handlers) effectiveActionScopeGroups(ctx context.Context, actionID string) ([]string, error) {
	groups, err := h.directScopeGroups(ctx, "action", actionID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(groups))
	for _, id := range groups {
		seen[id] = struct{}{}
	}
	setIDs, err := h.store.ListContainingActionSetIDs(ctx, actionID)
	if err != nil {
		return nil, err
	}
	definitionIDs := make(map[string]struct{})
	for _, setID := range setIDs {
		setGroups, err := h.directScopeGroups(ctx, "action_set", setID)
		if err != nil {
			return nil, err
		}
		for _, id := range setGroups {
			seen[id] = struct{}{}
		}
		ids, err := h.store.ListContainingDefinitionIDs(ctx, setID)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			definitionIDs[id] = struct{}{}
		}
	}
	for definitionID := range definitionIDs {
		definitionGroups, err := h.directScopeGroups(ctx, "definition", definitionID)
		if err != nil {
			return nil, err
		}
		for _, id := range definitionGroups {
			seen[id] = struct{}{}
		}
	}
	groups = groups[:0]
	for id := range seen {
		groups = append(groups, id)
	}
	return groups, nil
}

func groupsOverlap(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(left))
	for _, id := range left {
		seen[id] = struct{}{}
	}
	for _, id := range right {
		if _, ok := seen[id]; ok {
			return true
		}
	}
	return false
}
