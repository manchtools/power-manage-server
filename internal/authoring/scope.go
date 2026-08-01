package authoring

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

func (h *Handlers) directScopeGroups(ctx context.Context, objectType, id string) ([]string, error) {
	return directScopeGroups(ctx, h.store, objectType, id)
}

func directScopeGroups(ctx context.Context, st *store.Store, objectType, id string) ([]string, error) {
	targets, err := st.ListAuthoringAssignmentTargets(ctx, objectType, id)
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
			ids, err = st.ListDeviceGroupIDs(ctx, target.TargetID)
		case "user":
			ids, err = st.ListUserGroupIDsForUser(ctx, target.TargetID)
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

func effectiveActionScopeGroups(ctx context.Context, st *store.Store, actionID string) ([]string, error) {
	groups, err := directScopeGroups(ctx, st, "action", actionID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(groups))
	for _, id := range groups {
		seen[id] = struct{}{}
	}
	setIDs, err := st.ListContainingActionSetIDs(ctx, actionID)
	if err != nil {
		return nil, err
	}
	definitionIDs := make(map[string]struct{})
	for _, setID := range setIDs {
		setGroups, err := directScopeGroups(ctx, st, "action_set", setID)
		if err != nil {
			return nil, err
		}
		for _, id := range setGroups {
			seen[id] = struct{}{}
		}
		ids, err := st.ListContainingDefinitionIDs(ctx, setID)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			definitionIDs[id] = struct{}{}
		}
	}
	for definitionID := range definitionIDs {
		definitionGroups, err := directScopeGroups(ctx, st, "definition", definitionID)
		if err != nil {
			return nil, err
		}
		for _, id := range definitionGroups {
			seen[id] = struct{}{}
		}
	}
	policyIDs, err := st.ListCompliancePolicyIDsForAction(ctx, actionID)
	if err != nil {
		return nil, err
	}
	for _, policyID := range policyIDs {
		policyGroups, err := directScopeGroups(ctx, st, "compliance_policy", policyID)
		if err != nil {
			return nil, err
		}
		for _, id := range policyGroups {
			seen[id] = struct{}{}
		}
	}
	groups = groups[:0]
	for id := range seen {
		groups = append(groups, id)
	}
	return groups, nil
}

// ActionVisibleToCaller reports whether an Action belongs to a restricted
// caller's effective transitive object scope. Global callers are visible by
// definition; existence is checked separately by the handler.
func ActionVisibleToCaller(ctx context.Context, st *store.Store, actionID string) (bool, error) {
	if ctx == nil || st == nil {
		return false, fmt.Errorf("authoring: scope context and store are required")
	}
	callerGroups, restricted := auth.ObjectScopeListFilter(ctx)
	if !restricted {
		return true, nil
	}
	objectGroups, err := effectiveActionScopeGroups(ctx, st, actionID)
	if err != nil {
		return false, err
	}
	return groupsOverlap(callerGroups, objectGroups), nil
}

func (h *Handlers) effectiveActionSetScopeGroups(ctx context.Context, setID string) ([]string, error) {
	groups, err := h.directScopeGroups(ctx, "action_set", setID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(groups))
	for _, id := range groups {
		seen[id] = struct{}{}
	}
	definitionIDs, err := h.store.ListContainingDefinitionIDs(ctx, setID)
	if err != nil {
		return nil, err
	}
	for _, definitionID := range definitionIDs {
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
