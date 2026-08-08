package dispatch

import (
	"context"
	"errors"
	"fmt"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/assignment"
	"github.com/manchtools/power-manage/server/internal/authoring"
)

var errAssignedSourceNotVisible = errors.New("assigned source is outside caller scope")

func (h *Handlers) assignedManifests(ctx context.Context, deviceID string) ([]ManifestInput, error) {
	paths, err := h.store.ListResolvedSources(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	sources, err := assignment.ResolveSources(paths)
	if err != nil {
		return nil, err
	}
	byType := make(map[string][]assignment.ResolvedSource)
	for _, source := range sources {
		byType[source.Row.SourceType] = append(byType[source.Row.SourceType], source)
	}

	inputs := make([]ManifestInput, 0)
	absorbedSets := make(map[string]struct{})
	absorbedActions := make(map[string]struct{})
	emittedActions := make(map[string]struct{})

	for _, source := range byType["definition"] {
		if !source.Active && !source.Excluded {
			continue
		}
		sets, err := h.store.ListManifestDefinitionActionSets(ctx, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		for _, set := range sets {
			absorbedSets[set.ID] = struct{}{}
		}
		actions, err := h.store.ListManifestDefinitionActions(ctx, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		for _, action := range actions {
			absorbedActions[action.Action.ID] = struct{}{}
		}
		if !source.Active {
			continue
		}
		visible, err := authoring.DefinitionVisibleToCaller(ctx, h.store, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		if !visible {
			return nil, errAssignedSourceNotVisible
		}
		compiled, err := h.compiler.DefinitionForDevice(ctx, deviceID, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		for _, item := range compiled {
			forceAbsent(item, source.ForceAbsent)
			inputs = append(inputs, ManifestInput{Manifest: item, PersistActionIDs: true})
			rememberManifestActions(emittedActions, item)
		}
	}

	for _, source := range byType["action_set"] {
		if _, absorbed := absorbedSets[source.Row.SourceID]; absorbed || (!source.Active && !source.Excluded) {
			continue
		}
		actions, err := h.store.ListManifestActionSetActions(ctx, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		for _, action := range actions {
			absorbedActions[action.ID] = struct{}{}
		}
		if !source.Active {
			continue
		}
		visible, err := authoring.ActionSetVisibleToCaller(ctx, h.store, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		if !visible {
			return nil, errAssignedSourceNotVisible
		}
		compiled, err := h.compiler.ActionSetForDevice(ctx, deviceID, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		forceAbsent(compiled, source.ForceAbsent)
		inputs = append(inputs, ManifestInput{Manifest: compiled, PersistActionIDs: true})
		rememberManifestActions(emittedActions, compiled)
	}

	blockedActions := make(map[string]struct{})
	for _, source := range byType["action"] {
		if source.Excluded {
			blockedActions[source.Row.SourceID] = struct{}{}
		}
		if !source.Active {
			continue
		}
		if _, absorbed := absorbedActions[source.Row.SourceID]; absorbed {
			continue
		}
		visible, err := authoring.ActionVisibleToCaller(ctx, h.store, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		if !visible {
			return nil, errAssignedSourceNotVisible
		}
		compiled, err := h.compiler.ActionForDevice(ctx, deviceID, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		forceAbsent(compiled, source.ForceAbsent)
		inputs = append(inputs, ManifestInput{Manifest: compiled, PersistActionIDs: true})
		rememberManifestActions(emittedActions, compiled)
	}

	for _, source := range byType["compliance_policy"] {
		if !source.Active {
			continue
		}
		rules, err := h.store.ListCompliancePolicyRules(ctx, source.Row.SourceID)
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			if _, blocked := blockedActions[rule.ActionID]; blocked {
				continue
			}
			if _, absorbed := absorbedActions[rule.ActionID]; absorbed {
				continue
			}
			if _, emitted := emittedActions[rule.ActionID]; emitted {
				continue
			}
			visible, err := authoring.ActionVisibleToCaller(ctx, h.store, rule.ActionID)
			if err != nil {
				return nil, err
			}
			if !visible {
				return nil, errAssignedSourceNotVisible
			}
			compiled, err := h.compiler.ActionForDevice(ctx, deviceID, rule.ActionID)
			if err != nil {
				return nil, err
			}
			forceAbsent(compiled, source.ForceAbsent)
			inputs = append(inputs, ManifestInput{Manifest: compiled, PersistActionIDs: true})
			rememberManifestActions(emittedActions, compiled)
		}
	}

	for sourceType := range byType {
		switch sourceType {
		case "action", "action_set", "definition", "compliance_policy":
		default:
			return nil, fmt.Errorf("unknown assigned source type %q", sourceType)
		}
	}
	return inputs, nil
}

func forceAbsent(compiled *pmv1.Manifest, enabled bool) {
	if !enabled {
		return
	}
	for _, occurrence := range compiled.Occurrences {
		occurrence.Action.DesiredState = pmv1.DesiredState_DESIRED_STATE_ABSENT
	}
}

func rememberManifestActions(seen map[string]struct{}, compiled *pmv1.Manifest) {
	for _, occurrence := range compiled.Occurrences {
		seen[occurrence.Action.Id.Value] = struct{}{}
	}
}
