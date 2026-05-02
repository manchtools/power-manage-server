package resolution

import (
	"context"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// Mode integer values match pm.AssignmentMode in the proto.
const (
	ModeRequired  = 0
	ModeAvailable = 1
	ModeExcluded  = 2
	ModeUninstall = 3
)

// TreeQuerier is the subset of sqlc-generated queries the device-sync
// tree resolver depends on. Decoupled from Querier so tests can stub
// just the tree path.
type TreeQuerier interface {
	ListReachedDefinitionsForDevice(ctx context.Context, targetID string) ([]db.ListReachedDefinitionsForDeviceRow, error)
	ListReachedActionSetsForDevice(ctx context.Context, targetID string) ([]db.ListReachedActionSetsForDeviceRow, error)
	ListReachedActionAssignmentsForDevice(ctx context.Context, targetID string) ([]db.ListReachedActionAssignmentsForDeviceRow, error)
	ListDefinitionMembers(ctx context.Context, definitionID string) ([]db.ListDefinitionMembersRow, error)
	ListActionSetMembers(ctx context.Context, setID string) ([]db.ListActionSetMembersRow, error)
	GetActionByID(ctx context.Context, id string) (db.ActionsProjection, error)
}

// ReachedDefinition is a definition reaching the device, with the mode
// collapsed across all assignment paths (direct + via group) at the
// definition layer.
type ReachedDefinition struct {
	ID            string
	Name          string
	Schedule      []byte
	EffectiveMode int32
}

// ReachedSet is an action set reaching the device. Sets that are members
// of any reached definition are absorbed by that definition and excluded
// from this list (see ResolveDeviceTree).
type ReachedSet struct {
	ID            string
	Name          string
	Schedule      []byte
	EffectiveMode int32
}

// ReachedActionAssignment is an action with at least one direct assignment
// reaching the device. Actions absorbed by a reached set or definition
// are excluded from this list.
type ReachedActionAssignment struct {
	ID            string
	EffectiveMode int32
}

// TreeStandaloneAction is one direct-action assignment that survived
// the tree's absorption rules. The Mode is the action-layer assignment
// mode (already EXCLUDED-filtered upstream); the handler uses it to
// force ABSENT for UNINSTALL.
type TreeStandaloneAction struct {
	ActionID string
	Mode     int32
}

// DeviceTree is the result of the new layered resolution: a mix of
// container groups (each with one schedule and an ordered list of
// member actions) and standalone actions (each with its own schedule).
//
// Groups always come from a reached definition or a reached
// standalone-set. Standalone actions come from action-layer assignments
// not absorbed by any reached set or definition.
type DeviceTree struct {
	StandaloneActions []TreeStandaloneAction

	// Groups is built definition-first, then standalone-set, both in
	// (Name, ID) order from the underlying queries. Within a definition
	// group, sets walk in member sort_order and actions walk in member
	// sort_order. Same action_id may appear at multiple positions when
	// multiple sets in the same definition include it.
	Groups []DeviceTreeGroup

	// Action lookup keyed by action_id. Wire conversion happens in the
	// handler so this package stays free of proto dependencies.
	Actions map[string]db.ActionsProjection
}

// DeviceTreeGroup is one container's worth of actions sharing one
// schedule. Mode is the container's collapsed mode, used by the handler
// to decide UNINSTALL → ABSENT override (EXCLUDED groups are omitted
// upstream).
type DeviceTreeGroup struct {
	SourceLabel string // "definition:<ulid>" or "action_set:<ulid>"
	Schedule    []byte
	Mode        int32
	ActionIDs   []string // in declared order; duplicates allowed
}

// ResolveDeviceTree builds the device-layer sync tree using the new
// layered precedence (definition > action_set > action).
//
// Mode collapse within a layer follows EXCLUDED > UNINSTALL > REQUIRED >
// AVAILABLE — same priority as the per-action resolver, just applied at
// each container level. EXCLUDED at the winning container removes the
// action from the tree. UNINSTALL at the winning container is signalled
// via the group's Mode (or via the wrapping handler for standalone
// actions) so the desired_state can be forced to ABSENT downstream.
//
// Standalone actions are returned as a flat list of action_ids; the
// handler emits each on SyncActionsResponse.standalone_actions with the
// action's own ActionSchedule.
//
// User-layer assignments and the permission-derived TTY actions are NOT
// included here — they continue to flow through the existing flat
// resolver and are merged into standalone_actions by the caller.
func ResolveDeviceTree(ctx context.Context, q TreeQuerier, deviceID string) (DeviceTree, error) {
	defs, err := q.ListReachedDefinitionsForDevice(ctx, deviceID)
	if err != nil {
		return DeviceTree{}, err
	}
	sets, err := q.ListReachedActionSetsForDevice(ctx, deviceID)
	if err != nil {
		return DeviceTree{}, err
	}
	actionAssns, err := q.ListReachedActionAssignmentsForDevice(ctx, deviceID)
	if err != nil {
		return DeviceTree{}, err
	}

	tree := DeviceTree{Actions: map[string]db.ActionsProjection{}}

	// Pre-fetch members of each reached definition and each reached set.
	// We need them twice: (1) to compute absorbed sets / actions, (2) to
	// walk into groups. Cache to avoid duplicate queries.
	defMembersByID := make(map[string][]db.ListDefinitionMembersRow, len(defs))
	for _, d := range defs {
		members, err := q.ListDefinitionMembers(ctx, d.ID)
		if err != nil {
			return DeviceTree{}, err
		}
		defMembersByID[d.ID] = members
	}

	setMembersByID := make(map[string][]db.ListActionSetMembersRow)
	getSetMembers := func(setID string) ([]db.ListActionSetMembersRow, error) {
		if m, ok := setMembersByID[setID]; ok {
			return m, nil
		}
		m, err := q.ListActionSetMembers(ctx, setID)
		if err != nil {
			return nil, err
		}
		setMembersByID[setID] = m
		return m, nil
	}

	// Sets absorbed by a reached definition — these don't appear at the
	// standalone-set layer regardless of any direct set assignment.
	absorbedSets := make(map[string]bool)
	for _, d := range defs {
		for _, dm := range defMembersByID[d.ID] {
			absorbedSets[dm.ActionSetID] = true
		}
	}

	// Actions absorbed by any set the device reaches (definition-bound
	// or standalone) — these don't appear at the standalone-action layer.
	absorbedActions := make(map[string]bool)
	registerSetActions := func(setID string) error {
		members, err := getSetMembers(setID)
		if err != nil {
			return err
		}
		for _, am := range members {
			absorbedActions[am.ActionID] = true
		}
		return nil
	}
	for setID := range absorbedSets {
		if err := registerSetActions(setID); err != nil {
			return DeviceTree{}, err
		}
	}
	for _, s := range sets {
		if absorbedSets[s.ID] {
			continue // already accounted for via the def path
		}
		if err := registerSetActions(s.ID); err != nil {
			return DeviceTree{}, err
		}
	}

	cacheAction := func(id string) error {
		if _, ok := tree.Actions[id]; ok {
			return nil
		}
		a, err := q.GetActionByID(ctx, id)
		if err != nil {
			// Action gone (deleted between reach query and lookup) is
			// non-fatal — drop silently from this resolution.
			return nil
		}
		tree.Actions[id] = a
		return nil
	}

	// Definition groups.
	for _, d := range defs {
		if d.EffectiveMode == ModeExcluded {
			continue
		}
		group := DeviceTreeGroup{
			SourceLabel: "definition:" + d.ID,
			Schedule:    d.Schedule,
			Mode:        d.EffectiveMode,
		}
		for _, dm := range defMembersByID[d.ID] {
			members, err := getSetMembers(dm.ActionSetID)
			if err != nil {
				return DeviceTree{}, err
			}
			for _, am := range members {
				if err := cacheAction(am.ActionID); err != nil {
					return DeviceTree{}, err
				}
				if _, ok := tree.Actions[am.ActionID]; !ok {
					continue
				}
				group.ActionIDs = append(group.ActionIDs, am.ActionID)
			}
		}
		if len(group.ActionIDs) > 0 {
			tree.Groups = append(tree.Groups, group)
		}
	}

	// Standalone-set groups.
	for _, s := range sets {
		if absorbedSets[s.ID] {
			continue
		}
		if s.EffectiveMode == ModeExcluded {
			continue
		}
		group := DeviceTreeGroup{
			SourceLabel: "action_set:" + s.ID,
			Schedule:    s.Schedule,
			Mode:        s.EffectiveMode,
		}
		members, err := getSetMembers(s.ID)
		if err != nil {
			return DeviceTree{}, err
		}
		for _, am := range members {
			if err := cacheAction(am.ActionID); err != nil {
				return DeviceTree{}, err
			}
			if _, ok := tree.Actions[am.ActionID]; !ok {
				continue
			}
			group.ActionIDs = append(group.ActionIDs, am.ActionID)
		}
		if len(group.ActionIDs) > 0 {
			tree.Groups = append(tree.Groups, group)
		}
	}

	// Standalone actions: action-layer assignments not absorbed by any
	// reached set or definition. EXCLUDED at the action layer drops the
	// action; UNINSTALL is encoded by setting desired_state to ABSENT in
	// the wrapping handler.
	for _, aa := range actionAssns {
		if absorbedActions[aa.ID] {
			continue
		}
		if aa.EffectiveMode == ModeExcluded {
			continue
		}
		if err := cacheAction(aa.ID); err != nil {
			return DeviceTree{}, err
		}
		if _, ok := tree.Actions[aa.ID]; !ok {
			continue
		}
		tree.StandaloneActions = append(tree.StandaloneActions, TreeStandaloneAction{
			ActionID: aa.ID,
			Mode:     aa.EffectiveMode,
		})
	}

	return tree, nil
}
