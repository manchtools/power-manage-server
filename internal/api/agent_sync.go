package api

import (
	"context"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/resolution"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// SyncActions returns every action resolved for a device, each carrying a
// CA-signed envelope bound to that device.
//
// Signing happens at DELIVERY, not creation: the dispatch rewrite stopped
// create-time signing, so the autonomous sync path re-signs per device. A nil
// signer is therefore a wiring bug that must fail loudly — every action would
// otherwise ship with an empty signature that the offline agent rejects, which
// looks like "no actions apply" rather than "the server is misconfigured".
//
// Spec 41 removed one field from the response: lps_public_key, the CA-signed
// key agents sealed LPS passwords to. That key existed so a relaying gateway
// could not read or substitute the passwords in flight. With no relay the
// agent sends them over its own mTLS stream and control encrypts at rest, so
// there is no longer a key to distribute.
func (h *AgentOps) SyncActions(ctx context.Context, deviceID string) (*pm.SyncActionsResponse, error) {
	if deviceID == "" {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "device_id is required")
	}
	if h.signer == nil {
		h.logger.Error("sync actions: nil signer — wiring bug", "device_id", deviceID)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "action signer not configured")
	}
	if _, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: deviceID}); err != nil {
		h.logger.Warn("sync actions for unknown/deleted device", "device_id", deviceID)
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found or deleted")
	}

	// Device-layer tree (groups + standalone) with container-wins precedence.
	tree, err := resolution.ResolveDeviceTree(ctx, h.store.Queries(), deviceID)
	if err != nil {
		h.logger.Error("failed to resolve device tree", "device_id", deviceID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve actions")
	}

	// User-layer assignments and permission-derived TTY actions still flow
	// through the flat resolver and ride on standalone_actions. Its
	// device-layer results are filtered against the tree below to avoid
	// emitting the same action twice.
	dbActions, err := resolution.ResolveActionsForDevice(ctx, h.store.Queries(), deviceID)
	if err != nil {
		h.logger.Error("failed to resolve actions", "device_id", deviceID, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to resolve actions")
	}

	syncInterval, err := h.store.Repos().Device.SyncInterval(ctx, deviceID)
	if err != nil {
		h.logger.Warn("failed to get sync interval, using default", "device_id", deviceID, "error", err)
		syncInterval = 0
	}

	covered := make(map[string]bool, len(tree.Actions))
	for id := range tree.Actions {
		covered[id] = true
	}

	standalone := make([]*pm.Action, 0, len(tree.StandaloneActions)+len(dbActions))
	for _, sa := range tree.StandaloneActions {
		raw, ok := tree.Actions[sa.ActionID]
		if !ok {
			continue
		}
		// Fold UNINSTALL → ABSENT into the desired state we SIGN, not just the
		// advisory wire field: the agent executes the verified envelope, so the
		// container's intent must ride inside the signed bytes or it is a no-op
		// the verifier never sees.
		desiredState := raw.DesiredState
		if sa.Mode == resolution.ModeUninstall {
			desiredState = int32(pm.DesiredState_DESIRED_STATE_ABSENT)
		}
		wire, err := dbActionToWireAction(raw, h.signer, deviceID, desiredState)
		if err != nil {
			// Fail closed: skip an action whose params will not parse or whose
			// envelope will not sign, rather than syncing invalid params or an
			// empty signature (#368).
			h.logger.Warn("skipping standalone action with unparseable params or unsignable envelope",
				"action_id", raw.ID, "error", err)
			continue
		}
		standalone = append(standalone, wire)
	}

	for _, dbAction := range dbActions {
		if covered[dbAction.ID] {
			continue
		}
		action, err := dbResolvedActionToWireAction(dbAction, h.signer, deviceID)
		if err != nil {
			h.logger.Warn("skipping resolved action with unparseable params or unsignable envelope",
				"action_id", dbAction.ID, "error", err)
			continue
		}
		standalone = append(standalone, action)
	}

	groups := make([]*pm.ActionGroup, 0, len(tree.Groups))
	for _, g := range tree.Groups {
		groupActions := make([]*pm.Action, 0, len(g.ActionIDs))
		for _, id := range g.ActionIDs {
			raw, ok := tree.Actions[id]
			if !ok {
				continue
			}
			desiredState := raw.DesiredState
			if g.Mode == resolution.ModeUninstall {
				desiredState = int32(pm.DesiredState_DESIRED_STATE_ABSENT)
			}
			wire, err := dbActionToWireAction(raw, h.signer, deviceID, desiredState)
			if err != nil {
				h.logger.Warn("skipping group action with unparseable params or unsignable envelope",
					"action_id", raw.ID, "error", err)
				continue
			}
			groupActions = append(groupActions, wire)
		}
		if len(groupActions) == 0 {
			continue
		}
		groups = append(groups, &pm.ActionGroup{
			SourceLabel: g.SourceLabel,
			Schedule:    actionparams.ScheduleFromJSON(g.Schedule),
			Actions:     groupActions,
		})
	}

	// Union of maintenance windows across every group reaching the device.
	// nil means no constraint, and the proto field stays unset so the agent
	// skips the gate entirely rather than treating an empty window as "never".
	windowRows, err := h.store.Queries().ListMaintenanceWindowsForDevice(ctx, deviceID)
	if err != nil {
		h.logger.Warn("failed to load maintenance windows for sync; falling back to no constraint",
			"device_id", deviceID, "error", err)
	}

	return &pm.SyncActionsResponse{
		StandaloneActions:   standalone,
		GroupedActions:      groups,
		SyncIntervalMinutes: syncInterval,
		MaintenanceWindow:   resolveMaintenanceWindowUnion(windowRows),
	}, nil
}

// dbActionToWireAction converts a raw actions_projection row to wire format,
// signing the envelope for deviceID.
//
// effectiveDesiredState lets the caller fold a container-mode override
// (UNINSTALL → ABSENT) INTO the signed envelope rather than only the advisory
// wire field. The typed-params oneof and schedule stay populated as advisory
// metadata for the offline scheduler, but the agent executes the VERIFIED
// envelope, so the signed bytes are the source of truth.
//
// executionID = a.ID: a synced action has no execution yet (the agent mints one
// when it runs the action offline), so the action's own id binds the envelope,
// mirroring the dispatch path where the fresh execution id binds it.
func dbActionToWireAction(a db.ActionsProjection, signer ca.ActionSigner, deviceID string, effectiveDesiredState int32) (*pm.Action, error) {
	action := &pm.Action{
		Id:             &pm.ActionId{Value: a.ID},
		Type:           pm.ActionType(a.ActionType),
		DesiredState:   pm.DesiredState(effectiveDesiredState),
		TimeoutSeconds: a.TimeoutSeconds,
	}
	if len(a.Params) > 0 {
		if err := actionparams.PopulateAction(action, a.ActionType, a.Params); err != nil {
			return nil, err
		}
	}
	if len(a.Schedule) > 0 {
		action.Schedule = actionparams.ScheduleFromJSON(a.Schedule)
	}

	envelopeBytes, signature, err := actionparams.BuildAndSignEnvelope(
		signer, a.ID, a.ActionType, a.Params, effectiveDesiredState, a.TimeoutSeconds, action.Schedule, deviceID,
	)
	if err != nil {
		return nil, err
	}
	action.SignedEnvelope = envelopeBytes
	action.Signature = signature
	return action, nil
}

// dbResolvedActionToWireAction is the flat-resolver counterpart, keeping the
// per-action desired state rather than a container override.
func dbResolvedActionToWireAction(a db.ListResolvedActionsForDeviceRow, signer ca.ActionSigner, deviceID string) (*pm.Action, error) {
	action := &pm.Action{
		Id:             &pm.ActionId{Value: a.ID},
		Type:           pm.ActionType(a.ActionType),
		DesiredState:   pm.DesiredState(a.DesiredState),
		TimeoutSeconds: a.TimeoutSeconds,
	}
	if len(a.Params) > 0 {
		if err := actionparams.PopulateAction(action, a.ActionType, a.Params); err != nil {
			return nil, err
		}
	}
	if len(a.Schedule) > 0 {
		action.Schedule = actionparams.ScheduleFromJSON(a.Schedule)
	}

	envelopeBytes, signature, err := actionparams.BuildAndSignEnvelope(
		signer, a.ID, a.ActionType, a.Params, a.DesiredState, a.TimeoutSeconds, action.Schedule, deviceID,
	)
	if err != nil {
		return nil, err
	}
	action.SignedEnvelope = envelopeBytes
	action.Signature = signature
	return action, nil
}
