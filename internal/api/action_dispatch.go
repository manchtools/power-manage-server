// Package api file action_dispatch.go — Dispatch* / execution-state
// RPCs extracted from action_handler.go (audit F005). Owns the
// dispatch fan-outs (DispatchAction, DispatchToMultiple,
// DispatchAssignedActions, DispatchActionSet, DispatchDefinition,
// DispatchToGroup, DispatchInstantAction), the in-flight execution
// reads (GetExecution, ListExecutions), and the cancel + queue-side
// taskqueue payload construction. Single-action CRUD lives in
// action_crud.go.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// DispatchAction dispatches an action to a device.
func (h *ActionHandler) DispatchAction(ctx context.Context, req *connect.Request[pm.DispatchActionRequest]) (*connect.Response[pm.DispatchActionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "DispatchAction", req.Msg.DeviceId); err != nil {
		return nil, err
	}

	// Existence check — the row itself is now only consumed by the
	// post-commit search listener, which reloads it fresh. We keep the
	// load here to fail fast with NotFound before touching anything
	// heavier downstream.
	if _, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId}); err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	// dispatchInputs collects the values either branch of the
	// ActionSource oneof produces — the stored-action branch loads
	// them from the projection row, the inline-action branch lifts
	// them from the request payload. Downstream code (signing,
	// taskqueue payload, event data) reads from this struct so the
	// "where did this value come from" question has one answer.
	//
	// signature + paramsCanonical stay separate because they're
	// computed downstream by the re-sign step, not extracted from
	// either source branch. See manchtools/power-manage-server#165.
	type dispatchInputs struct {
		// actionType is the proto ActionType the agent dispatch
		// payload + ExecutionCreated event carry. Stored-action
		// branch reads from action.ActionType; inline branch reads
		// from action.Type.
		actionType pm.ActionType
		// desiredState defaults to PRESENT on the stored branch
		// (ad-hoc dispatch always asks for "make it so") and
		// follows the inline action's explicit desired_state on the
		// inline branch.
		desiredState pm.DesiredState
		// params is the action-params JSON carried verbatim into the
		// signed envelope and the typed ExecutionCreated/Scheduled
		// payload (json.RawMessage so the bytes are emitted as-is, no
		// re-encode). Stored branch lifts the projection row's JSONB
		// directly; inline branch marshals the request's params oneof.
		// An empty / malformed source defaults to `{}` so the sign site
		// never produces an unverifiable empty-params signature.
		params json.RawMessage
		// timeoutSeconds is clamped to a 300s default on the inline
		// branch when the request omits it; the stored branch trusts
		// whatever was persisted at create time.
		timeoutSeconds int32
		// actionID is non-nil only on the stored-action branch (the
		// projection row's primary key). The inline branch leaves
		// it nil so the dispatch event's `action_id` field is
		// omitted — there's no stored action to reference.
		actionID *string
	}

	var inputs dispatchInputs

	switch source := req.Msg.ActionSource.(type) {
	case *pm.DispatchActionRequest_ActionId:
		action, err := h.store.Repos().Action.Get(ctx, source.ActionId)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, apiErrorCtx(ctx, ErrActionNotFound, connect.CodeNotFound, "action not found")
			}
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action")
		}
		// Object read-scope (spec 29 S1): a scope-restricted admin must not be
		// able to execute a catalog action it cannot Get. Device scope alone
		// (enforced above) confines WHERE it runs, not WHICH object runs. Mirrors
		// the AddActionToSet/AddActionToPolicy read-scope gate. Out of scope →
		// NotFound (no existence leak).
		if err := enforceObjectReadScope(ctx, objScope(h.store), h.logger, "action", source.ActionId, ErrActionNotFound, "action not found"); err != nil {
			return nil, err
		}
		inputs.actionType = pm.ActionType(action.ActionType)
		inputs.desiredState = pm.DesiredState_DESIRED_STATE_PRESENT // Default for ad-hoc dispatch
		// The stored params JSONB is carried verbatim into the envelope
		// and the typed event payload. Guard against an empty / malformed
		// row so the sign site can't produce an empty-params signature.
		inputs.params = rawParamsOrEmpty(action.Params)
		inputs.timeoutSeconds = action.TimeoutSeconds
		inputs.actionID = &source.ActionId
		// Contract (closes #137 audit F002): always re-sign every
		// dispatch. action.Signature + action.ParamsCanonical on the
		// stored row are NOT consumed here — the re-sign step below
		// overwrites both with a fresh signature against the current
		// signing key. Reasons:
		//   1. The signing key may have rotated since the action was
		//      originally created. A stored signature would become
		//      unverifiable against the current public key the agent
		//      has cached.
		//   2. The agent's verification path doesn't accept "old"
		//      signatures — it always checks against whatever the
		//      current control-cert chain says.
		//   3. The cost of re-signing is one HMAC, dwarfed by the
		//      Asynq enqueue and the bidi-stream RTT.
		// The columns stay on the row as audit-history (the original
		// signature at create-time) but never round-trip into a
		// dispatch.

	case *pm.DispatchActionRequest_InlineAction:
		action := source.InlineAction
		// Run the same per-oneof validation Create applies, plus
		// the outer Action invariants (Type non-unspecified, timeout
		// bounds, schedule, params-match-type). validateInlineAction
		// also rejects nil — important, otherwise ExtractParamsMsg
		// below would panic on the typed-nil inner message.
		if err := validateInlineAction(ctx, action); err != nil {
			return nil, err
		}
		inputs.actionType = action.Type
		inputs.desiredState = action.DesiredState
		serialized, err := marshalInlineParams(actionparams.ExtractParamsMsg(action))
		if err != nil {
			h.logger.Warn("failed to serialize inline action params", "error", err)
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "failed to serialize inline action params")
		}
		inputs.params = serialized
		inputs.timeoutSeconds = action.TimeoutSeconds
		if inputs.timeoutSeconds <= 0 {
			inputs.timeoutSeconds = 300
		}

	default:
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "either action_id or inline_action is required")
	}

	id := ulid.Make().String()

	// Compute the deferred-dispatch delay. RunAt is optional; when set
	// it must be strictly in the future at scheduling time per the
	// proto contract (a past timestamp would race the deferred-vs-
	// immediate decision below).
	var dispatchDelay time.Duration
	if req.Msg.RunAt != nil {
		dispatchAt := req.Msg.RunAt.AsTime()
		dispatchDelay = time.Until(dispatchAt)
		if dispatchDelay <= 0 {
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "run_at must be in the future")
		}
	}

	// Note: req.Msg.RespectMaintenanceWindow used to be persisted on the
	// dispatch event under the comment "reserved for #58", but #58
	// (per-group maintenance windows) shipped via a separate enforcement
	// path and no execution projector ever read this field. Dropped in
	// audit N009 to stop writing dead bytes into the event store. The
	// proto field stays so existing API clients keep building; it now
	// has no server-side effect.

	// Fail fast when no task queue is configured. Without this
	// guard the handler used to silently write an ExecutionCreated
	// event, skip signing, and return success — leaving the row in
	// `pending` forever because no agent task was ever delivered.
	// Self-hosted deployments that forget to set CONTROL_VALKEY_ADDR
	// would have looked like dispatch worked. CodeFailedPrecondition
	// is the correct shape: it tells the client to fix their
	// deployment configuration rather than retry the call.
	//
	// Positioned here (after Validate + auth + device lookup + inline
	// validation) so body-level errors still surface with their own
	// code — a malformed request should see InvalidArgument, not get
	// shadowed by an infrastructure precondition.
	if h.aqClient == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeFailedPrecondition, "dispatch unavailable: task queue not configured")
	}

	// Sign the dispatch BEFORE writing the ExecutionCreated event.
	//
	// Previously the sequence was:  appendEvent → sign → enqueue.
	// Any failure after the event-write (sign fail, enqueue fail)
	// left an execution row in the DB that no agent task would ever
	// deliver — a zombie "pending forever" the operator had to cancel
	// by hand. Signing doesn't depend on the row existing (it hashes
	// `id`, `actionType`, `paramsJSON`), so we can fail fast here
	// before touching the DB.
	//
	// Nil signer is a wiring bug (main.go passes the real internal/ca
	// signer; tests pass NoOpSigner). Fail-closed to avoid silently
	// enqueueing unsigned tasks the agent would drop on receipt.
	if h.signer == nil {
		h.logger.Error("dispatch: nil signer — wiring bug", "execution_id", id)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "action signer not configured")
	}
	paramsJSON, marshalErr := json.Marshal(inputs.params)
	if marshalErr != nil {
		// `params` is either a map[string]any from extractActionParamsMsg
		// (proto → map via protojson) or a raw JSON string — both should
		// be safe to remarshal, but a json.Marshal error here MUST fail
		// closed. Silently enqueueing with nil paramsJSON would produce
		// an unverifiable signature and an empty-params task the agent
		// rejects on receipt.
		h.logger.Error("dispatch: failed to marshal params for signing",
			"execution_id", id, "error", marshalErr)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to marshal dispatch params")
	}
	// Build and sign the full SignedActionEnvelope. The bytes we sign are
	// the bytes we transport (envelopeBytes -> ActionDispatchPayload.
	// EnvelopeBytes) — the agent verifies and unmarshals the same bytes.
	// Ad-hoc dispatch carries no schedule (nil): the schedule field is
	// authoritative only on the autonomous sync path, not on a one-shot
	// dispatch.
	envelopeBytes, signature, signErr := actionparams.BuildAndSignEnvelope(
		h.signer,
		id,
		int32(inputs.actionType),
		paramsJSON,
		int32(inputs.desiredState),
		inputs.timeoutSeconds,
		nil, // schedule: not part of an ad-hoc dispatch
		req.Msg.DeviceId,
	)
	if signErr != nil {
		h.logger.Error("dispatch: failed to build/sign action envelope", "execution_id", id, "error", signErr)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to sign dispatched action")
	}

	// Choose ExecutionScheduled vs ExecutionCreated based on whether
	// the caller asked for a deferred dispatch. The two events are
	// projected to status='scheduled' / status='pending' respectively
	// and the row only diverges from there on the dispatch's outcome.
	// Both carry the typed payloads.Execution* shape (not an ad-hoc map)
	// so the emitted keys cannot drift from the projector contract.
	actionType := int32(inputs.actionType)
	desiredState := int32(inputs.desiredState)
	timeoutSeconds := inputs.timeoutSeconds
	initialEventType := string(eventtypes.ExecutionCreated)
	var eventData any = payloads.ExecutionCreated{
		DeviceID:       req.Msg.DeviceId,
		ActionID:       inputs.actionID,
		ActionType:     &actionType,
		DesiredState:   &desiredState,
		Params:         inputs.params,
		TimeoutSeconds: &timeoutSeconds,
	}
	if dispatchDelay > 0 {
		initialEventType = string(eventtypes.ExecutionScheduled)
		eventData = payloads.ExecutionScheduled{
			DeviceID:       req.Msg.DeviceId,
			ActionID:       inputs.actionID,
			ActionType:     &actionType,
			DesiredState:   &desiredState,
			Params:         inputs.params,
			TimeoutSeconds: &timeoutSeconds,
			ScheduledFor:   req.Msg.RunAt.AsTime().UTC().Format(time.RFC3339Nano),
		}
	}
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "execution",
		StreamID:   id,
		EventType:  initialEventType,
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to create execution"); err != nil {
		return nil, err
	}

	// Dispatch action to device via Asynq task queue. The row exists
	// now; if the enqueue fails we MUST transition it to a terminal
	// state so the projection reflects reality. Silently returning
	// success used to leave the row as `pending` indefinitely.
	//
	// For deferred dispatches the asynq.TaskID is set to the execution
	// id so CancelExecution can prune the scheduled task by that id.
	// asynq.ProcessIn schedules the worker to pick the task up after
	// dispatchDelay rather than immediately.
	//
	// h.aqClient is guaranteed non-nil here — the precondition check
	// at the top of DispatchAction rejects the call otherwise.
	enqueueOpts := []asynq.Option{asynq.MaxRetry(5)}
	if dispatchDelay > 0 {
		enqueueOpts = append(enqueueOpts, asynq.TaskID(id), asynq.ProcessIn(dispatchDelay))
	}
	if err := h.aqClient.EnqueueToDevice(req.Msg.DeviceId, taskqueue.TypeActionDispatch, taskqueue.ActionDispatchPayload{
		ExecutionID:   id,
		EnvelopeBytes: envelopeBytes,
		Signature:     signature,
	}, enqueueOpts...); err != nil {
		h.logger.Error("failed to enqueue action dispatch; emitting ExecutionFailed",
			"error", err, "execution_id", id)
		// Append a compensating ExecutionFailed event so the row
		// moves to a terminal state the operator can act on.
		// Best-effort: a failure here is logged but we still return
		// the enqueue error to the caller so they know the dispatch
		// did not reach the device.
		if failErr := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "execution",
			StreamID:   id,
			EventType:  string(eventtypes.ExecutionFailed),
			Data: payloads.ExecutionFailedCompensating{
				Error: fmt.Sprintf("dispatch enqueue failed: %v", err),
			},
			ActorType: "system",
			ActorID:   "system",
		}, "failed to append ExecutionFailed compensating event"); failErr != nil {
			h.logger.Error("compensating ExecutionFailed event failed; execution row is stuck in pending",
				"execution_id", id, "error", failErr)
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to enqueue action dispatch")
	}

	exec, err := h.store.Repos().Execution.Get(ctx, id)
	if err != nil {
		h.logger.Error("failed to get execution after creation", "error", err, "execution_id", id)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get execution")
	}

	// Execution search reindex is handled by api.SearchListener: the
	// listener fires on every Execution* event type and reloads the
	// projection through loadSearchEntityData.

	h.logger.Info("action dispatched",
		"execution_id", id,
		"device_id", req.Msg.DeviceId,
		"action_type", inputs.actionType.String(),
	)

	return connect.NewResponse(&pm.DispatchActionResponse{
		Execution: h.executionToProto(exec),
	}), nil
}

// enforceDeviceScopeAll confines a fan-out dispatch to the caller's device-group
// scope: every target device must be reachable under `perm` (base-tier scope),
// or the WHOLE request fails closed with the first denial. Dispatch is a
// mutating, potentially destructive action, so a partial/silent execution is
// worse than a clear denial — a scope-limited admin must target devices/groups
// fully within their scope. The per-device DispatchAction gate the fan-outs
// delegate to is NOT sufficient: it keys off the "DispatchAction" permission,
// which a holder of (say) DispatchToMultiple need not have, so it would wave the
// fan-out through unconfined.
func (h *ActionHandler) enforceDeviceScopeAll(ctx context.Context, perm string, deviceIDs []string) error {
	resolver := newScopeResolver(h.store)
	for _, deviceID := range deviceIDs {
		if err := auth.EnforceDeviceScopeOnBaseTier(ctx, resolver, perm, deviceID); err != nil {
			return err
		}
	}
	return nil
}

// dispatchTask is a single fan-out element consumed by dispatchEach:
// the wire request to issue and the structured log fields that
// identify it on the failure path. Extracted to deduplicate the
// "load list → loop → DispatchAction → log on err → append on
// success" skeleton shared by 4 fan-out RPCs (audit F024).
type dispatchTask struct {
	req     *pm.DispatchActionRequest
	logArgs []any
}

// dispatchEach runs a slice of dispatch tasks, log-and-continues on
// per-element error, and returns the successful executions.
// `rpc` is the calling RPC name — included in every failure log so
// the operator can correlate a degraded fan-out result back to its
// origin RPC. The slice is preallocated to len(tasks) since most
// fan-outs succeed end-to-end.
func (h *ActionHandler) dispatchEach(ctx context.Context, rpc string, tasks []dispatchTask) []*pm.ActionExecution {
	out := make([]*pm.ActionExecution, 0, len(tasks))
	for _, t := range tasks {
		resp, err := h.DispatchAction(ctx, connect.NewRequest(t.req))
		if err != nil {
			args := make([]any, 0, len(t.logArgs)+4)
			args = append(args, "rpc", rpc, "error", err)
			args = append(args, t.logArgs...)
			h.logger.Warn("dispatch failed", args...)
			continue
		}
		out = append(out, resp.Msg.Execution)
	}
	return out
}

// DispatchToMultiple dispatches an action to multiple devices.
func (h *ActionHandler) DispatchToMultiple(ctx context.Context, req *connect.Request[pm.DispatchToMultipleRequest]) (*connect.Response[pm.DispatchToMultipleResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := h.enforceDeviceScopeAll(ctx, "DispatchToMultiple", req.Msg.DeviceIds); err != nil {
		return nil, err
	}

	tasks := make([]dispatchTask, 0, len(req.Msg.DeviceIds))
	for _, deviceID := range req.Msg.DeviceIds {
		// The oneof's interface is package-private, so we build the
		// concrete DispatchActionRequest in each branch instead of
		// hoisting a typed local variable.
		var dispatchReq *pm.DispatchActionRequest
		switch s := req.Msg.ActionSource.(type) {
		case *pm.DispatchToMultipleRequest_ActionId:
			dispatchReq = &pm.DispatchActionRequest{
				DeviceId:     deviceID,
				ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: s.ActionId},
			}
		case *pm.DispatchToMultipleRequest_InlineAction:
			dispatchReq = &pm.DispatchActionRequest{
				DeviceId:     deviceID,
				ActionSource: &pm.DispatchActionRequest_InlineAction{InlineAction: s.InlineAction},
			}
		default:
			continue
		}
		tasks = append(tasks, dispatchTask{
			req:     dispatchReq,
			logArgs: []any{"device_id", deviceID},
		})
	}

	return connect.NewResponse(&pm.DispatchToMultipleResponse{
		Executions: h.dispatchEach(ctx, "DispatchToMultiple", tasks),
	}), nil
}

// DispatchAssignedActions dispatches all actions assigned to a device.
func (h *ActionHandler) DispatchAssignedActions(ctx context.Context, req *connect.Request[pm.DispatchAssignedActionsRequest]) (*connect.Response[pm.DispatchAssignedActionsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "DispatchAssignedActions", req.Msg.DeviceId); err != nil {
		return nil, err
	}

	actions, err := h.store.Queries().ListAssignedActionsForDevice(ctx, req.Msg.DeviceId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get assigned actions")
	}

	tasks := make([]dispatchTask, 0, len(actions))
	for _, action := range actions {
		tasks = append(tasks, dispatchTask{
			req: &pm.DispatchActionRequest{
				DeviceId:     req.Msg.DeviceId,
				ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: action.ID},
			},
			logArgs: []any{"device_id", req.Msg.DeviceId, "action_id", action.ID},
		})
	}

	return connect.NewResponse(&pm.DispatchAssignedActionsResponse{
		Executions: h.dispatchEach(ctx, "DispatchAssignedActions", tasks),
	}), nil
}

// DispatchActionSet dispatches all actions from an action set to a device.
func (h *ActionHandler) DispatchActionSet(ctx context.Context, req *connect.Request[pm.DispatchActionSetRequest]) (*connect.Response[pm.DispatchActionSetResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := h.enforceDeviceScopeAll(ctx, "DispatchActionSet", []string{req.Msg.DeviceId}); err != nil {
		return nil, err
	}

	// Object read-scope (spec 29 S1): confine WHICH set can be executed, not just
	// which device it runs on. Out of scope → NotFound.
	if err := enforceObjectReadScope(ctx, objScope(h.store), h.logger, "action_set", req.Msg.ActionSetId, ErrActionSetNotFound, "action set not found"); err != nil {
		return nil, err
	}

	actions, err := h.store.Queries().ListActionsInSet(ctx, req.Msg.ActionSetId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get actions in set")
	}

	tasks := make([]dispatchTask, 0, len(actions))
	for _, action := range actions {
		tasks = append(tasks, dispatchTask{
			req: &pm.DispatchActionRequest{
				DeviceId:     req.Msg.DeviceId,
				ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: action.ID},
			},
			logArgs: []any{
				"device_id", req.Msg.DeviceId,
				"action_set_id", req.Msg.ActionSetId,
				"action_id", action.ID,
			},
		})
	}

	return connect.NewResponse(&pm.DispatchActionSetResponse{
		Executions: h.dispatchEach(ctx, "DispatchActionSet", tasks),
	}), nil
}

// DispatchDefinition dispatches all actions from a definition to a device.
func (h *ActionHandler) DispatchDefinition(ctx context.Context, req *connect.Request[pm.DispatchDefinitionRequest]) (*connect.Response[pm.DispatchDefinitionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	if err := h.enforceDeviceScopeAll(ctx, "DispatchDefinition", []string{req.Msg.DeviceId}); err != nil {
		return nil, err
	}

	// Object read-scope (spec 29 S1): confine WHICH definition can be executed.
	// Out of scope → NotFound.
	if err := enforceObjectReadScope(ctx, objScope(h.store), h.logger, "definition", req.Msg.DefinitionId, ErrDefinitionNotFound, "definition not found"); err != nil {
		return nil, err
	}

	actionSets, err := h.store.Repos().ActionSet.ListInDefinition(ctx, req.Msg.DefinitionId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get action sets in definition")
	}

	var tasks []dispatchTask
	for _, set := range actionSets {
		actions, err := h.store.Queries().ListActionsInSet(ctx, set.ID)
		if err != nil {
			h.logger.Warn("dispatch failed", "rpc", "DispatchDefinition",
				"reason", "list actions in set",
				"device_id", req.Msg.DeviceId, "definition_id", req.Msg.DefinitionId,
				"action_set_id", set.ID, "error", err)
			continue
		}
		for _, action := range actions {
			tasks = append(tasks, dispatchTask{
				req: &pm.DispatchActionRequest{
					DeviceId:     req.Msg.DeviceId,
					ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: action.ID},
				},
				logArgs: []any{
					"device_id", req.Msg.DeviceId,
					"definition_id", req.Msg.DefinitionId,
					"action_set_id", set.ID,
					"action_id", action.ID,
				},
			})
		}
	}

	return connect.NewResponse(&pm.DispatchDefinitionResponse{
		Executions: h.dispatchEach(ctx, "DispatchDefinition", tasks),
	}), nil
}

// DispatchToGroup dispatches an action/set/definition to all devices in a group.
func (h *ActionHandler) DispatchToGroup(ctx context.Context, req *connect.Request[pm.DispatchToGroupRequest]) (*connect.Response[pm.DispatchToGroupResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	devices, err := h.store.Queries().ListDevicesInGroup(ctx, req.Msg.GroupId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get devices in group")
	}

	// Scope (#3): every member device must be within the caller's DispatchToGroup
	// scope — fail the whole fan-out closed otherwise. The delegated DispatchAction
	// gate keys off "DispatchAction" (which a DispatchToGroup holder need not have)
	// and so would not confine this fan-out on its own.
	memberIDs := make([]string, len(devices))
	for i, d := range devices {
		memberIDs[i] = d.ID
	}
	if err := h.enforceDeviceScopeAll(ctx, "DispatchToGroup", memberIDs); err != nil {
		return nil, err
	}

	// Object read-scope (spec 29 S1): confine WHICH stored object the fan-out
	// executes, once, before the per-device loop. Inline sources have no stored
	// object to scope. Out of scope → NotFound.
	switch source := req.Msg.ActionSource.(type) {
	case *pm.DispatchToGroupRequest_ActionId:
		if err := enforceObjectReadScope(ctx, objScope(h.store), h.logger, "action", source.ActionId, ErrActionNotFound, "action not found"); err != nil {
			return nil, err
		}
	case *pm.DispatchToGroupRequest_ActionSetId:
		if err := enforceObjectReadScope(ctx, objScope(h.store), h.logger, "action_set", source.ActionSetId, ErrActionSetNotFound, "action set not found"); err != nil {
			return nil, err
		}
	case *pm.DispatchToGroupRequest_DefinitionId:
		if err := enforceObjectReadScope(ctx, objScope(h.store), h.logger, "definition", source.DefinitionId, ErrDefinitionNotFound, "definition not found"); err != nil {
			return nil, err
		}
	}

	executions := make([]*pm.ActionExecution, 0)

	for _, device := range devices {
		switch source := req.Msg.ActionSource.(type) {
		case *pm.DispatchToGroupRequest_ActionId:
			dispatchReq := &pm.DispatchActionRequest{
				DeviceId:     device.ID,
				ActionSource: &pm.DispatchActionRequest_ActionId{ActionId: source.ActionId},
			}
			resp, err := h.DispatchAction(ctx, connect.NewRequest(dispatchReq))
			if err == nil {
				executions = append(executions, resp.Msg.Execution)
			} else {
				h.logger.Warn("dispatch failed", "rpc", "DispatchToGroup",
					"source", "action", "group_id", req.Msg.GroupId,
					"device_id", device.ID, "action_id", source.ActionId, "error", err)
			}

		case *pm.DispatchToGroupRequest_ActionSetId:
			setReq := &pm.DispatchActionSetRequest{
				DeviceId:    device.ID,
				ActionSetId: source.ActionSetId,
			}
			resp, err := h.DispatchActionSet(ctx, connect.NewRequest(setReq))
			if err == nil {
				executions = append(executions, resp.Msg.Executions...)
			} else {
				h.logger.Warn("dispatch failed", "rpc", "DispatchToGroup",
					"source", "action_set", "group_id", req.Msg.GroupId,
					"device_id", device.ID, "action_set_id", source.ActionSetId, "error", err)
			}

		case *pm.DispatchToGroupRequest_DefinitionId:
			defReq := &pm.DispatchDefinitionRequest{
				DeviceId:     device.ID,
				DefinitionId: source.DefinitionId,
			}
			resp, err := h.DispatchDefinition(ctx, connect.NewRequest(defReq))
			if err == nil {
				executions = append(executions, resp.Msg.Executions...)
			} else {
				h.logger.Warn("dispatch failed", "rpc", "DispatchToGroup",
					"source", "definition", "group_id", req.Msg.GroupId,
					"device_id", device.ID, "definition_id", source.DefinitionId, "error", err)
			}

		case *pm.DispatchToGroupRequest_InlineAction:
			dispatchReq := &pm.DispatchActionRequest{
				DeviceId:     device.ID,
				ActionSource: &pm.DispatchActionRequest_InlineAction{InlineAction: source.InlineAction},
			}
			resp, err := h.DispatchAction(ctx, connect.NewRequest(dispatchReq))
			if err == nil {
				executions = append(executions, resp.Msg.Execution)
			} else {
				h.logger.Warn("dispatch failed", "rpc", "DispatchToGroup",
					"source", "inline_action", "group_id", req.Msg.GroupId,
					"device_id", device.ID, "error", err)
			}
		}
	}

	return connect.NewResponse(&pm.DispatchToGroupResponse{
		Executions: executions,
	}), nil
}

// GetExecution returns an execution by ID.
func (h *ActionHandler) GetExecution(ctx context.Context, req *connect.Request[pm.GetExecutionRequest]) (*connect.Response[pm.GetExecutionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	exec, err := h.store.Repos().Execution.Get(ctx, req.Msg.Id)
	if err != nil {
		if store.IsNotFound(err) {
			// Uniform with the out-of-scope path below (spec 29 S10): a
			// scope-restricted caller must not tell a missing execution apart from
			// one on a device outside their scope.
			return nil, deviceScopeMissError(ctx, "GetExecution", ErrExecutionNotFound, "execution not found")
		}
		return nil, handleGetError(ctx, err, ErrExecutionNotFound, "execution not found")
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "GetExecution", exec.DeviceID); err != nil {
		return nil, err
	}

	protoExec := h.executionToProto(exec)

	// Fetch action name
	if exec.ActionID != nil {
		rows, err := h.store.Repos().Action.NamesByIDs(ctx, []string{*exec.ActionID})
		if err == nil && len(rows) > 0 {
			protoExec.ActionName = rows[0].Name
		} else if err != nil {
			logEnrichmentErr("GetActionNamesByIDs", "action_id", *exec.ActionID, err)
		}
	}

	// Load live output from output chunks
	liveOutput := h.loadLiveOutput(ctx, req.Msg.Id)
	if liveOutput != nil {
		protoExec.LiveOutput = liveOutput
	}

	return connect.NewResponse(&pm.GetExecutionResponse{
		Execution: protoExec,
	}), nil
}

// ListExecutions returns a paginated list of executions.
func (h *ActionHandler) ListExecutions(ctx context.Context, req *connect.Request[pm.ListExecutionsRequest]) (*connect.Response[pm.ListExecutionsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	pageSize, offset, err := parsePagination(int32(req.Msg.PageSize), req.Msg.PageToken)
	if err != nil {
		return nil, err
	}

	statusFilter := ""
	if req.Msg.StatusFilter != pm.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED {
		statusFilter = statusToString(req.Msg.StatusFilter)
	}

	typeFilter := int32(req.Msg.TypeFilter)
	searchQuery := strings.TrimSpace(req.Msg.Search)

	// Device-group scope (#3): a scope-limited ListExecutions holder sees only
	// executions whose device is in their scope groups. Same restriction drives
	// the count so pagination totals stay honest.
	scopeGroups, scopeRestricted := auth.DeviceScopeListFilter(ctx, "ListExecutions")
	scope := store.ScopeGroupFilter{Restricted: scopeRestricted, GroupIDs: scopeGroups}

	execs, err := h.store.Repos().Execution.List(ctx, store.ListExecutionsFilter{DeviceID: req.Msg.DeviceId, Status: statusFilter, ActionTypeFilter: typeFilter, Search: searchQuery, Limit: pageSize, Offset: offset, Scope: scope})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to list executions")
	}

	count, err := h.store.Repos().Execution.Count(ctx, store.CountExecutionsFilter{DeviceID: req.Msg.DeviceId, Status: statusFilter, ActionTypeFilter: typeFilter, Search: searchQuery, Scope: scope})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to count executions")
	}

	nextPageToken := buildNextPageToken(int32(len(execs)), offset, pageSize, count)

	protoExecs := make([]*pm.ActionExecution, len(execs))
	for i, e := range execs {
		protoExecs[i] = h.executionToProto(e)
	}

	// Batch-fetch action names to avoid N+1 queries on the client
	actionIDs := make([]string, 0, len(execs))
	for _, e := range execs {
		if e.ActionID != nil {
			actionIDs = append(actionIDs, *e.ActionID)
		}
	}
	if len(actionIDs) > 0 {
		rows, err := h.store.Repos().Action.NamesByIDs(ctx, actionIDs)
		if err != nil {
			h.logger.Warn("GetActionNamesByIDs bulk enrichment failed",
				"action_id_count", len(actionIDs), "error", err)
		} else {
			nameMap := make(map[string]string, len(rows))
			for _, row := range rows {
				nameMap[row.ID] = row.Name
			}
			for i, e := range execs {
				if e.ActionID != nil {
					protoExecs[i].ActionName = nameMap[*e.ActionID]
				}
			}
		}
	}

	return connect.NewResponse(&pm.ListExecutionsResponse{
		Executions:    protoExecs,
		NextPageToken: nextPageToken,
		TotalCount:    int32(count),
	}), nil
}

// isInstantActionType returns true if the action type is an instant action (agent-builtin, no parameters).
func isInstantActionType(t pm.ActionType) bool {
	return t == pm.ActionType_ACTION_TYPE_REBOOT || t == pm.ActionType_ACTION_TYPE_SYNC
}

// DispatchInstantAction dispatches an instant action (reboot, sync) to a device.
// Instant actions are agent-builtin and require no parameters.
func (h *ActionHandler) DispatchInstantAction(ctx context.Context, req *connect.Request[pm.DispatchInstantActionRequest]) (*connect.Response[pm.DispatchInstantActionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	if !isInstantActionType(req.Msg.InstantAction) {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid instant action type: "+req.Msg.InstantAction.String())
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "DispatchInstantAction", req.Msg.DeviceId); err != nil {
		return nil, err
	}

	_, err = h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: req.Msg.DeviceId})
	if err != nil {
		return nil, handleGetError(ctx, err, ErrDeviceNotFound, "device not found")
	}

	var timeoutSeconds int32
	switch req.Msg.InstantAction {
	case pm.ActionType_ACTION_TYPE_REBOOT:
		timeoutSeconds = 600
	case pm.ActionType_ACTION_TYPE_SYNC:
		timeoutSeconds = 60
	}

	id := ulid.Make().String()

	// Same deferred-dispatch handling as DispatchAction: optional
	// future RunAt switches the path from immediate to scheduled.
	var dispatchDelay time.Duration
	if req.Msg.RunAt != nil {
		dispatchDelay = time.Until(req.Msg.RunAt.AsTime())
		if dispatchDelay <= 0 {
			return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "run_at must be in the future")
		}
	}

	// Note: req.Msg.RespectMaintenanceWindow is intentionally not
	// persisted — see DispatchAction above for the audit-N009 reasoning.

	// Fail fast when no task queue is configured — same fail-closed
	// contract as DispatchAction. Positioned after validation/auth/
	// device-lookup so body-level errors surface with their own codes.
	if h.aqClient == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeFailedPrecondition, "instant dispatch unavailable: task queue not configured")
	}

	// Typed payload (not an ad-hoc map). Instant actions are parameterless,
	// so params is the empty-object JSON `{}`.
	instantActionType := int32(req.Msg.InstantAction)
	instantDesiredState := int32(pm.DesiredState_DESIRED_STATE_PRESENT)
	instantTimeout := timeoutSeconds
	initialEventType := string(eventtypes.ExecutionCreated)
	var eventData any = payloads.ExecutionCreated{
		DeviceID:       req.Msg.DeviceId,
		ActionType:     &instantActionType,
		DesiredState:   &instantDesiredState,
		Params:         json.RawMessage("{}"),
		TimeoutSeconds: &instantTimeout,
	}
	if dispatchDelay > 0 {
		initialEventType = string(eventtypes.ExecutionScheduled)
		eventData = payloads.ExecutionScheduled{
			DeviceID:       req.Msg.DeviceId,
			ActionType:     &instantActionType,
			DesiredState:   &instantDesiredState,
			Params:         json.RawMessage("{}"),
			TimeoutSeconds: &instantTimeout,
			ScheduledFor:   req.Msg.RunAt.AsTime().UTC().Format(time.RFC3339Nano),
		}
	}
	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "execution",
		StreamID:   id,
		EventType:  initialEventType,
		Data:       eventData,
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to create execution"); err != nil {
		return nil, err
	}

	// Dispatch instant action. Same contract as DispatchAction: an
	// enqueue failure after the ExecutionCreated write MUST emit a
	// compensating ExecutionFailed event so the row moves to a
	// terminal `failed` state — otherwise the projection sits in
	// `pending` forever and the operator has no idea why the
	// reboot/sync never happened.
	enqueueOpts := []asynq.Option{asynq.MaxRetry(3)}
	if dispatchDelay > 0 {
		enqueueOpts = append(enqueueOpts, asynq.TaskID(id), asynq.ProcessIn(dispatchDelay))
	}
	// Sign the instant dispatch with the same canonical-bytes contract
	// as regular actions (audit F-31): the agent refuses to execute
	// REBOOT / SYNC without a valid CA-signature once the matching
	// agent PR drops the IsInstantAction verifier skip. Canonical
	// params for parameterless instant actions is the empty-object
	// JSON `{}` — agent's verifier uses the same (id, type,
	// paramsCanonical) tuple as for regular actions, so no protocol
	// change is needed.
	//
	// Fail-closed on a nil signer — matches the existing
	// DispatchAction contract at action_dispatch.go:219 (CR finding
	// on the F-31 PR). A nil signer is a wiring bug, not a config
	// option: production main.go passes the real internal/ca signer,
	// tests pass NoOpSigner. Dispatching an unsigned instant task
	// from this branch would silently survive a misconfigured boot
	// and re-open the REBOOT-storm primitive that F-31 closes.
	if h.signer == nil {
		h.logger.Error("instant dispatch: nil signer — wiring bug", "execution_id", id)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "action signer not configured")
	}
	// Build and sign the full envelope for the instant action. REBOOT /
	// SYNC carry no params, so the empty-object JSON `{}` is the params
	// source — PopulateEnvelope classifies these as param-less and leaves
	// the oneof unset. The action_type is bound inside the signed bytes so
	// a compromised relay can't lift a REBOOT signature onto SYNC (or vice
	// versa) or retarget the device.
	envelopeBytes, instantSig, sigErr := actionparams.BuildAndSignEnvelope(
		h.signer,
		id,
		int32(req.Msg.InstantAction),
		[]byte("{}"),
		int32(pm.DesiredState_DESIRED_STATE_PRESENT),
		timeoutSeconds,
		nil, // instant actions are one-shot, no schedule
		req.Msg.DeviceId,
	)
	if sigErr != nil {
		h.logger.Error("failed to build/sign instant action envelope; refusing dispatch",
			"execution_id", id, "action_type", req.Msg.InstantAction.String(), "error", sigErr)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to sign instant action")
	}
	if err := h.aqClient.EnqueueToDevice(req.Msg.DeviceId, taskqueue.TypeActionDispatch, taskqueue.ActionDispatchPayload{
		ExecutionID:   id,
		EnvelopeBytes: envelopeBytes,
		Signature:     instantSig,
	}, enqueueOpts...); err != nil {
		h.logger.Error("failed to enqueue instant action dispatch; emitting ExecutionFailed",
			"error", err, "execution_id", id)
		if failErr := appendEvent(ctx, h.store, h.logger, store.Event{
			StreamType: "execution",
			StreamID:   id,
			EventType:  string(eventtypes.ExecutionFailed),
			Data: payloads.ExecutionFailedCompensating{
				Error: fmt.Sprintf("instant dispatch enqueue failed: %v", err),
				// CompletedAt nil so the projector falls back to event.occurred_at.
			},
			ActorType: "system",
			ActorID:   "system",
		}, "failed to append ExecutionFailed compensating event"); failErr != nil {
			h.logger.Error("compensating ExecutionFailed event failed; execution row is stuck in pending",
				"execution_id", id, "error", failErr)
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to enqueue instant action dispatch")
	}

	exec, err := h.store.Repos().Execution.Get(ctx, id)
	if err != nil {
		h.logger.Error("failed to get execution after creation", "error", err, "execution_id", id)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get execution")
	}

	h.logger.Info("instant action dispatched",
		"execution_id", id,
		"device_id", req.Msg.DeviceId,
		"action_type", req.Msg.InstantAction.String(),
	)

	return connect.NewResponse(&pm.DispatchInstantActionResponse{
		Execution: h.executionToProto(exec),
	}), nil
}

// CancelExecution prunes a scheduled or pending dispatch before it
// fires. Idempotent: an execution that already left the SCHEDULED /
// PENDING window is returned as-is (the projection's WHEN-clause on
// ExecutionCancelled also guards against overwriting a real outcome
// after the dispatch has run). See manchtools/power-manage-server#57.
func (h *ActionHandler) CancelExecution(ctx context.Context, req *connect.Request[pm.CancelExecutionRequest]) (*connect.Response[pm.CancelExecutionResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	userCtx, err := requireAuth(ctx)
	if err != nil {
		return nil, err
	}

	exec, err := h.store.Repos().Execution.Get(ctx, req.Msg.ExecutionId)
	if err != nil {
		if store.IsNotFound(err) {
			// Uniform with the out-of-scope path below (spec 29 S10).
			return nil, deviceScopeMissError(ctx, "CancelExecution", ErrExecutionNotFound, "execution not found")
		}
		return nil, handleGetError(ctx, err, ErrExecutionNotFound, "execution not found")
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "CancelExecution", exec.DeviceID); err != nil {
		return nil, err
	}

	// Cancel only acts on rows that haven't dispatched yet. Past that
	// point the execution either is running on the agent or has
	// already reached a terminal state — both of which the cancel
	// must NOT overwrite. Return the row as-is so the caller can
	// observe the actual status and decide what to do.
	if exec.Status != "scheduled" && exec.Status != "pending" {
		return connect.NewResponse(&pm.CancelExecutionResponse{
			Execution: h.executionToProto(exec),
		}), nil
	}

	// Best-effort prune of the deferred Asynq task. A miss is fine —
	// the projection's WHEN-clause guards the cancel event against
	// double-application, so an in-flight dispatch that beat the
	// inspector here will still surface its real outcome.
	if h.aqClient != nil {
		if delErr := h.aqClient.DeleteScheduledDeviceTask(exec.DeviceID, exec.ID); delErr != nil {
			h.logger.Warn("CancelExecution: asynq prune failed; emitting ExecutionCancelled anyway",
				"execution_id", exec.ID, "device_id", exec.DeviceID, "error", delErr)
		}
	}

	if err := appendEvent(ctx, h.store, h.logger, store.Event{
		StreamType: "execution",
		StreamID:   exec.ID,
		EventType:  string(eventtypes.ExecutionCancelled),
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    userCtx.ID,
	}, "failed to cancel execution"); err != nil {
		return nil, err
	}

	exec, err = h.store.Repos().Execution.Get(ctx, req.Msg.ExecutionId)
	if err != nil {
		h.logger.Error("CancelExecution: failed to refetch execution after cancel", "execution_id", req.Msg.ExecutionId, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to read execution after cancel")
	}

	h.logger.Info("execution cancelled",
		"execution_id", exec.ID,
		"device_id", exec.DeviceID,
		"actor_id", userCtx.ID,
	)

	return connect.NewResponse(&pm.CancelExecutionResponse{
		Execution: h.executionToProto(exec),
	}), nil
}

// serializeProtoParams marshals an action params proto to the
// map[string]any shape that's stored in the event's Data field.
// Delegates to actionparams.MarshalActionParams so the wire format
// is identical for user-created and system-managed actions — both
// use EmitUnpopulated so proto3 scalar zero values cross the wire
// rather than being silently dropped. See that helper for the full
