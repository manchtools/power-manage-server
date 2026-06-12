// Package actionparams provides shared action parameter serialization
// for both the wire format (Action) and the API format (ManagedAction).
package actionparams

import (
	"fmt"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var unmarshalOpts = protojson.UnmarshalOptions{DiscardUnknown: true}

// marshalOptions is the single protojson configuration used to
// serialise action params throughout the server — both user-created
// actions (action_handler.serializeProtoParams) and system-managed
// actions (api.system_actions). Sharing this configuration is the
// whole point: every path that produces action JSON emits the same
// bytes for the same proto message, and the contract across the wire
// is identical regardless of whether a human or the control server
// authored the action.
//
// Two deliberate choices:
//
//   - EmitUnpopulated = true. Without this, proto3 scalar zero values
//     are dropped from the JSON output, which makes it impossible to
//     distinguish "the caller explicitly wants false" from "the caller
//     did not mention the field." The pm-tty-* home directory bug
//     exploited this exact gap: syncTtyUserAction set createHome:
//     false, which the default marshaller dropped, and the agent's
//     "default true for normal users" logic then fabricated a home
//     the server never asked for. Emitting unpopulated keeps explicit
//     false observable on the wire.
//
//   - UseProtoNames = false (default). camelCase JSON names are what
//     protojson produces and consumes by default, and the agent
//     unmarshals using default protojson options. Both sides use the
//     same naming; staying on the default avoids a second, silent
//     inconsistency.
var marshalOptions = protojson.MarshalOptions{
	EmitUnpopulated: true,
	UseProtoNames:   false,
}

// MarshalActionParams serialises an action params proto message to
// JSON bytes using marshalOptions above. Returns an error on a nil
// message so callers don't accidentally emit a bare "null".
//
// All code paths that produce action-params JSON — user-created via
// CreateAction / UpdateActionParams, and system-managed via
// SystemActionManager — should go through this helper. Direct use of
// protojson.Marshal (which defaults to EmitUnpopulated=false) is a
// bug: proto3 scalar zero values silently drop from the output.
func MarshalActionParams(msg proto.Message) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("actionparams.MarshalActionParams: nil message")
	}
	return marshalOptions.Marshal(msg)
}

// isNoParamsActionType reports whether an action type legitimately carries no
// params oneof (so reaching the switch default is expected, not an error).
// REBOOT and SYNC are instant actions with no parameters; UNSPECIFIED is the
// zero value. Any OTHER unhandled type is a new ActionType that the params
// registry forgot to wire up (paramsFieldByActionType in registry.go).
func isNoParamsActionType(t pm.ActionType) bool {
	switch t {
	case pm.ActionType_ACTION_TYPE_UNSPECIFIED,
		pm.ActionType_ACTION_TYPE_REBOOT,
		pm.ActionType_ACTION_TYPE_SYNC:
		return true
	default:
		return false
	}
}

// PopulateAction deserializes params JSON into a wire-format Action proto.
// Used by the gateway (action dispatch) and internal service (agent sync).
//
// Returns an error on a protojson parse failure OR an unhandled action type,
// so callers can fail closed (retry/dead-letter, log) instead of dispatching an
// action with empty/nil params (#368). The per-type mapping lives in the single
// proto-reflection registry (registry.go), not a switch.
func PopulateAction(action *pm.Action, actionType int32, paramsJSON []byte) error {
	return populateParamsOneof(action, pm.ActionType(actionType), paramsJSON)
}

// PopulateEnvelope deserializes params JSON into a SignedActionEnvelope's
// params oneof — the signed/transported representation the agent verifies and
// unmarshals to execute. Used by the dispatch signing path
// (BuildAndSignEnvelope) so the bytes the CA signs carry exactly the typed
// params that run. Fail-closed identically to PopulateAction.
func PopulateEnvelope(env *pm.SignedActionEnvelope, actionType int32, paramsJSON []byte) error {
	return populateParamsOneof(env, pm.ActionType(actionType), paramsJSON)
}

// PopulateManagedAction deserializes params JSON into an API-format
// ManagedAction proto. Used by the control server API (action list/get
// responses). Fail-closed identically to PopulateAction.
func PopulateManagedAction(action *pm.ManagedAction, actionType pm.ActionType, paramsJSON []byte) error {
	return populateParamsOneof(action, actionType, paramsJSON)
}
