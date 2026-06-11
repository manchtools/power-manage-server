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
// zero value. Any OTHER unhandled type is a new ActionType that PopulateAction
// forgot to wire up.
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
// action with empty/nil params (#368). Previously it swallowed both, and the
// gateway dispatched the action anyway.
func PopulateAction(action *pm.Action, actionType int32, paramsJSON []byte) error {
	switch pm.ActionType(actionType) {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		var p pm.PackageParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal PACKAGE params: %w", err)
		}
		action.Params = &pm.Action_Package{Package: &p}
	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		var p pm.AppInstallParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal APP_INSTALL params: %w", err)
		}
		action.Params = &pm.Action_App{App: &p}
	case pm.ActionType_ACTION_TYPE_FLATPAK:
		var p pm.FlatpakParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal FLATPAK params: %w", err)
		}
		action.Params = &pm.Action_Flatpak{Flatpak: &p}
	case pm.ActionType_ACTION_TYPE_SHELL, pm.ActionType_ACTION_TYPE_SCRIPT_RUN:
		var p pm.ShellParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal SHELL params: %w", err)
		}
		action.Params = &pm.Action_Shell{Shell: &p}
	case pm.ActionType_ACTION_TYPE_SERVICE:
		var p pm.ServiceParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal SERVICE params: %w", err)
		}
		action.Params = &pm.Action_Service{Service: &p}
	case pm.ActionType_ACTION_TYPE_FILE:
		var p pm.FileParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal FILE params: %w", err)
		}
		action.Params = &pm.Action_File{File: &p}
	case pm.ActionType_ACTION_TYPE_UPDATE:
		var p pm.UpdateParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal UPDATE params: %w", err)
		}
		action.Params = &pm.Action_Update{Update: &p}
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		var p pm.RepositoryParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal REPOSITORY params: %w", err)
		}
		action.Params = &pm.Action_Repository{Repository: &p}
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		var p pm.DirectoryParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal DIRECTORY params: %w", err)
		}
		action.Params = &pm.Action_Directory{Directory: &p}
	case pm.ActionType_ACTION_TYPE_USER:
		var p pm.UserParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal USER params: %w", err)
		}
		action.Params = &pm.Action_User{User: &p}
	case pm.ActionType_ACTION_TYPE_GROUP:
		var p pm.GroupParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal GROUP params: %w", err)
		}
		action.Params = &pm.Action_Group{Group: &p}
	case pm.ActionType_ACTION_TYPE_SSH:
		var p pm.SshParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal SSH params: %w", err)
		}
		action.Params = &pm.Action_Ssh{Ssh: &p}
	case pm.ActionType_ACTION_TYPE_SSHD:
		var p pm.SshdParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal SSHD params: %w", err)
		}
		action.Params = &pm.Action_Sshd{Sshd: &p}
	case pm.ActionType_ACTION_TYPE_ADMIN_POLICY:
		var p pm.AdminPolicyParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal ADMIN_POLICY params: %w", err)
		}
		action.Params = &pm.Action_AdminPolicy{AdminPolicy: &p}
	case pm.ActionType_ACTION_TYPE_LPS:
		var p pm.LpsParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal LPS params: %w", err)
		}
		action.Params = &pm.Action_Lps{Lps: &p}
	case pm.ActionType_ACTION_TYPE_ENCRYPTION:
		var p pm.EncryptionParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal ENCRYPTION params: %w", err)
		}
		action.Params = &pm.Action_Encryption{Encryption: &p}
	case pm.ActionType_ACTION_TYPE_WIFI:
		var p pm.WifiParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal WIFI params: %w", err)
		}
		action.Params = &pm.Action_Wifi{Wifi: &p}
	case pm.ActionType_ACTION_TYPE_AGENT_UPDATE:
		var p pm.AgentUpdateParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal AGENT_UPDATE params: %w", err)
		}
		action.Params = &pm.Action_AgentUpdate{AgentUpdate: &p}
	default:
		if isNoParamsActionType(pm.ActionType(actionType)) {
			return nil
		}
		return fmt.Errorf("actionparams: unhandled action type %d (%s)", actionType, pm.ActionType(actionType))
	}
	return nil
}

// PopulateManagedAction deserializes params JSON into an API-format
// ManagedAction proto. Used by the control server API (action list/get
// responses). Returns an error on a protojson parse failure OR an unhandled
// action type (#368).
func PopulateManagedAction(action *pm.ManagedAction, actionType pm.ActionType, paramsJSON []byte) error {
	switch actionType {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		var p pm.PackageParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal PACKAGE params: %w", err)
		}
		action.Params = &pm.ManagedAction_Package{Package: &p}
	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		var p pm.AppInstallParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal APP_INSTALL params: %w", err)
		}
		action.Params = &pm.ManagedAction_App{App: &p}
	case pm.ActionType_ACTION_TYPE_FLATPAK:
		var p pm.FlatpakParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal FLATPAK params: %w", err)
		}
		action.Params = &pm.ManagedAction_Flatpak{Flatpak: &p}
	case pm.ActionType_ACTION_TYPE_SHELL, pm.ActionType_ACTION_TYPE_SCRIPT_RUN:
		var p pm.ShellParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal SHELL params: %w", err)
		}
		action.Params = &pm.ManagedAction_Shell{Shell: &p}
	case pm.ActionType_ACTION_TYPE_SERVICE:
		var p pm.ServiceParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal SERVICE params: %w", err)
		}
		action.Params = &pm.ManagedAction_Service{Service: &p}
	case pm.ActionType_ACTION_TYPE_FILE:
		var p pm.FileParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal FILE params: %w", err)
		}
		action.Params = &pm.ManagedAction_File{File: &p}
	case pm.ActionType_ACTION_TYPE_UPDATE:
		var p pm.UpdateParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal UPDATE params: %w", err)
		}
		action.Params = &pm.ManagedAction_Update{Update: &p}
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		var p pm.RepositoryParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal REPOSITORY params: %w", err)
		}
		action.Params = &pm.ManagedAction_Repository{Repository: &p}
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		var p pm.DirectoryParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal DIRECTORY params: %w", err)
		}
		action.Params = &pm.ManagedAction_Directory{Directory: &p}
	case pm.ActionType_ACTION_TYPE_USER:
		var p pm.UserParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal USER params: %w", err)
		}
		action.Params = &pm.ManagedAction_User{User: &p}
	case pm.ActionType_ACTION_TYPE_GROUP:
		var p pm.GroupParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal GROUP params: %w", err)
		}
		action.Params = &pm.ManagedAction_Group{Group: &p}
	case pm.ActionType_ACTION_TYPE_SSH:
		var p pm.SshParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal SSH params: %w", err)
		}
		action.Params = &pm.ManagedAction_Ssh{Ssh: &p}
	case pm.ActionType_ACTION_TYPE_SSHD:
		var p pm.SshdParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal SSHD params: %w", err)
		}
		action.Params = &pm.ManagedAction_Sshd{Sshd: &p}
	case pm.ActionType_ACTION_TYPE_ADMIN_POLICY:
		var p pm.AdminPolicyParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal ADMIN_POLICY params: %w", err)
		}
		action.Params = &pm.ManagedAction_AdminPolicy{AdminPolicy: &p}
	case pm.ActionType_ACTION_TYPE_LPS:
		var p pm.LpsParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal LPS params: %w", err)
		}
		action.Params = &pm.ManagedAction_Lps{Lps: &p}
	case pm.ActionType_ACTION_TYPE_ENCRYPTION:
		var p pm.EncryptionParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal ENCRYPTION params: %w", err)
		}
		action.Params = &pm.ManagedAction_Encryption{Encryption: &p}
	case pm.ActionType_ACTION_TYPE_WIFI:
		var p pm.WifiParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal WIFI params: %w", err)
		}
		action.Params = &pm.ManagedAction_Wifi{Wifi: &p}
	case pm.ActionType_ACTION_TYPE_AGENT_UPDATE:
		var p pm.AgentUpdateParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err != nil {
			return fmt.Errorf("actionparams: unmarshal AGENT_UPDATE params: %w", err)
		}
		action.Params = &pm.ManagedAction_AgentUpdate{AgentUpdate: &p}
	default:
		if isNoParamsActionType(actionType) {
			return nil
		}
		return fmt.Errorf("actionparams: unhandled action type %d (%s)", int32(actionType), actionType)
	}
	return nil
}
