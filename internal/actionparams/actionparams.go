// Package actionparams provides shared action parameter serialization
// for both the wire format (Action) and the API format (ManagedAction).
package actionparams

import (
	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

var unmarshalOpts = protojson.UnmarshalOptions{DiscardUnknown: true}

// PopulateAction deserializes params JSON into a wire-format Action proto.
// Used by the gateway (action dispatch) and internal service (agent sync).
func PopulateAction(action *pm.Action, actionType int32, paramsJSON []byte) {
	switch pm.ActionType(actionType) {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		var p pm.PackageParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Package{Package: &p}
		}
	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		var p pm.AppInstallParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_App{App: &p}
		}
	case pm.ActionType_ACTION_TYPE_FLATPAK:
		var p pm.FlatpakParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Flatpak{Flatpak: &p}
		}
	case pm.ActionType_ACTION_TYPE_SHELL, pm.ActionType_ACTION_TYPE_SCRIPT_RUN:
		var p pm.ShellParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Shell{Shell: &p}
		}
	case pm.ActionType_ACTION_TYPE_SERVICE:
		var p pm.ServiceParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Service{Service: &p}
		}
	case pm.ActionType_ACTION_TYPE_FILE:
		var p pm.FileParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_File{File: &p}
		}
	case pm.ActionType_ACTION_TYPE_UPDATE:
		var p pm.UpdateParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Update{Update: &p}
		}
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		var p pm.RepositoryParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Repository{Repository: &p}
		}
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		var p pm.DirectoryParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Directory{Directory: &p}
		}
	case pm.ActionType_ACTION_TYPE_USER:
		var p pm.UserParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_User{User: &p}
		}
	case pm.ActionType_ACTION_TYPE_GROUP:
		var p pm.GroupParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Group{Group: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSH:
		var p pm.SshParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Ssh{Ssh: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSHD:
		var p pm.SshdParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Sshd{Sshd: &p}
		}
	case pm.ActionType_ACTION_TYPE_ADMIN_POLICY:
		var p pm.AdminPolicyParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_AdminPolicy{AdminPolicy: &p}
		}
	case pm.ActionType_ACTION_TYPE_LPS:
		var p pm.LpsParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Lps{Lps: &p}
		}
	case pm.ActionType_ACTION_TYPE_ENCRYPTION:
		var p pm.EncryptionParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Encryption{Encryption: &p}
		}
	case pm.ActionType_ACTION_TYPE_WIFI:
		var p pm.WifiParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Wifi{Wifi: &p}
		}
	case pm.ActionType_ACTION_TYPE_AGENT_UPDATE:
		var p pm.AgentUpdateParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_AgentUpdate{AgentUpdate: &p}
		}
	}
}

// PopulateManagedAction deserializes params JSON into an API-format ManagedAction proto.
// Used by the control server API (action list/get responses).
func PopulateManagedAction(action *pm.ManagedAction, actionType pm.ActionType, paramsJSON []byte) {
	switch actionType {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		var p pm.PackageParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Package{Package: &p}
		}
	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		var p pm.AppInstallParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_App{App: &p}
		}
	case pm.ActionType_ACTION_TYPE_FLATPAK:
		var p pm.FlatpakParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Flatpak{Flatpak: &p}
		}
	case pm.ActionType_ACTION_TYPE_SHELL, pm.ActionType_ACTION_TYPE_SCRIPT_RUN:
		var p pm.ShellParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Shell{Shell: &p}
		}
	case pm.ActionType_ACTION_TYPE_SERVICE:
		var p pm.ServiceParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Service{Service: &p}
		}
	case pm.ActionType_ACTION_TYPE_FILE:
		var p pm.FileParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_File{File: &p}
		}
	case pm.ActionType_ACTION_TYPE_UPDATE:
		var p pm.UpdateParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Update{Update: &p}
		}
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		var p pm.RepositoryParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Repository{Repository: &p}
		}
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		var p pm.DirectoryParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Directory{Directory: &p}
		}
	case pm.ActionType_ACTION_TYPE_USER:
		var p pm.UserParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_User{User: &p}
		}
	case pm.ActionType_ACTION_TYPE_GROUP:
		var p pm.GroupParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Group{Group: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSH:
		var p pm.SshParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Ssh{Ssh: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSHD:
		var p pm.SshdParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Sshd{Sshd: &p}
		}
	case pm.ActionType_ACTION_TYPE_ADMIN_POLICY:
		var p pm.AdminPolicyParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_AdminPolicy{AdminPolicy: &p}
		}
	case pm.ActionType_ACTION_TYPE_LPS:
		var p pm.LpsParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Lps{Lps: &p}
		}
	case pm.ActionType_ACTION_TYPE_ENCRYPTION:
		var p pm.EncryptionParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Encryption{Encryption: &p}
		}
	case pm.ActionType_ACTION_TYPE_WIFI:
		var p pm.WifiParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_Wifi{Wifi: &p}
		}
	case pm.ActionType_ACTION_TYPE_AGENT_UPDATE:
		var p pm.AgentUpdateParams
		if err := unmarshalOpts.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.ManagedAction_AgentUpdate{AgentUpdate: &p}
		}
	}
}
