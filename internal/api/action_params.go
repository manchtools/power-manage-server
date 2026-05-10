// Package api file action_params.go — proto-message extraction
// helpers split out of action_handler.go (audit F005). Single
// responsibility: turn the per-RPC oneof params off Create/Update
// requests (and ManagedAction read paths) into the proto.Message
// the actionparams library knows how to marshal canonically. Keep
// the dispatch table here so adding a new action type touches one
// file (this) instead of three (Create handler, Update handler,
// inline-action validator).
package api

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
)

// rationale.
func serializeProtoParams(msg proto.Message) (map[string]any, error) {
	if msg == nil {
		return map[string]any{}, nil
	}
	data, err := actionparams.MarshalActionParams(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	var params map[string]any
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, fmt.Errorf("unmarshal params to map: %w", err)
	}
	return params, nil
}

// extractCreateActionParamsMsg returns the concrete proto.Message from a CreateActionRequest oneof.
func extractCreateActionParamsMsg(req *pm.CreateActionRequest) proto.Message {
	switch p := req.Params.(type) {
	case *pm.CreateActionRequest_Package:
		return p.Package
	case *pm.CreateActionRequest_App:
		return p.App
	case *pm.CreateActionRequest_Flatpak:
		return p.Flatpak
	case *pm.CreateActionRequest_Shell:
		return p.Shell
	case *pm.CreateActionRequest_Service:
		return p.Service
	case *pm.CreateActionRequest_File:
		return p.File
	case *pm.CreateActionRequest_Update:
		return p.Update
	case *pm.CreateActionRequest_Repository:
		return p.Repository
	case *pm.CreateActionRequest_Directory:
		return p.Directory
	case *pm.CreateActionRequest_User:
		return p.User
	case *pm.CreateActionRequest_Ssh:
		return p.Ssh
	case *pm.CreateActionRequest_Sshd:
		return p.Sshd
	case *pm.CreateActionRequest_AdminPolicy:
		return p.AdminPolicy
	case *pm.CreateActionRequest_Lps:
		return p.Lps
	case *pm.CreateActionRequest_Encryption:
		return p.Encryption
	case *pm.CreateActionRequest_Group:
		return p.Group
	case *pm.CreateActionRequest_Wifi:
		return p.Wifi
	case *pm.CreateActionRequest_AgentUpdate:
		return p.AgentUpdate
	default:
		return nil
	}
}

// extractUpdateActionParamsMsg returns the concrete proto.Message from an UpdateActionParamsRequest oneof.
func extractUpdateActionParamsMsg(req *pm.UpdateActionParamsRequest) proto.Message {
	switch p := req.Params.(type) {
	case *pm.UpdateActionParamsRequest_Package:
		return p.Package
	case *pm.UpdateActionParamsRequest_App:
		return p.App
	case *pm.UpdateActionParamsRequest_Flatpak:
		return p.Flatpak
	case *pm.UpdateActionParamsRequest_Shell:
		return p.Shell
	case *pm.UpdateActionParamsRequest_Service:
		return p.Service
	case *pm.UpdateActionParamsRequest_File:
		return p.File
	case *pm.UpdateActionParamsRequest_Update:
		return p.Update
	case *pm.UpdateActionParamsRequest_Repository:
		return p.Repository
	case *pm.UpdateActionParamsRequest_Directory:
		return p.Directory
	case *pm.UpdateActionParamsRequest_User:
		return p.User
	case *pm.UpdateActionParamsRequest_Ssh:
		return p.Ssh
	case *pm.UpdateActionParamsRequest_Sshd:
		return p.Sshd
	case *pm.UpdateActionParamsRequest_AdminPolicy:
		return p.AdminPolicy
	case *pm.UpdateActionParamsRequest_Lps:
		return p.Lps
	case *pm.UpdateActionParamsRequest_Encryption:
		return p.Encryption
	case *pm.UpdateActionParamsRequest_Group:
		return p.Group
	case *pm.UpdateActionParamsRequest_Wifi:
		return p.Wifi
	case *pm.UpdateActionParamsRequest_AgentUpdate:
		return p.AgentUpdate
	default:
		return nil
	}
}

// extractActionParamsMsg returns the concrete proto.Message from an Action oneof.
func extractActionParamsMsg(action *pm.Action) proto.Message {
	switch p := action.Params.(type) {
	case *pm.Action_Package:
		return p.Package
	case *pm.Action_App:
		return p.App
	case *pm.Action_Flatpak:
		return p.Flatpak
	case *pm.Action_Shell:
		return p.Shell
	case *pm.Action_Service:
		return p.Service
	case *pm.Action_File:
		return p.File
	case *pm.Action_Update:
		return p.Update
	case *pm.Action_Repository:
		return p.Repository
	case *pm.Action_Directory:
		return p.Directory
	case *pm.Action_User:
		return p.User
	case *pm.Action_Ssh:
		return p.Ssh
	case *pm.Action_Sshd:
		return p.Sshd
	case *pm.Action_AdminPolicy:
		return p.AdminPolicy
	case *pm.Action_Lps:
		return p.Lps
	case *pm.Action_Encryption:
		return p.Encryption
	case *pm.Action_Group:
		return p.Group
	case *pm.Action_Wifi:
		return p.Wifi
	case *pm.Action_AgentUpdate:
		return p.AgentUpdate
	default:
		return nil
	}
}
