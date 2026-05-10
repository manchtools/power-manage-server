// Package api file action_validators.go — Create / Update request
// validators + the action-type ↔ params message dispatch table,
// extracted from action_handler.go (audit F005). All validators
// take a context for log/error correlation and return a
// connect.Error so handlers can return them straight through.
package api

import (
	"context"
	"strings"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// validateCreateActionParams validates params for CreateActionRequest using struct tags.
func validateCreateActionParams(ctx context.Context, req *pm.CreateActionRequest) error {
	switch p := req.Params.(type) {
	case *pm.CreateActionRequest_Package:
		if p.Package != nil {
			return Validate(ctx, p.Package)
		}
	case *pm.CreateActionRequest_Shell:
		if p.Shell != nil {
			if err := Validate(ctx, p.Shell); err != nil {
				return err
			}
			return validateShellScriptChoice(ctx, p.Shell)
		}
	case *pm.CreateActionRequest_Service:
		if p.Service != nil {
			return Validate(ctx, p.Service)
		}
	case *pm.CreateActionRequest_File:
		if p.File != nil {
			return Validate(ctx, p.File)
		}
	case *pm.CreateActionRequest_App:
		if p.App != nil {
			return Validate(ctx, p.App)
		}
	case *pm.CreateActionRequest_Flatpak:
		if p.Flatpak != nil {
			return Validate(ctx, p.Flatpak)
		}
	case *pm.CreateActionRequest_Update:
		if p.Update != nil {
			return Validate(ctx, p.Update)
		}
	case *pm.CreateActionRequest_Repository:
		if p.Repository != nil {
			return Validate(ctx, p.Repository)
		}
	case *pm.CreateActionRequest_Directory:
		if p.Directory != nil {
			return Validate(ctx, p.Directory)
		}
	case *pm.CreateActionRequest_User:
		if p.User != nil {
			return Validate(ctx, p.User)
		}
	case *pm.CreateActionRequest_Ssh:
		if p.Ssh != nil {
			return Validate(ctx, p.Ssh)
		}
	case *pm.CreateActionRequest_Sshd:
		if p.Sshd != nil {
			return Validate(ctx, p.Sshd)
		}
	case *pm.CreateActionRequest_AdminPolicy:
		if p.AdminPolicy != nil {
			return Validate(ctx, p.AdminPolicy)
		}
	case *pm.CreateActionRequest_Lps:
		if p.Lps != nil {
			return Validate(ctx, p.Lps)
		}
	case *pm.CreateActionRequest_Encryption:
		if p.Encryption != nil {
			return Validate(ctx, p.Encryption)
		}
	case *pm.CreateActionRequest_Group:
		if p.Group != nil {
			return Validate(ctx, p.Group)
		}
	case *pm.CreateActionRequest_Wifi:
		if p.Wifi != nil {
			return Validate(ctx, p.Wifi)
		}
	case *pm.CreateActionRequest_AgentUpdate:
		if p.AgentUpdate != nil {
			return validateAgentUpdateParams(ctx, p.AgentUpdate)
		}
	}
	return nil
}

// validateShellScriptChoice enforces the Create-time rule that a
// shell action must specify at least one of `script` or
// `detection_script` — otherwise the action is a no-op that signs
// cleanly and turns into a mystery when operators can't figure out
// why nothing ran. Applied anywhere a ShellParams is accepted
// (Create, Update params, inline Dispatch).
func validateShellScriptChoice(ctx context.Context, p *pm.ShellParams) error {
	if p == nil {
		return nil
	}
	if p.Script == "" && p.DetectionScript == "" {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one of script or detection_script is required")
	}
	return nil
}

// validateInlineAction validates an inline Action proto on a
// DispatchAction request. The non-inline DispatchAction path pulls
// the action by ID from the DB, which has already been validated at
// Create/Update time; inline actions skip that lookup and would
// otherwise reach the agent unvalidated, potentially signing a
// malformed or oversized payload that the agent silently drops.
//
// Every oneof branch mirrors validateCreateActionParams — including
// the shell "at least one of script or detection_script" rule —
// so an inline dispatched action cannot do anything a Create-path
// action cannot.
//
// Beyond the per-oneof params validation, this function enforces the
// outer Action invariants that the by-ID dispatch path gets for free
// from the Create/Update gate:
//
//   - Type is non-unspecified.
//   - TimeoutSeconds is in [0, 3600].
//   - Schedule, if present, validates.
//   - Type matches the populated params oneof — a caller cannot say
//     `Type=USER` while sending an Ssh oneof and have the dispatch
//     path treat it as a USER action with garbage params.
func validateInlineAction(ctx context.Context, action *pm.Action) error {
	if action == nil {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inline_action is required")
	}
	if action.Type == pm.ActionType_ACTION_TYPE_UNSPECIFIED {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "action type is required")
	}
	if action.TimeoutSeconds < 0 || action.TimeoutSeconds > 3600 {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "timeout_seconds must be between 0 and 3600")
	}
	if action.Schedule != nil {
		if err := Validate(ctx, action.Schedule); err != nil {
			return err
		}
	}

	params := extractActionParamsMsg(action)
	if params == nil {
		// ACTION_TYPE_UPDATE has no params payload — that one
		// matches `nil` legitimately. Every other type must
		// carry a populated oneof.
		if action.Type == pm.ActionType_ACTION_TYPE_UPDATE {
			return nil
		}
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inline_action params are required")
	}
	if !actionParamsMatchType(action.Type, action.Params) {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inline_action params do not match action.Type")
	}
	if err := Validate(ctx, params); err != nil {
		return err
	}
	if shell, ok := params.(*pm.ShellParams); ok {
		return validateShellScriptChoice(ctx, shell)
	}
	if agentUpdate, ok := params.(*pm.AgentUpdateParams); ok {
		return validateAgentUpdateParams(ctx, agentUpdate)
	}
	return nil
}

// actionParamsMatchType returns true when the populated params oneof
// matches the declared action.Type. The dispatch path trusts both
// fields independently — without this guard, a caller could route a
// Type=USER action through the Action_Ssh oneof and the agent would
// receive a USER action whose params bytes are an Ssh proto, leading
// to silent param corruption.
func actionParamsMatchType(t pm.ActionType, params interface{}) bool {
	switch t {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		_, ok := params.(*pm.Action_Package)
		return ok
	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		_, ok := params.(*pm.Action_App)
		return ok
	case pm.ActionType_ACTION_TYPE_FLATPAK:
		_, ok := params.(*pm.Action_Flatpak)
		return ok
	case pm.ActionType_ACTION_TYPE_SHELL, pm.ActionType_ACTION_TYPE_SCRIPT_RUN:
		_, ok := params.(*pm.Action_Shell)
		return ok
	case pm.ActionType_ACTION_TYPE_SERVICE:
		_, ok := params.(*pm.Action_Service)
		return ok
	case pm.ActionType_ACTION_TYPE_FILE:
		_, ok := params.(*pm.Action_File)
		return ok
	case pm.ActionType_ACTION_TYPE_UPDATE:
		// ACTION_TYPE_UPDATE may carry either *pm.Action_Update or
		// nil params (kicks off whatever the agent's package
		// manager considers an update). Both shapes are valid.
		if params == nil {
			return true
		}
		_, ok := params.(*pm.Action_Update)
		return ok
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		_, ok := params.(*pm.Action_Repository)
		return ok
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		_, ok := params.(*pm.Action_Directory)
		return ok
	case pm.ActionType_ACTION_TYPE_USER:
		_, ok := params.(*pm.Action_User)
		return ok
	case pm.ActionType_ACTION_TYPE_GROUP:
		_, ok := params.(*pm.Action_Group)
		return ok
	case pm.ActionType_ACTION_TYPE_SSH:
		_, ok := params.(*pm.Action_Ssh)
		return ok
	case pm.ActionType_ACTION_TYPE_SSHD:
		_, ok := params.(*pm.Action_Sshd)
		return ok
	case pm.ActionType_ACTION_TYPE_ADMIN_POLICY:
		_, ok := params.(*pm.Action_AdminPolicy)
		return ok
	case pm.ActionType_ACTION_TYPE_LPS:
		_, ok := params.(*pm.Action_Lps)
		return ok
	case pm.ActionType_ACTION_TYPE_ENCRYPTION:
		_, ok := params.(*pm.Action_Encryption)
		return ok
	case pm.ActionType_ACTION_TYPE_WIFI:
		_, ok := params.(*pm.Action_Wifi)
		return ok
	case pm.ActionType_ACTION_TYPE_AGENT_UPDATE:
		_, ok := params.(*pm.Action_AgentUpdate)
		return ok
	}
	return false
}

// validateUpdateActionParams validates params for UpdateActionParamsRequest using struct tags.
func validateUpdateActionParams(ctx context.Context, req *pm.UpdateActionParamsRequest) error {
	switch p := req.Params.(type) {
	case *pm.UpdateActionParamsRequest_Package:
		if p.Package != nil {
			return Validate(ctx, p.Package)
		}
	case *pm.UpdateActionParamsRequest_Shell:
		if p.Shell != nil {
			if err := Validate(ctx, p.Shell); err != nil {
				return err
			}
			return validateShellScriptChoice(ctx, p.Shell)
		}
	case *pm.UpdateActionParamsRequest_Service:
		if p.Service != nil {
			return Validate(ctx, p.Service)
		}
	case *pm.UpdateActionParamsRequest_File:
		if p.File != nil {
			return Validate(ctx, p.File)
		}
	case *pm.UpdateActionParamsRequest_App:
		if p.App != nil {
			return Validate(ctx, p.App)
		}
	case *pm.UpdateActionParamsRequest_Flatpak:
		if p.Flatpak != nil {
			return Validate(ctx, p.Flatpak)
		}
	case *pm.UpdateActionParamsRequest_Update:
		if p.Update != nil {
			return Validate(ctx, p.Update)
		}
	case *pm.UpdateActionParamsRequest_Repository:
		if p.Repository != nil {
			return Validate(ctx, p.Repository)
		}
	case *pm.UpdateActionParamsRequest_Directory:
		if p.Directory != nil {
			return Validate(ctx, p.Directory)
		}
	case *pm.UpdateActionParamsRequest_User:
		if p.User != nil {
			return Validate(ctx, p.User)
		}
	case *pm.UpdateActionParamsRequest_Ssh:
		if p.Ssh != nil {
			return Validate(ctx, p.Ssh)
		}
	case *pm.UpdateActionParamsRequest_Sshd:
		if p.Sshd != nil {
			return Validate(ctx, p.Sshd)
		}
	case *pm.UpdateActionParamsRequest_AdminPolicy:
		if p.AdminPolicy != nil {
			return Validate(ctx, p.AdminPolicy)
		}
	case *pm.UpdateActionParamsRequest_Lps:
		if p.Lps != nil {
			return Validate(ctx, p.Lps)
		}
	case *pm.UpdateActionParamsRequest_Encryption:
		if p.Encryption != nil {
			return Validate(ctx, p.Encryption)
		}
	case *pm.UpdateActionParamsRequest_Group:
		if p.Group != nil {
			return Validate(ctx, p.Group)
		}
	case *pm.UpdateActionParamsRequest_Wifi:
		if p.Wifi != nil {
			return Validate(ctx, p.Wifi)
		}
	case *pm.UpdateActionParamsRequest_AgentUpdate:
		if p.AgentUpdate != nil {
			return validateAgentUpdateParams(ctx, p.AgentUpdate)
		}
	}
	return nil
}

// validateAgentUpdateParams checks that at least one arch is set and all URLs are HTTPS.
func validateAgentUpdateParams(ctx context.Context, p *pm.AgentUpdateParams) error {
	if err := Validate(ctx, p); err != nil {
		return err
	}
	if p.Amd64 == nil && p.Arm64 == nil {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one architecture (amd64 or arm64) must be specified")
	}
	for _, arch := range []*pm.AgentUpdateArch{p.Amd64, p.Arm64} {
		if arch == nil {
			continue
		}
		if !strings.HasPrefix(arch.BinaryUrl, "https://") {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "binary_url must use HTTPS")
		}
		if !strings.HasPrefix(arch.ChecksumUrl, "https://") {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "checksum_url must use HTTPS")
		}
	}
	return nil
}

