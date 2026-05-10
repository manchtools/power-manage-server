// Stubs added in PR #195 step 1 (foundation). Real implementations land in PR #195 step 2 alongside the events + RBAC permissions.
package api

import (
	"context"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// SetDeviceGroupVariable is a foundation-step stub (#195).
func (s *ControlService) SetDeviceGroupVariable(ctx context.Context, _ *connect.Request[pm.SetDeviceGroupVariableRequest]) (*connect.Response[pm.SetDeviceGroupVariableResponse], error) {
	return nil, apiErrorCtx(ctx, ErrUnimplemented, connect.CodeUnimplemented, "group variables not yet wired")
}

// DeleteDeviceGroupVariable is a foundation-step stub (#195).
func (s *ControlService) DeleteDeviceGroupVariable(ctx context.Context, _ *connect.Request[pm.DeleteDeviceGroupVariableRequest]) (*connect.Response[pm.DeleteDeviceGroupVariableResponse], error) {
	return nil, apiErrorCtx(ctx, ErrUnimplemented, connect.CodeUnimplemented, "group variables not yet wired")
}

// GetDeviceGroupVariables is a foundation-step stub (#195).
func (s *ControlService) GetDeviceGroupVariables(ctx context.Context, _ *connect.Request[pm.GetDeviceGroupVariablesRequest]) (*connect.Response[pm.GetDeviceGroupVariablesResponse], error) {
	return nil, apiErrorCtx(ctx, ErrUnimplemented, connect.CodeUnimplemented, "group variables not yet wired")
}

// SetUserGroupVariable is a foundation-step stub (#195).
func (s *ControlService) SetUserGroupVariable(ctx context.Context, _ *connect.Request[pm.SetUserGroupVariableRequest]) (*connect.Response[pm.SetUserGroupVariableResponse], error) {
	return nil, apiErrorCtx(ctx, ErrUnimplemented, connect.CodeUnimplemented, "group variables not yet wired")
}

// DeleteUserGroupVariable is a foundation-step stub (#195).
func (s *ControlService) DeleteUserGroupVariable(ctx context.Context, _ *connect.Request[pm.DeleteUserGroupVariableRequest]) (*connect.Response[pm.DeleteUserGroupVariableResponse], error) {
	return nil, apiErrorCtx(ctx, ErrUnimplemented, connect.CodeUnimplemented, "group variables not yet wired")
}

// GetUserGroupVariables is a foundation-step stub (#195).
func (s *ControlService) GetUserGroupVariables(ctx context.Context, _ *connect.Request[pm.GetUserGroupVariablesRequest]) (*connect.Response[pm.GetUserGroupVariablesResponse], error) {
	return nil, apiErrorCtx(ctx, ErrUnimplemented, connect.CodeUnimplemented, "group variables not yet wired")
}

// ListAvailableVariables is a foundation-step stub (#195).
func (s *ControlService) ListAvailableVariables(ctx context.Context, _ *connect.Request[pm.ListAvailableVariablesRequest]) (*connect.Response[pm.ListAvailableVariablesResponse], error) {
	return nil, apiErrorCtx(ctx, ErrUnimplemented, connect.CodeUnimplemented, "group variables not yet wired")
}
