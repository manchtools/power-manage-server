package authoring

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

// MountActions registers exactly the explicit Action CRUD procedures.
func (h *Handlers) MountActions(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("authoring: mux is required")
	}
	mounted := make([]string, 0, 7)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceCreateActionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateActionProcedure, h.CreateAction, opts...))
	register(powermanagev1connect.ControlServiceGetActionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetActionProcedure, h.GetAction, opts...))
	register(powermanagev1connect.ControlServiceListActionsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListActionsProcedure, h.ListActions, opts...))
	register(powermanagev1connect.ControlServiceRenameActionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRenameActionProcedure, h.RenameAction, opts...))
	register(powermanagev1connect.ControlServiceUpdateActionDescriptionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateActionDescriptionProcedure, h.UpdateActionDescription, opts...))
	register(powermanagev1connect.ControlServiceUpdateActionParamsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateActionParamsProcedure, h.UpdateActionParams, opts...))
	register(powermanagev1connect.ControlServiceDeleteActionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteActionProcedure, h.DeleteAction, opts...))
	return mounted
}

// ActionMutationProcedures is the exact audited Action mutation surface.
func ActionMutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceCreateActionProcedure,
		powermanagev1connect.ControlServiceRenameActionProcedure,
		powermanagev1connect.ControlServiceUpdateActionDescriptionProcedure,
		powermanagev1connect.ControlServiceUpdateActionParamsProcedure,
		powermanagev1connect.ControlServiceDeleteActionProcedure,
	}
}

// ActionReadProcedures is the exact non-mutating Action surface.
func ActionReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceGetActionProcedure,
		powermanagev1connect.ControlServiceListActionsProcedure,
	}
}
