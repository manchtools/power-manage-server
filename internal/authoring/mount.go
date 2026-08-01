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

// MountActionSets registers exactly the explicit ActionSet CRUD procedures.
func (h *Handlers) MountActionSets(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("authoring: mux is required")
	}
	mounted := make([]string, 0, 10)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceCreateActionSetProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateActionSetProcedure, h.CreateActionSet, opts...))
	register(powermanagev1connect.ControlServiceGetActionSetProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetActionSetProcedure, h.GetActionSet, opts...))
	register(powermanagev1connect.ControlServiceListActionSetsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListActionSetsProcedure, h.ListActionSets, opts...))
	register(powermanagev1connect.ControlServiceRenameActionSetProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRenameActionSetProcedure, h.RenameActionSet, opts...))
	register(powermanagev1connect.ControlServiceUpdateActionSetDescriptionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateActionSetDescriptionProcedure, h.UpdateActionSetDescription, opts...))
	register(powermanagev1connect.ControlServiceUpdateActionSetScheduleProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUpdateActionSetScheduleProcedure, h.UpdateActionSetSchedule, opts...))
	register(powermanagev1connect.ControlServiceDeleteActionSetProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteActionSetProcedure, h.DeleteActionSet, opts...))
	register(powermanagev1connect.ControlServiceAddActionToSetProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceAddActionToSetProcedure, h.AddActionToSet, opts...))
	register(powermanagev1connect.ControlServiceRemoveActionFromSetProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRemoveActionFromSetProcedure, h.RemoveActionFromSet, opts...))
	register(powermanagev1connect.ControlServiceReorderActionInSetProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceReorderActionInSetProcedure, h.ReorderActionInSet, opts...))
	return mounted
}

// ActionSetMutationProcedures is the exact audited ActionSet mutation surface.
func ActionSetMutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceCreateActionSetProcedure,
		powermanagev1connect.ControlServiceRenameActionSetProcedure,
		powermanagev1connect.ControlServiceUpdateActionSetDescriptionProcedure,
		powermanagev1connect.ControlServiceUpdateActionSetScheduleProcedure,
		powermanagev1connect.ControlServiceDeleteActionSetProcedure,
		powermanagev1connect.ControlServiceAddActionToSetProcedure,
		powermanagev1connect.ControlServiceRemoveActionFromSetProcedure,
		powermanagev1connect.ControlServiceReorderActionInSetProcedure,
	}
}

// ActionSetReadProcedures is the exact non-mutating ActionSet surface.
func ActionSetReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceGetActionSetProcedure,
		powermanagev1connect.ControlServiceListActionSetsProcedure,
	}
}
