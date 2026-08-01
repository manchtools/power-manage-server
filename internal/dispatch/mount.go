package dispatch

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

// MountActions registers the direct singleton dispatch procedures.
func (h *Handlers) MountActions(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("dispatch: mux is required")
	}
	mounted := make([]string, 0, 6)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceDispatchActionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDispatchActionProcedure, h.DispatchAction, opts...))
	register(powermanagev1connect.ControlServiceDispatchInstantActionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDispatchInstantActionProcedure, h.DispatchInstantAction, opts...))
	register(powermanagev1connect.ControlServiceDispatchActionSetProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDispatchActionSetProcedure, h.DispatchActionSet, opts...))
	register(powermanagev1connect.ControlServiceDispatchDefinitionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDispatchDefinitionProcedure, h.DispatchDefinition, opts...))
	register(powermanagev1connect.ControlServiceDispatchToMultipleProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDispatchToMultipleProcedure, h.DispatchToMultiple, opts...))
	register(powermanagev1connect.ControlServiceDispatchToGroupProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDispatchToGroupProcedure, h.DispatchToGroup, opts...))
	return mounted
}

// MutationProcedures is the exact audited dispatch surface implemented here.
func MutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceDispatchActionProcedure,
		powermanagev1connect.ControlServiceDispatchInstantActionProcedure,
		powermanagev1connect.ControlServiceDispatchActionSetProcedure,
		powermanagev1connect.ControlServiceDispatchDefinitionProcedure,
		powermanagev1connect.ControlServiceDispatchToMultipleProcedure,
		powermanagev1connect.ControlServiceDispatchToGroupProcedure,
	}
}
