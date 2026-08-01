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
	mounted := make([]string, 0, 2)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceDispatchActionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDispatchActionProcedure, h.DispatchAction, opts...))
	register(powermanagev1connect.ControlServiceDispatchInstantActionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDispatchInstantActionProcedure, h.DispatchInstantAction, opts...))
	return mounted
}

// MutationProcedures is the exact audited dispatch surface implemented here.
func MutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceDispatchActionProcedure,
		powermanagev1connect.ControlServiceDispatchInstantActionProcedure,
	}
}
