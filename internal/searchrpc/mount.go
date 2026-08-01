package searchrpc

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

// Mount registers exactly the PostgreSQL search procedures.
func (h *Handlers) Mount(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("search: mux is required")
	}
	mounted := make([]string, 0, 2)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceSearchProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceSearchProcedure, h.Search, opts...))
	register(powermanagev1connect.ControlServiceRebuildSearchIndexProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRebuildSearchIndexProcedure, h.RebuildSearchIndex, opts...))
	return mounted
}

// ReadProcedures is the exact non-mutating search surface.
func ReadProcedures() []string {
	return []string{powermanagev1connect.ControlServiceSearchProcedure}
}

// MutationProcedures is the exact audited search-maintenance surface.
func MutationProcedures() []string {
	return []string{powermanagev1connect.ControlServiceRebuildSearchIndexProcedure}
}
