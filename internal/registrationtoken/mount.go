package registrationtoken

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

// Mount registers exactly the explicit registration-token procedures.
func (h *Handlers) Mount(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("registrationtoken: mux is required")
	}
	mounted := make([]string, 0, 6)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceCreateTokenProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateTokenProcedure, h.CreateToken, opts...))
	register(powermanagev1connect.ControlServiceGetTokenProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetTokenProcedure, h.GetToken, opts...))
	register(powermanagev1connect.ControlServiceListTokensProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListTokensProcedure, h.ListTokens, opts...))
	register(powermanagev1connect.ControlServiceRenameTokenProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRenameTokenProcedure, h.RenameToken, opts...))
	register(powermanagev1connect.ControlServiceSetTokenDisabledProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetTokenDisabledProcedure, h.SetTokenDisabled, opts...))
	register(powermanagev1connect.ControlServiceDeleteTokenProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteTokenProcedure, h.DeleteToken, opts...))
	return mounted
}

// MutationProcedures is the exact audited registration-token mutation set.
func MutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceCreateTokenProcedure,
		powermanagev1connect.ControlServiceRenameTokenProcedure,
		powermanagev1connect.ControlServiceSetTokenDisabledProcedure,
		powermanagev1connect.ControlServiceDeleteTokenProcedure,
	}
}

// ReadProcedures is the exact non-mutating registration-token set.
func ReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceGetTokenProcedure,
		powermanagev1connect.ControlServiceListTokensProcedure,
	}
}
