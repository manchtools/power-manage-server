package enrollment

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

// Mount registers exactly the two device-credential procedures.
func (h *Handlers) Mount(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("enrollment: mux is required")
	}
	mux.Handle(powermanagev1connect.ControlServiceRegisterProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRegisterProcedure, h.Register, opts...))
	mux.Handle(powermanagev1connect.ControlServiceRenewCertificateProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRenewCertificateProcedure, h.RenewCertificate, opts...))
	return []string{
		powermanagev1connect.ControlServiceRegisterProcedure,
		powermanagev1connect.ControlServiceRenewCertificateProcedure,
	}
}

// MutationProcedures is the exact audited enrollment surface.
func MutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceRegisterProcedure,
		powermanagev1connect.ControlServiceRenewCertificateProcedure,
	}
}
