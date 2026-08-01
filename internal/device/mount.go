package device

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

// Mount registers exactly the device CRUD procedures implemented here.
func (h *Handlers) Mount(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil {
		panic("device: mux is required")
	}
	mounted := make([]string, 0, 12)
	register := func(procedure string, handler http.Handler) {
		mux.Handle(procedure, handler)
		mounted = append(mounted, procedure)
	}
	register(powermanagev1connect.ControlServiceListDevicesProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListDevicesProcedure, h.ListDevices, opts...))
	register(powermanagev1connect.ControlServiceGetDeviceProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetDeviceProcedure, h.GetDevice, opts...))
	register(powermanagev1connect.ControlServiceGetDeviceInventoryProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetDeviceInventoryProcedure, h.GetDeviceInventory, opts...))
	register(powermanagev1connect.ControlServiceGetOSQueryResultProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetOSQueryResultProcedure, h.GetOSQueryResult, opts...))
	register(powermanagev1connect.ControlServiceSetDeviceLabelProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetDeviceLabelProcedure, h.SetDeviceLabel, opts...))
	register(powermanagev1connect.ControlServiceRemoveDeviceLabelProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRemoveDeviceLabelProcedure, h.RemoveDeviceLabel, opts...))
	register(powermanagev1connect.ControlServiceAssignDeviceProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceAssignDeviceProcedure, h.AssignDevice, opts...))
	register(powermanagev1connect.ControlServiceUnassignDeviceProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceUnassignDeviceProcedure, h.UnassignDevice, opts...))
	register(powermanagev1connect.ControlServiceListDeviceAssigneesProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListDeviceAssigneesProcedure, h.ListDeviceAssignees, opts...))
	register(powermanagev1connect.ControlServiceSetDeviceSyncIntervalProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetDeviceSyncIntervalProcedure, h.SetDeviceSyncInterval, opts...))
	register(powermanagev1connect.ControlServiceSetDeviceInventoryIntervalProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceSetDeviceInventoryIntervalProcedure, h.SetDeviceInventoryInterval, opts...))
	register(powermanagev1connect.ControlServiceDeleteDeviceProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDeleteDeviceProcedure, h.DeleteDevice, opts...))
	return mounted
}

// MutationProcedures is the exact audited device mutation surface.
func MutationProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceSetDeviceLabelProcedure,
		powermanagev1connect.ControlServiceRemoveDeviceLabelProcedure,
		powermanagev1connect.ControlServiceAssignDeviceProcedure,
		powermanagev1connect.ControlServiceUnassignDeviceProcedure,
		powermanagev1connect.ControlServiceSetDeviceSyncIntervalProcedure,
		powermanagev1connect.ControlServiceSetDeviceInventoryIntervalProcedure,
		powermanagev1connect.ControlServiceDeleteDeviceProcedure,
	}
}

// ReadProcedures is the exact non-mutating device surface.
func ReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceListDevicesProcedure,
		powermanagev1connect.ControlServiceGetDeviceProcedure,
		powermanagev1connect.ControlServiceGetDeviceInventoryProcedure,
		powermanagev1connect.ControlServiceGetOSQueryResultProcedure,
		powermanagev1connect.ControlServiceListDeviceAssigneesProcedure,
	}
}
