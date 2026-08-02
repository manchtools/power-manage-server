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
	mounted := make([]string, 0, 31)
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
	register(powermanagev1connect.ControlServiceGetDeviceLogResultProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetDeviceLogResultProcedure, h.GetDeviceLogResult, opts...))
	register(powermanagev1connect.ControlServiceGetDeviceComplianceProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetDeviceComplianceProcedure, h.GetDeviceCompliance, opts...))
	register(powermanagev1connect.ControlServiceGetDeviceCompliancePolicyStatusProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetDeviceCompliancePolicyStatusProcedure, h.GetDeviceCompliancePolicyStatus, opts...))
	register(powermanagev1connect.ControlServiceGetExecutionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceGetExecutionProcedure, h.GetExecution, opts...))
	register(powermanagev1connect.ControlServiceListExecutionsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListExecutionsProcedure, h.ListExecutions, opts...))
	register(powermanagev1connect.ControlServiceCancelExecutionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCancelExecutionProcedure, h.CancelExecution, opts...))
	register(powermanagev1connect.ControlServiceListLpsPasswordsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListLpsPasswordsProcedure, h.ListLpsPasswords, opts...))
	register(powermanagev1connect.ControlServiceRevealLpsPasswordProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRevealLpsPasswordProcedure, h.RevealLpsPassword, opts...))
	register(powermanagev1connect.ControlServiceListLuksKeysProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListLuksKeysProcedure, h.ListLuksKeys, opts...))
	register(powermanagev1connect.ControlServiceRevealLuksKeyProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRevealLuksKeyProcedure, h.RevealLuksKey, opts...))
	register(powermanagev1connect.ControlServiceCreateLuksTokenProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateLuksTokenProcedure, h.CreateLuksToken, opts...))
	register(powermanagev1connect.ControlServiceRevokeLuksDeviceKeyProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRevokeLuksDeviceKeyProcedure, h.RevokeLuksDeviceKey, opts...))
	register(powermanagev1connect.ControlServiceDispatchOSQueryProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceDispatchOSQueryProcedure, h.DispatchOSQuery, opts...))
	register(powermanagev1connect.ControlServiceRefreshDeviceInventoryProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRefreshDeviceInventoryProcedure, h.RefreshDeviceInventory, opts...))
	register(powermanagev1connect.ControlServiceQueryDeviceLogsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceQueryDeviceLogsProcedure, h.QueryDeviceLogs, opts...))
	register(powermanagev1connect.ControlServiceStartTerminalProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceStartTerminalProcedure, h.StartTerminal, opts...))
	register(powermanagev1connect.ControlServiceStopTerminalProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceStopTerminalProcedure, h.StopTerminal, opts...))
	register(powermanagev1connect.ControlServiceListActiveTerminalSessionsProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceListActiveTerminalSessionsProcedure, h.ListActiveTerminalSessions, opts...))
	register(powermanagev1connect.ControlServiceTerminateTerminalSessionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceTerminateTerminalSessionProcedure, h.TerminateTerminalSession, opts...))
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
		powermanagev1connect.ControlServiceCancelExecutionProcedure,
		powermanagev1connect.ControlServiceCreateLuksTokenProcedure,
		powermanagev1connect.ControlServiceRevokeLuksDeviceKeyProcedure,
		powermanagev1connect.ControlServiceDispatchOSQueryProcedure,
		powermanagev1connect.ControlServiceRefreshDeviceInventoryProcedure,
		powermanagev1connect.ControlServiceQueryDeviceLogsProcedure,
		powermanagev1connect.ControlServiceStartTerminalProcedure,
		powermanagev1connect.ControlServiceStopTerminalProcedure,
		powermanagev1connect.ControlServiceTerminateTerminalSessionProcedure,
	}
}

// ReadProcedures is the exact non-mutating device surface.
func ReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceListDevicesProcedure,
		powermanagev1connect.ControlServiceGetDeviceProcedure,
		powermanagev1connect.ControlServiceListDeviceAssigneesProcedure,
	}
}

// SensitiveReadProcedures is the protected device-data surface that records
// evidence before returning inventory, query output, logs, or detection data.
func SensitiveReadProcedures() []string {
	return []string{
		powermanagev1connect.ControlServiceGetDeviceInventoryProcedure,
		powermanagev1connect.ControlServiceGetOSQueryResultProcedure,
		powermanagev1connect.ControlServiceGetDeviceLogResultProcedure,
		powermanagev1connect.ControlServiceGetDeviceComplianceProcedure,
		powermanagev1connect.ControlServiceGetDeviceCompliancePolicyStatusProcedure,
		powermanagev1connect.ControlServiceGetExecutionProcedure,
		powermanagev1connect.ControlServiceListExecutionsProcedure,
		powermanagev1connect.ControlServiceListLpsPasswordsProcedure,
		powermanagev1connect.ControlServiceRevealLpsPasswordProcedure,
		powermanagev1connect.ControlServiceListLuksKeysProcedure,
		powermanagev1connect.ControlServiceRevealLuksKeyProcedure,
		powermanagev1connect.ControlServiceListActiveTerminalSessionsProcedure,
	}
}
