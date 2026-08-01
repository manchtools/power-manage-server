// Package controlrpc assembles the explicit ControlService handlers.
package controlrpc

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/server/internal/assignment"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/compliance"
	"github.com/manchtools/power-manage/server/internal/device"
	"github.com/manchtools/power-manage/server/internal/devicegroup"
	"github.com/manchtools/power-manage/server/internal/dispatch"
	"github.com/manchtools/power-manage/server/internal/enrollment"
	"github.com/manchtools/power-manage/server/internal/identity"
	"github.com/manchtools/power-manage/server/internal/registrationtoken"
	"github.com/manchtools/power-manage/server/internal/searchrpc"
)

// Handlers is the complete direct implementation of ControlService. Keeping
// the domains explicit makes an omitted or duplicated procedure visible at
// assembly time instead of silently falling through an embedded mega-handler.
type Handlers struct {
	Identity           *identity.Handlers
	Enrollment         *enrollment.Handlers
	Authoring          *authoring.Handlers
	Assignments        *assignment.Handlers
	DeviceGroups       *devicegroup.Handlers
	Devices            *device.Handlers
	RegistrationTokens *registrationtoken.Handlers
	Compliance         *compliance.Handlers
	Dispatch           *dispatch.Handlers
	Search             *searchrpc.Handlers
}

// Mount registers the complete retained ControlService surface.
func (h Handlers) Mount(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	if mux == nil || h.Identity == nil || h.Enrollment == nil || h.Authoring == nil ||
		h.Assignments == nil || h.DeviceGroups == nil || h.Devices == nil ||
		h.RegistrationTokens == nil || h.Compliance == nil || h.Dispatch == nil || h.Search == nil {
		panic("controlrpc: complete handler wiring is required")
	}
	var mounted []string
	mounted = append(mounted, h.Identity.Mount(mux, opts...)...)
	mounted = append(mounted, h.Enrollment.Mount(mux, opts...)...)
	mounted = append(mounted, h.Authoring.MountActions(mux, opts...)...)
	mounted = append(mounted, h.Authoring.MountActionSets(mux, opts...)...)
	mounted = append(mounted, h.Authoring.MountDefinitions(mux, opts...)...)
	mounted = append(mounted, h.Assignments.Mount(mux, opts...)...)
	mounted = append(mounted, h.DeviceGroups.Mount(mux, opts...)...)
	mounted = append(mounted, h.Devices.Mount(mux, opts...)...)
	mounted = append(mounted, h.RegistrationTokens.Mount(mux, opts...)...)
	mounted = append(mounted, h.Compliance.MountPolicies(mux, opts...)...)
	mounted = append(mounted, h.Dispatch.MountActions(mux, opts...)...)
	mounted = append(mounted, h.Search.Mount(mux, opts...)...)
	return mounted
}
