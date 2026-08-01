package controlrpc

import (
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
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

func TestMountIsExactControlServiceDescriptorSet(t *testing.T) {
	handlers := Handlers{
		Identity: &identity.Handlers{}, Enrollment: &enrollment.Handlers{},
		Authoring: &authoring.Handlers{}, Assignments: &assignment.Handlers{},
		DeviceGroups: &devicegroup.Handlers{}, Devices: &device.Handlers{},
		RegistrationTokens: &registrationtoken.Handlers{}, Compliance: &compliance.Handlers{},
		Dispatch: &dispatch.Handlers{}, Search: &searchrpc.Handlers{},
	}
	mounted := handlers.Mount(http.NewServeMux())
	got := make(map[string]struct{}, len(mounted))
	var duplicates []string
	for _, procedure := range mounted {
		if _, exists := got[procedure]; exists {
			duplicates = append(duplicates, procedure)
		}
		got[procedure] = struct{}{}
	}
	assert.Empty(t, duplicates, "one procedure must have one direct owner")

	service := pmv1.File_powermanage_v1_control_proto.Services().ByName("ControlService")
	require.NotNil(t, service)
	want := make(map[string]struct{}, service.Methods().Len())
	for i := 0; i < service.Methods().Len(); i++ {
		method := service.Methods().Get(i)
		want[fmt.Sprintf("/%s/%s", service.FullName(), method.Name())] = struct{}{}
	}

	var missing, extra []string
	for procedure := range want {
		if _, exists := got[procedure]; !exists {
			missing = append(missing, procedure)
		}
	}
	for procedure := range got {
		if _, exists := want[procedure]; !exists {
			extra = append(extra, procedure)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	assert.Empty(t, missing)
	assert.Empty(t, extra)
	assert.Len(t, mounted, service.Methods().Len())
}
