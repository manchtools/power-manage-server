package api_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestStartTerminal_ScopeGate covers the #7 device-group scope gate on
// the web session-start RPC: a StartTerminal:scope=dgX holder may open a
// session only on devices in dgX; a global StartTerminal holder reaches
// any device.
func TestStartTerminal_ScopeGate(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h, _ := newTerminalHandler(t, st)

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setLinuxUsername(t, st, userID, "alice")
	dgX := testutil.CreateTestDeviceGroup(t, st, userID, "Plant X")
	devIn := testutil.CreateTestDevice(t, st, "host-in")
	devOut := testutil.CreateTestDevice(t, st, "host-out")
	testutil.AddDeviceToTestGroup(t, st, userID, dgX, devIn)

	scopedCtx := testutil.AuthContextScoped(userID, "u@test.com", []string{"StartTerminal"},
		[]auth.ScopedGrant{{Permission: "StartTerminal", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: dgX}})

	t.Run("in-scope device allowed", func(t *testing.T) {
		_, err := h.StartTerminal(scopedCtx, connect.NewRequest(&pm.StartTerminalRequest{DeviceId: devIn}))
		require.NoError(t, err)
	})
	t.Run("out-of-scope device denied", func(t *testing.T) {
		_, err := h.StartTerminal(scopedCtx, connect.NewRequest(&pm.StartTerminalRequest{DeviceId: devOut}))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
	t.Run("global StartTerminal reaches any device", func(t *testing.T) {
		globalCtx := testutil.AuthContextScoped(userID, "u@test.com", []string{"StartTerminal"},
			[]auth.ScopedGrant{{Permission: "StartTerminal"}})
		_, err := h.StartTerminal(globalCtx, connect.NewRequest(&pm.StartTerminalRequest{DeviceId: devOut}))
		require.NoError(t, err)
	})
}
