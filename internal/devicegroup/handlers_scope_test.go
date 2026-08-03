package devicegroup_test

import (
	"context"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/devicegroup"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testdb"
)

func newID() string { return ulid.Make().String() }

func newScopeFixture(t *testing.T) (*devicegroup.Handlers, *testdb.DB) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "power-manage.db")
	st, err := store.New(ctx, path)
	require.NoError(t, err)
	t.Cleanup(st.Close)
	raw, err := testdb.Open(ctx, path)
	require.NoError(t, err)
	t.Cleanup(raw.Close)
	return devicegroup.NewHandlers(devicegroup.HandlersConfig{Store: st}), raw
}

func seedScopedDevice(t *testing.T, raw *testdb.DB, groupID, deviceID string) {
	t.Helper()
	ctx := context.Background()
	_, err := raw.Exec(ctx,
		`INSERT INTO devices (id, hostname, agent_sealing_public_key) VALUES ($1, $2, $3)`,
		deviceID, "host-"+deviceID, make([]byte, 32))
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `INSERT INTO device_groups (id, name) VALUES ($1, $2)`, groupID, "grp-"+groupID)
	require.NoError(t, err)
	_, err = raw.Exec(ctx,
		`INSERT INTO device_group_members (group_id, device_id, added_at) VALUES ($1, $2, CURRENT_TIMESTAMP)`,
		groupID, deviceID)
	require.NoError(t, err)
}

func scopedCaller(scopeGroupID string) *auth.UserContext {
	return &auth.UserContext{
		ID: newID(), Kind: auth.PrincipalUser,
		Permissions: []string{"ListDeviceGroupsForDevice"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListDeviceGroupsForDevice",
			ScopeKind:  auth.ScopeKindDeviceGroup, ScopeID: scopeGroupID,
		}},
	}
}

func unrestrictedCaller() *auth.UserContext {
	return &auth.UserContext{
		ID: newID(), Kind: auth.PrincipalUser,
		Permissions: []string{"ListDeviceGroupsForDevice"},
	}
}

// TestListDeviceGroupsForDevice_OutOfScopeDeviceIsNotAnExistenceOracle proves a
// scope-restricted caller cannot distinguish a device outside its scope from a
// nonexistent one: both read as NotFound, matching how GetDeviceGroup and
// device.GetDevice fold out-of-scope access. Before the fix an existing
// out-of-scope device returned OK with an empty group list, leaking existence.
func TestListDeviceGroupsForDevice_OutOfScopeDeviceIsNotAnExistenceOracle(t *testing.T) {
	h, raw := newScopeFixture(t)
	ctx := context.Background()

	scopeGroup := newID()
	inScopeDevice := newID()
	seedScopedDevice(t, raw, scopeGroup, inScopeDevice)

	otherGroup := newID()
	outOfScopeDevice := newID()
	seedScopedDevice(t, raw, otherGroup, outOfScopeDevice)

	call := func(caller *auth.UserContext, deviceID string) (*connect.Response[pmv1.ListDeviceGroupsForDeviceResponse], error) {
		return h.ListDeviceGroupsForDevice(auth.WithUser(ctx, caller),
			connect.NewRequest(&pmv1.ListDeviceGroupsForDeviceRequest{DeviceId: deviceID}))
	}

	t.Run("restricted caller: out-of-scope existing device reads as NotFound", func(t *testing.T) {
		_, err := call(scopedCaller(scopeGroup), outOfScopeDevice)
		require.Error(t, err)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err),
			"an out-of-scope device must not be an existence oracle")
	})

	t.Run("restricted caller: in-scope device returns its visible groups", func(t *testing.T) {
		resp, err := call(scopedCaller(scopeGroup), inScopeDevice)
		require.NoError(t, err)
		require.NotNil(t, resp)
		ids := make([]string, 0, len(resp.Msg.Groups))
		for _, g := range resp.Msg.Groups {
			ids = append(ids, g.Id)
		}
		assert.Contains(t, ids, scopeGroup)
	})

	t.Run("restricted caller: nonexistent device reads as NotFound", func(t *testing.T) {
		_, err := call(scopedCaller(scopeGroup), newID())
		require.Error(t, err)
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})

	t.Run("unrestricted caller is unaffected by scope", func(t *testing.T) {
		resp, err := call(unrestrictedCaller(), outOfScopeDevice)
		require.NoError(t, err)
		require.NotNil(t, resp)
		ids := make([]string, 0, len(resp.Msg.Groups))
		for _, g := range resp.Msg.Groups {
			ids = append(ids, g.Id)
		}
		assert.Contains(t, ids, otherGroup, "an unrestricted caller still sees the device's groups")
	})
}
