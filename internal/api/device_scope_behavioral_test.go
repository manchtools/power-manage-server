package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// deviceScopeDriver drives one device-targeted RPC for the behavioral
// out-of-scope confinement sweep. The device family confines via
// EnforceDeviceScopeOnBaseTier (which delegates to EnforceDeviceScope), returning
// PermissionDenied uniformly for an out-of-scope device — read and write alike,
// per the S10 decision; the device family does not use the object family's
// NotFound existence oracle.
//
// For write RPCs, readState returns the mutable state (via a privileged read) so
// the sweep can assert a denied call left it unchanged AND an allowed call
// changed it to afterAllowed. nil readState marks a read RPC (nothing to mutate).
type deviceScopeDriver struct {
	rpc          string // the RPC name, which is also the permission key
	call         func(ctx context.Context, st *store.Store, deviceID string) error
	readState    func(t *testing.T, st *store.Store, adminID, deviceID string) any
	afterAllowed any
}

func deviceScopeDrivers() []deviceScopeDriver {
	logger := slog.Default()
	dev := func(st *store.Store) *api.DeviceHandler {
		return api.NewDeviceHandler(st, nil, logger, api.NoOpSigner{})
	}
	getDevice := func(st *store.Store, adminID, id string) (*pm.Device, error) {
		resp, err := dev(st).GetDevice(testutil.AdminContext(adminID), connect.NewRequest(&pm.GetDeviceRequest{Id: id}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetDevice(), nil
	}
	return []deviceScopeDriver{
		{
			rpc: "GetDevice",
			call: func(ctx context.Context, st *store.Store, deviceID string) error {
				_, err := dev(st).GetDevice(ctx, connect.NewRequest(&pm.GetDeviceRequest{Id: deviceID}))
				return err
			},
		},
		{
			rpc: "SetDeviceSyncInterval",
			call: func(ctx context.Context, st *store.Store, deviceID string) error {
				_, err := dev(st).SetDeviceSyncInterval(ctx, connect.NewRequest(&pm.SetDeviceSyncIntervalRequest{Id: deviceID, SyncIntervalMinutes: 60}))
				return err
			},
			readState: func(t *testing.T, st *store.Store, adminID, deviceID string) any {
				d, err := getDevice(st, adminID, deviceID)
				require.NoError(t, err)
				return d.GetSyncIntervalMinutes()
			},
			afterAllowed: int32(60),
		},
		{
			rpc: "DeleteDevice",
			call: func(ctx context.Context, st *store.Store, deviceID string) error {
				_, err := dev(st).DeleteDevice(ctx, connect.NewRequest(&pm.DeleteDeviceRequest{Id: deviceID}))
				return err
			},
			// State is device existence: true until an allowed delete removes it.
			readState: func(t *testing.T, st *store.Store, adminID, deviceID string) any {
				_, err := getDevice(st, adminID, deviceID)
				return err == nil
			},
			afterAllowed: false,
		},
	}
}

// TestDeviceScopeHandlers_ConfineOutOfScope drives representative SCOPABLE
// (TargetDevice) device RPCs (read, interval write, delete) through the real
// handler with a device-group-scoped caller and an out-of-scope device (a member
// of a DIFFERENT group), asserting PermissionDenied. For write RPCs it reads the
// device back with a privileged caller to assert the denied call did NOT mutate
// and the in-scope positive control DID. Org-tier device RPCs
// (SetDeviceLabel/AssignDevice, which are TargetUnspecified in AllPermissions)
// are deliberately NOT device-group-scoped and so are not part of this sweep.
//
// Per-RPC completeness for the device family is held by the AST permission guard
// (TestScopablePermissions_AllEnforced): every TargetDevice permission, which is
// its RPC name, must be passed to a recognized scope enforcer. This sweep adds
// the behavioral proof that the enforcer actually confines at runtime.
func TestDeviceScopeHandlers_ConfineOutOfScope(t *testing.T) {
	drivers := deviceScopeDrivers()
	require.NotEmpty(t, drivers, "no device scope drivers — the sweep would pass vacuously")

	for _, d := range drivers {
		t.Run(d.rpc, func(t *testing.T) {
			st := testutil.SetupPostgres(t)
			admin := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")
			dgA := testutil.CreateTestDeviceGroup(t, st, admin, "Fleet A")
			dgB := testutil.CreateTestDeviceGroup(t, st, admin, "Fleet B")
			device := testutil.CreateTestDevice(t, st, "host-"+d.rpc)
			testutil.AddDeviceToTestGroup(t, st, admin, dgA, device)

			var before any
			if d.readState != nil {
				before = d.readState(t, st, admin, device)
			}

			// Caller scoped to dgB; the device is a member of dgA.
			err := d.call(deviceScoped(testutil.NewID(), d.rpc, dgB), st, device)
			require.Errorf(t, err, "%s: out-of-scope device op must error", d.rpc)
			assert.Equalf(t, connect.CodePermissionDenied, connect.CodeOf(err),
				"%s: out-of-scope device op must be PermissionDenied; got %v", d.rpc, connect.CodeOf(err))
			if d.readState != nil {
				assert.Equalf(t, before, d.readState(t, st, admin, device),
					"%s: a denied write must NOT persist", d.rpc)
			}

			// Positive control: a caller scoped to dgA (the device's group) succeeds
			// and the write actually persists.
			require.NoErrorf(t, d.call(deviceScoped(testutil.NewID(), d.rpc, dgA), st, device),
				"%s: in-scope device op must succeed", d.rpc)
			if d.readState != nil {
				assert.Equalf(t, d.afterAllowed, d.readState(t, st, admin, device),
					"%s: an allowed write must persist", d.rpc)
			}
		})
	}
}
