package store_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/dynamicquery"
	"github.com/manchtools/power-manage/server/internal/dyngroupeval"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// newEvalSvc returns a dyngroupeval.Evaluator wired against the test
// store. The tests in this file used to count matching devices via the
// PL/pgSQL CountMatchingDevicesForQuery; Wave C.5 dropped that function
// in favour of the in-process evaluator. Behaviour is unchanged.
func newEvalSvc(st *store.Store) *dyngroupeval.Evaluator {
	return dyngroupeval.New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// addDeviceToGroup emits a DeviceAddedToGroup event.
func addDeviceToGroup(t *testing.T, st *store.Store, groupID, deviceID, actorID string) {
	t.Helper()
	err := st.AppendEvent(context.Background(), store.Event{
		StreamType: "device_group",
		StreamID:   groupID,
		EventType:  "DeviceAddedToGroup",
		Data:       map[string]any{"device_id": deviceID},
		ActorType:  "user",
		ActorID:    actorID,
	})
	require.NoError(t, err)
}

func TestDynamicGroupQuery_DeviceGroupEquals(t *testing.T) {
	st := testutil.SetupPostgres(t)
	evalSvc := newEvalSvc(st)
	ctx := context.Background()
	actor := testutil.NewID()

	device := testutil.CreateTestDevice(t, st, "server-01")
	group := testutil.CreateTestDeviceGroup(t, st, actor, "Production")
	addDeviceToGroup(t, st, group, device, actor)

	count, err := evalSvc.CountMatchingDevices(ctx, `device.group equals "Production"`)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestDynamicGroupQuery_DeviceGroupNotEquals(t *testing.T) {
	st := testutil.SetupPostgres(t)
	evalSvc := newEvalSvc(st)
	ctx := context.Background()
	actor := testutil.NewID()

	device := testutil.CreateTestDevice(t, st, "server-01")
	group := testutil.CreateTestDeviceGroup(t, st, actor, "Production")
	addDeviceToGroup(t, st, group, device, actor)

	count, err := evalSvc.CountMatchingDevices(ctx, `device.group notEquals "Staging"`)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = evalSvc.CountMatchingDevices(ctx, `device.group notEquals "Production"`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestDynamicGroupQuery_DeviceGroupContains(t *testing.T) {
	st := testutil.SetupPostgres(t)
	evalSvc := newEvalSvc(st)
	ctx := context.Background()
	actor := testutil.NewID()

	device := testutil.CreateTestDevice(t, st, "server-01")
	group := testutil.CreateTestDeviceGroup(t, st, actor, "Berlin Office Servers")
	addDeviceToGroup(t, st, group, device, actor)

	count, err := evalSvc.CountMatchingDevices(ctx, `device.group contains "Berlin"`)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = evalSvc.CountMatchingDevices(ctx, `device.group contains "Munich"`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestDynamicGroupQuery_DeviceGroupIn(t *testing.T) {
	st := testutil.SetupPostgres(t)
	evalSvc := newEvalSvc(st)
	ctx := context.Background()
	actor := testutil.NewID()

	device := testutil.CreateTestDevice(t, st, "server-01")
	group := testutil.CreateTestDeviceGroup(t, st, actor, "Production")
	addDeviceToGroup(t, st, group, device, actor)

	count, err := evalSvc.CountMatchingDevices(ctx, `device.group in "Production,Staging"`)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = evalSvc.CountMatchingDevices(ctx, `device.group in "Staging,Development"`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestDynamicGroupQuery_DeviceGroupExists(t *testing.T) {
	st := testutil.SetupPostgres(t)
	evalSvc := newEvalSvc(st)
	ctx := context.Background()
	actor := testutil.NewID()

	deviceInGroup := testutil.CreateTestDevice(t, st, "server-01")
	testutil.CreateTestDevice(t, st, "server-02") // not in any group
	group := testutil.CreateTestDeviceGroup(t, st, actor, "Production")
	addDeviceToGroup(t, st, group, deviceInGroup, actor)

	count, err := evalSvc.CountMatchingDevices(ctx, `device.group exists`)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = evalSvc.CountMatchingDevices(ctx, `device.group notExists`)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestDynamicGroupQuery_DeviceGroupCombinedWithLabel(t *testing.T) {
	st := testutil.SetupPostgres(t)
	evalSvc := newEvalSvc(st)
	ctx := context.Background()
	actor := testutil.NewID()

	device := testutil.CreateTestDevice(t, st, "server-01")
	group := testutil.CreateTestDeviceGroup(t, st, actor, "Production")
	addDeviceToGroup(t, st, group, device, actor)

	// Set a label on the device
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   device,
		EventType:  "DeviceLabelSet",
		Data:       map[string]any{"key": "env", "value": "prod"},
		ActorType:  "user",
		ActorID:    actor,
	})
	require.NoError(t, err)

	// Both conditions match
	count, err := evalSvc.CountMatchingDevices(ctx, `(device.group equals "Production") AND (device.labels.env equals "prod")`)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Group matches, label doesn't
	count, err = evalSvc.CountMatchingDevices(ctx, `(device.group equals "Production") AND (device.labels.env equals "staging")`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestDynamicGroupQuery_DeviceGroupValidation(t *testing.T) {
	// Pure validation — no DB needed since the Go validator parses
	// the query string in-process. testutil.SetupPostgres is skipped
	// here so the test stays fast.
	require.NoError(t, dynamicquery.ValidateDeviceQuery(`device.group equals "Production"`))
	require.NoError(t, dynamicquery.ValidateDeviceQuery(`device.group exists`))
	require.NoError(t, dynamicquery.ValidateDeviceQuery(`device.group in "A,B,C"`))
}

func TestDynamicGroupQuery_MultipleGroups(t *testing.T) {
	st := testutil.SetupPostgres(t)
	evalSvc := newEvalSvc(st)
	ctx := context.Background()
	actor := testutil.NewID()

	device := testutil.CreateTestDevice(t, st, "server-01")
	group1 := testutil.CreateTestDeviceGroup(t, st, actor, "Production")
	group2 := testutil.CreateTestDeviceGroup(t, st, actor, "Ubuntu")
	addDeviceToGroup(t, st, group1, device, actor)
	addDeviceToGroup(t, st, group2, device, actor)

	// Device is in both groups
	count, err := evalSvc.CountMatchingDevices(ctx, `(device.group equals "Production") AND (device.group equals "Ubuntu")`)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Device is in Production but not Staging
	count, err = evalSvc.CountMatchingDevices(ctx, `(device.group equals "Production") AND (device.group equals "Staging")`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}
