package store_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/devicegroup"
)

type deviceGroupHandlerFixture struct {
	*deviceHandlerFixture
	handlers *devicegroup.Handlers
}

func newDeviceGroupHandlerFixture(t *testing.T) *deviceGroupHandlerFixture {
	t.Helper()
	devices := newDeviceHandlerFixture(t)
	return &deviceGroupHandlerFixture{
		deviceHandlerFixture: devices,
		handlers: devicegroup.NewHandlers(devicegroup.HandlersConfig{
			Store: devices.store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Now: func() time.Time { return devices.now },
		}),
	}
}

func TestDeviceGroupHandlers_ValidateBeforeAuthentication(t *testing.T) {
	f := newDeviceGroupHandlerFixture(t)
	_, err := f.handlers.GetDeviceGroup(context.Background(), connect.NewRequest(&pmv1.GetDeviceGroupRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.GetDeviceGroup(context.Background(), connect.NewRequest(&pmv1.GetDeviceGroupRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestDeviceGroupHandlers_CRUDMembershipAndAudit(t *testing.T) {
	f := newDeviceGroupHandlerFixture(t)
	ctx := f.actor(
		"CreateStaticDeviceGroup", "CreateDynamicDeviceGroup", "GetDeviceGroup", "ListDeviceGroups",
		"ListDeviceGroupsForDevice", "RenameDeviceGroup", "UpdateDeviceGroupDescription",
		"UpdateDynamicDeviceGroupQuery", "DeleteDeviceGroup", "AddDeviceToGroup", "RemoveDeviceFromGroup",
		"SetDeviceGroupSyncInterval", "SetDeviceGroupInventoryInterval", "SetDeviceGroupMaintenanceWindow",
	)

	created, err := f.handlers.CreateDeviceGroup(ctx, connect.NewRequest(&pmv1.CreateDeviceGroupRequest{
		Name: "workstations", Description: "static fleet",
	}))
	require.NoError(t, err)
	id := created.Msg.Group.Id

	added, err := f.handlers.AddDeviceToGroup(ctx, connect.NewRequest(&pmv1.AddDeviceToGroupRequest{
		GroupId: id, DeviceId: f.directID, DeviceIds: []string{f.groupID, f.directID},
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(2), added.Msg.Group.MemberCount)

	got, err := f.handlers.GetDeviceGroup(ctx, connect.NewRequest(&pmv1.GetDeviceGroupRequest{Id: id}))
	require.NoError(t, err)
	require.Len(t, got.Msg.Devices, 2)
	assert.Len(t, got.Msg.DeviceIds, 2)

	removed, err := f.handlers.RemoveDeviceFromGroup(ctx, connect.NewRequest(&pmv1.RemoveDeviceFromGroupRequest{
		GroupId: id, DeviceId: f.directID,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), removed.Msg.Group.MemberCount)

	renamed, err := f.handlers.RenameDeviceGroup(ctx, connect.NewRequest(&pmv1.RenameDeviceGroupRequest{Id: id, Name: "renamed"}))
	require.NoError(t, err)
	assert.Equal(t, "renamed", renamed.Msg.Group.Name)
	described, err := f.handlers.UpdateDeviceGroupDescription(ctx, connect.NewRequest(&pmv1.UpdateDeviceGroupDescriptionRequest{
		Id: id, Description: "direct state",
	}))
	require.NoError(t, err)
	assert.Equal(t, "direct state", described.Msg.Group.Description)

	synced, err := f.handlers.SetDeviceGroupSyncInterval(ctx, connect.NewRequest(&pmv1.SetDeviceGroupSyncIntervalRequest{
		Id: id, SyncIntervalMinutes: 30,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(30), synced.Msg.Group.SyncIntervalMinutes)
	inventoried, err := f.handlers.SetDeviceGroupInventoryInterval(ctx, connect.NewRequest(&pmv1.SetDeviceGroupInventoryIntervalRequest{
		Id: id, InventoryIntervalMinutes: 120,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(120), inventoried.Msg.Group.InventoryIntervalMinutes)
	windowed, err := f.handlers.SetDeviceGroupMaintenanceWindow(ctx, connect.NewRequest(&pmv1.SetDeviceGroupMaintenanceWindowRequest{
		Id: id, MaintenanceWindow: &pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{{
			Days: []string{"mon"}, Allow: "09:00-17:00",
		}}},
	}))
	require.NoError(t, err)
	require.Len(t, windowed.Msg.Group.MaintenanceWindow.Schedule, 1)

	_, err = f.handlers.UpdateDeviceGroupQuery(ctx, connect.NewRequest(&pmv1.UpdateDeviceGroupQueryRequest{
		Id: id, IsDynamic: true, DynamicQuery: `device.labels.env equals prod`,
	}))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	dynamic, err := f.handlers.CreateDeviceGroup(ctx, connect.NewRequest(&pmv1.CreateDeviceGroupRequest{
		Name: "dynamic workstations", IsDynamic: true, DynamicQuery: `device.labels.env equals prod`,
	}))
	require.NoError(t, err)
	updatedQuery, err := f.handlers.UpdateDeviceGroupQuery(ctx, connect.NewRequest(&pmv1.UpdateDeviceGroupQueryRequest{
		Id: dynamic.Msg.Group.Id, IsDynamic: true, DynamicQuery: `device.hostname contains work`,
	}))
	require.NoError(t, err)
	assert.Equal(t, `device.hostname contains work`, updatedQuery.Msg.Group.DynamicQuery)
	_, err = f.handlers.AddDeviceToGroup(ctx, connect.NewRequest(&pmv1.AddDeviceToGroupRequest{
		GroupId: dynamic.Msg.Group.Id, DeviceId: f.outsideID,
	}))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))

	listed, err := f.handlers.ListDeviceGroups(ctx, connect.NewRequest(&pmv1.ListDeviceGroupsRequest{}))
	require.NoError(t, err)
	assert.NotEmpty(t, listed.Msg.Groups)
	assert.GreaterOrEqual(t, listed.Msg.TotalCount, int32(2))
	forDevice, err := f.handlers.ListDeviceGroupsForDevice(ctx, connect.NewRequest(&pmv1.ListDeviceGroupsForDeviceRequest{
		DeviceId: f.groupID,
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, forDevice.Msg.Groups)

	_, err = f.handlers.DeleteDeviceGroup(ctx, connect.NewRequest(&pmv1.DeleteDeviceGroupRequest{Id: id}))
	require.NoError(t, err)
	_, err = f.handlers.GetDeviceGroup(ctx, connect.NewRequest(&pmv1.GetDeviceGroupRequest{Id: id}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	for _, procedure := range devicegroup.MutationProcedures() {
		operation, err := latestOperationFor(t, f.store, f.raw, procedure)
		require.NoError(t, err, procedure)
		effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
		require.NoError(t, err, procedure)
		assert.NotEmpty(t, effects, procedure)
	}
}

func TestDeviceGroupHandlers_ShapeSpecificCreatePermissionAndScope(t *testing.T) {
	f := newDeviceGroupHandlerFixture(t)
	staticOnly := f.actor("CreateStaticDeviceGroup")
	_, err := f.handlers.CreateDeviceGroup(staticOnly, connect.NewRequest(&pmv1.CreateDeviceGroupRequest{
		Name: "denied", IsDynamic: true, DynamicQuery: `device.labels.env equals prod`,
	}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	dynamicOnly := f.actor("CreateDynamicDeviceGroup")
	created, err := f.handlers.CreateDeviceGroup(dynamicOnly, connect.NewRequest(&pmv1.CreateDeviceGroupRequest{
		Name: "dynamic", IsDynamic: true, DynamicQuery: `device.labels.env equals prod`,
	}))
	require.NoError(t, err)

	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetDeviceGroup", "ListDeviceGroups", "RenameDeviceGroup"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "GetDeviceGroup", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup,
		}, {
			Permission: "ListDeviceGroups", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup,
		}, {
			Permission: "RenameDeviceGroup", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup,
		}},
	})
	_, err = f.handlers.GetDeviceGroup(scoped, connect.NewRequest(&pmv1.GetDeviceGroupRequest{Id: created.Msg.Group.Id}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	_, err = f.handlers.RenameDeviceGroup(scoped, connect.NewRequest(&pmv1.RenameDeviceGroupRequest{
		Id: created.Msg.Group.Id, Name: "denied",
	}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	list, err := f.handlers.ListDeviceGroups(scoped, connect.NewRequest(&pmv1.ListDeviceGroupsRequest{}))
	require.NoError(t, err)
	require.Len(t, list.Msg.Groups, 1)
	assert.Equal(t, f.scopeGroup, list.Msg.Groups[0].Id)

	membershipScoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser, Permissions: []string{"AddDeviceToGroup"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "AddDeviceToGroup", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: f.scopeGroup,
		}},
	})
	_, err = f.handlers.AddDeviceToGroup(membershipScoped, connect.NewRequest(&pmv1.AddDeviceToGroupRequest{
		GroupId: f.scopeGroup, DeviceId: f.groupID,
	}))
	require.NoError(t, err)
	_, err = f.handlers.AddDeviceToGroup(membershipScoped, connect.NewRequest(&pmv1.AddDeviceToGroupRequest{
		GroupId: f.scopeGroup, DeviceId: f.outsideID,
	}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "membership writes must not widen the caller's device scope")
}

func TestDeviceGroupHandlers_MountsDirectSurfaceWithoutEvaluatorRPCs(t *testing.T) {
	f := newDeviceGroupHandlerFixture(t)
	mounted := f.handlers.Mount(http.NewServeMux())
	assert.Equal(t, []string{
		powermanagev1connect.ControlServiceCreateDeviceGroupProcedure,
		powermanagev1connect.ControlServiceGetDeviceGroupProcedure,
		powermanagev1connect.ControlServiceListDeviceGroupsProcedure,
		powermanagev1connect.ControlServiceListDeviceGroupsForDeviceProcedure,
		powermanagev1connect.ControlServiceRenameDeviceGroupProcedure,
		powermanagev1connect.ControlServiceUpdateDeviceGroupDescriptionProcedure,
		powermanagev1connect.ControlServiceUpdateDeviceGroupQueryProcedure,
		powermanagev1connect.ControlServiceDeleteDeviceGroupProcedure,
		powermanagev1connect.ControlServiceAddDeviceToGroupProcedure,
		powermanagev1connect.ControlServiceRemoveDeviceFromGroupProcedure,
		powermanagev1connect.ControlServiceSetDeviceGroupSyncIntervalProcedure,
		powermanagev1connect.ControlServiceSetDeviceGroupInventoryIntervalProcedure,
		powermanagev1connect.ControlServiceSetDeviceGroupMaintenanceWindowProcedure,
	}, mounted)
}
