package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestCreateDeviceGroup_Static(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name: "Web Servers",
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Group.Id)
	assert.Equal(t, "Web Servers", resp.Msg.Group.Name)
	assert.False(t, resp.Msg.Group.IsDynamic)
}

func TestGetDeviceGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Test Group")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: groupID}))
	require.NoError(t, err)
	assert.Equal(t, groupID, resp.Msg.Group.Id)
	assert.Equal(t, "Test Group", resp.Msg.Group.Name)
}

func TestGetDeviceGroup_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: testutil.NewID()}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestListDeviceGroups(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for i := 0; i < 3; i++ {
		testutil.CreateTestDeviceGroup(t, st, adminID, testutil.NewID())
	}

	resp, err := h.ListDeviceGroups(ctx, connect.NewRequest(&pm.ListDeviceGroupsRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Groups), 3)
}

func TestRenameDeviceGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Old")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.RenameDeviceGroup(ctx, connect.NewRequest(&pm.RenameDeviceGroupRequest{
		Id:   groupID,
		Name: "New",
	}))
	require.NoError(t, err)
	assert.Equal(t, "New", resp.Msg.Group.Name)
}

func TestDeleteDeviceGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "To Delete")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteDeviceGroup(ctx, connect.NewRequest(&pm.DeleteDeviceGroupRequest{Id: groupID}))
	require.NoError(t, err)

	_, err = h.GetDeviceGroup(ctx, connect.NewRequest(&pm.GetDeviceGroupRequest{Id: groupID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAddDeviceToGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Members Group")
	deviceID := testutil.CreateTestDevice(t, st, "member-host")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.AddDeviceToGroup(ctx, connect.NewRequest(&pm.AddDeviceToGroupRequest{
		GroupId:  groupID,
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.Msg.Group.MemberCount)
}

func TestRemoveDeviceFromGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Remove Group")
	deviceID := testutil.CreateTestDevice(t, st, "remove-host")
	ctx := testutil.AdminContext(adminID)

	// Add first
	_, err := h.AddDeviceToGroup(ctx, connect.NewRequest(&pm.AddDeviceToGroupRequest{
		GroupId:  groupID,
		DeviceId: deviceID,
	}))
	require.NoError(t, err)

	// Remove
	resp, err := h.RemoveDeviceFromGroup(ctx, connect.NewRequest(&pm.RemoveDeviceFromGroupRequest{
		GroupId:  groupID,
		DeviceId: deviceID,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(0), resp.Msg.Group.MemberCount)
}

func TestSetDeviceGroupSyncInterval(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Sync Group")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.SetDeviceGroupSyncInterval(ctx, connect.NewRequest(&pm.SetDeviceGroupSyncIntervalRequest{
		Id:                  groupID,
		SyncIntervalMinutes: 60,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(60), resp.Msg.Group.SyncIntervalMinutes)
}

func TestSetDeviceGroupMaintenanceWindow(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Window Group")
	ctx := testutil.AdminContext(adminID)

	// Set a window with two entries; the response carries the
	// projected schedule as proto so we can assert round-trip
	// fidelity end-to-end (handler → event → projector → query).
	resp, err := h.SetDeviceGroupMaintenanceWindow(ctx, connect.NewRequest(&pm.SetDeviceGroupMaintenanceWindowRequest{
		Id: groupID,
		MaintenanceWindow: &pm.MaintenanceWindow{Schedule: []*pm.MaintenanceWindowEntry{
			{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Allow: "22:00-06:00"},
			{Days: []string{"sat", "sun"}, Allow: "00:00-23:59"},
		}},
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.Group.MaintenanceWindow)
	require.Len(t, resp.Msg.Group.MaintenanceWindow.Schedule, 2)
	assert.Equal(t, []string{"mon", "tue", "wed", "thu", "fri"}, resp.Msg.Group.MaintenanceWindow.Schedule[0].Days)
	assert.Equal(t, "22:00-06:00", resp.Msg.Group.MaintenanceWindow.Schedule[0].Allow)
	assert.Equal(t, []string{"sat", "sun"}, resp.Msg.Group.MaintenanceWindow.Schedule[1].Days)
	assert.Equal(t, "00:00-23:59", resp.Msg.Group.MaintenanceWindow.Schedule[1].Allow)

	// Clear the window — passing nil drops the schedule and the
	// projection's COALESCE should restore the empty default.
	clearResp, err := h.SetDeviceGroupMaintenanceWindow(ctx, connect.NewRequest(&pm.SetDeviceGroupMaintenanceWindowRequest{
		Id:                groupID,
		MaintenanceWindow: nil,
	}))
	require.NoError(t, err)
	assert.Nil(t, clearResp.Msg.Group.MaintenanceWindow,
		"cleared window must surface as nil (no constraint)")
}

func TestSetDeviceGroupMaintenanceWindow_InvalidEntryRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	groupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Window Group Bad")
	ctx := testutil.AdminContext(adminID)

	_, err := h.SetDeviceGroupMaintenanceWindow(ctx, connect.NewRequest(&pm.SetDeviceGroupMaintenanceWindowRequest{
		Id: groupID,
		MaintenanceWindow: &pm.MaintenanceWindow{Schedule: []*pm.MaintenanceWindowEntry{
			{Days: []string{"funday"}, Allow: "09:00-17:00"},
		}},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"validator should reject non-canonical weekday tokens at the boundary")
}

func TestValidateDynamicQuery(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ValidateDynamicQuery(ctx, connect.NewRequest(&pm.ValidateDynamicQueryRequest{
		Query: `(device.labels.environment equals "production")`,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Valid)
}

// =============================================================================
// CreateDeviceGroup / UpdateDeviceGroupQuery handler dispatch
// (server #7 T-S2 — static/dynamic permission narrowing)
//
// Tests drive the actual handler with hand-built UserContexts that
// hold ONLY the specific split permission under test, NOT a full
// admin grant. That's the load-bearing assertion: the handler MUST
// narrow on request shape, not rely on either permission being held
// (which the interceptor already does via ProcedureAlternatives).
//
// Wrong-data is sourced from intent (the T-S2 design: a static-only
// admin must be unable to author or modify dynamic groups), NOT
// from the artifact under test.
// =============================================================================

func TestCreateDeviceGroup_StaticRequest_StaticPermOnly_Succeeds(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AuthContext(userID, "static-only@test.com", []string{"CreateStaticDeviceGroup"})

	resp, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name: "Static Group",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Group.IsDynamic, "static-only path must produce a static group")
}

func TestCreateDeviceGroup_DynamicRequest_StaticPermOnly_Denied(t *testing.T) {
	// T-S2: static-only admin must NOT be able to create a dynamic
	// group. The interceptor would let them through (alternatives
	// map: holding CreateStaticDeviceGroup is sufficient to ENTER
	// the RPC), but the handler narrows to CreateDynamicDeviceGroup
	// once it sees the dynamic-query request shape.
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AuthContext(userID, "static-only@test.com", []string{"CreateStaticDeviceGroup"})

	_, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name:         "Sneaky Dynamic",
		IsDynamic:    true,
		DynamicQuery: `(device.labels.environment equals "prod")`,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"static-only admin must be denied when request asks for dynamic — T-S2 mitigation")
}

func TestCreateDeviceGroup_DynamicRequest_DynamicPermOnly_Succeeds(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AuthContext(userID, "dynamic-only@test.com", []string{"CreateDynamicDeviceGroup"})

	resp, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name:         "Dynamic Group",
		IsDynamic:    true,
		DynamicQuery: `(device.labels.environment equals "prod")`,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Group.IsDynamic, "dynamic-only path must produce a dynamic group")
}

func TestCreateDeviceGroup_StaticRequest_DynamicPermOnly_Denied(t *testing.T) {
	// Symmetric — dynamic-only admin must NOT be able to create a
	// static group. This is the inverse asymmetry guard so a
	// future PR can't accidentally collapse the dispatch to "any
	// split perm satisfies".
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AuthContext(userID, "dynamic-only@test.com", []string{"CreateDynamicDeviceGroup"})

	_, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name: "Static Attempt",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err),
		"dynamic-only admin must be denied when request asks for static — asymmetry guard")
}

func TestCreateDeviceGroup_DynamicRequest_BothPermsHeld_Succeeds(t *testing.T) {
	// Admin tier — both split perms held — covers either request
	// shape. Sanity check on the typical admin flow.
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AuthContext(userID, "both@test.com", []string{
		"CreateStaticDeviceGroup",
		"CreateDynamicDeviceGroup",
	})

	resp, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name:         "Either",
		IsDynamic:    true,
		DynamicQuery: `(device.labels.x equals "y")`,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Group.IsDynamic)
}

func TestUpdateDeviceGroupQuery_RejectsStaticGroup_FailedPrecondition(t *testing.T) {
	// Defensive: applying UpdateDeviceGroupQuery to a static group
	// would silently promote it to dynamic, bypassing the
	// CreateDynamicDeviceGroup gate. Must fail with
	// FailedPrecondition (not InvalidArgument) so callers can
	// distinguish "I sent a bad request" from "the resource isn't
	// in the expected state".
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	staticGroupID := testutil.CreateTestDeviceGroup(t, st, adminID, "Static Target")
	ctx := testutil.AdminContext(adminID)

	_, err := h.UpdateDeviceGroupQuery(ctx, connect.NewRequest(&pm.UpdateDeviceGroupQueryRequest{
		Id:           staticGroupID,
		IsDynamic:    true,
		DynamicQuery: `(device.labels.env equals "prod")`,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err),
		"applying UpdateDeviceGroupQuery to a static group must FailedPrecondition — no implicit promotion (T-S2 update pathway)")
}

// =============================================================================
// CR-#333 regression: reject `IsDynamic=true` with an empty
// `DynamicQuery`. Without this guard the handler's wantsDynamic
// predicate evaluates false (because DynamicQuery is empty), letting
// a holder of CreateStaticDeviceGroup pass the static permission
// check while the event still persists IsDynamic=true with an empty
// query. Empty queries match every device at evaluation time, so
// the resulting group would scoop up the entire fleet — a T-S2
// bypass in disguise.
// =============================================================================

func TestCreateDeviceGroup_IsDynamicTrueWithEmptyQuery_Rejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name:         "Suspicious",
		IsDynamic:    true,
		DynamicQuery: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"is_dynamic=true with empty dynamic_query must be rejected at the boundary — CR #333 T-S2 bypass guard")
}

func TestCreateDeviceGroup_IsDynamicTrueWithEmptyQuery_StaticOnlyActor_NotElevated(t *testing.T) {
	// Threat lens: even a static-only admin must NOT be able to
	// slip a `IsDynamic=true, DynamicQuery=""` payload past the
	// permission check. The bypass guard rejects BEFORE the
	// permission narrowing runs.
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	userID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "user")
	ctx := testutil.AuthContext(userID, "static-only@test.com", []string{"CreateStaticDeviceGroup"})

	_, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name:         "Bypass Attempt",
		IsDynamic:    true,
		DynamicQuery: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"the bypass guard must fire BEFORE the permission narrowing — invalid request shape is rejected ahead of authz")
}

func TestUpdateDeviceGroupQuery_IsDynamicTrueWithEmptyQuery_Rejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@admin.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	created, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name:         "Existing Dyn",
		IsDynamic:    true,
		DynamicQuery: `(device.labels.x equals "y")`,
	}))
	require.NoError(t, err)

	_, err = h.UpdateDeviceGroupQuery(ctx, connect.NewRequest(&pm.UpdateDeviceGroupQueryRequest{
		Id:           created.Msg.Group.Id,
		IsDynamic:    true,
		DynamicQuery: "",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"clearing the dynamic query on an existing dynamic group via IsDynamic=true must be rejected — same all-devices-match bypass")
}

func TestUpdateDeviceGroupQuery_AcceptsDynamicGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Create a dynamic group first
	created, err := h.CreateDeviceGroup(ctx, connect.NewRequest(&pm.CreateDeviceGroupRequest{
		Name:         "Dyn Target",
		IsDynamic:    true,
		DynamicQuery: `(device.labels.env equals "stage")`,
	}))
	require.NoError(t, err)

	resp, err := h.UpdateDeviceGroupQuery(ctx, connect.NewRequest(&pm.UpdateDeviceGroupQueryRequest{
		Id:           created.Msg.Group.Id,
		IsDynamic:    true,
		DynamicQuery: `(device.labels.env equals "prod")`,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Group.IsDynamic)
	assert.Contains(t, resp.Msg.Group.DynamicQuery, "prod")
}
