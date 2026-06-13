package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func deviceScoped(actorID string, perm, groupID string) context.Context {
	return testutil.AuthContextScoped(actorID, "scoped@test.com", []string{perm},
		[]auth.ScopedGrant{{Permission: perm, ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupID}})
}

func userScoped(actorID string, perm, groupID string) context.Context {
	return testutil.AuthContextScoped(actorID, "scoped@test.com", []string{perm},
		[]auth.ScopedGrant{{Permission: perm, ScopeKind: auth.ScopeKindUserGroup, ScopeID: groupID}})
}

func globalCtx(actorID, perm string) context.Context {
	return testutil.AuthContextScoped(actorID, "g@test.com", []string{perm},
		[]auth.ScopedGrant{{Permission: perm}})
}

// Finding #3 (list filters): a device-group-scoped caller listing devices sees
// ONLY devices that are members of a group in their scope; a global caller sees
// all. Membership-based.
func TestListDevices_DeviceScopeFiltered(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceHandler(st, nil, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	dgX := testutil.CreateTestDeviceGroup(t, st, actor, "Plant X")
	devIn := testutil.CreateTestDevice(t, st, "in-scope")
	devOut := testutil.CreateTestDevice(t, st, "out-of-scope")
	testutil.AddDeviceToTestGroup(t, st, actor, dgX, devIn)

	list := func(ctx context.Context) []string {
		resp, err := h.ListDevices(ctx, connect.NewRequest(&pm.ListDevicesRequest{PageSize: 100}))
		require.NoError(t, err)
		ids := make([]string, len(resp.Msg.Devices))
		for i, d := range resp.Msg.Devices {
			ids[i] = d.Id
		}
		// Count parity: the page holds every matching row (pageSize 100), so a
		// correct, identically-scoped COUNT must equal the returned length.
		assert.Equal(t, int32(len(ids)), resp.Msg.TotalCount, "TotalCount must apply the same scope filter as the list")
		return ids
	}

	t.Run("scoped caller sees only in-scope devices", func(t *testing.T) {
		ids := list(deviceScoped(actor, "ListDevices", dgX))
		assert.Contains(t, ids, devIn)
		assert.NotContains(t, ids, devOut)
	})
	t.Run("global caller sees all devices", func(t *testing.T) {
		ids := list(globalCtx(actor, "ListDevices"))
		assert.Contains(t, ids, devIn)
		assert.Contains(t, ids, devOut)
	})
}

// ListUsers: membership-based on user groups.
func TestListUsers_UserScopeFiltered(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserHandler(st, slog.Default(), nil)
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	ugX := testutil.CreateTestUserGroup(t, st, actor, "Team X")
	userIn := testutil.CreateTestUser(t, st, testutil.NewID()+"@in.com", "pass", "user")
	userOut := testutil.CreateTestUser(t, st, testutil.NewID()+"@out.com", "pass", "user")
	testutil.AddUserToTestGroup(t, st, actor, ugX, userIn)

	list := func(ctx context.Context) []string {
		resp, err := h.ListUsers(ctx, connect.NewRequest(&pm.ListUsersRequest{PageSize: 100}))
		require.NoError(t, err)
		ids := make([]string, len(resp.Msg.Users))
		for i, u := range resp.Msg.Users {
			ids[i] = u.Id
		}
		assert.Equal(t, int32(len(ids)), resp.Msg.TotalCount, "TotalCount must apply the same scope filter as the list")
		return ids
	}

	t.Run("scoped caller sees only in-scope users", func(t *testing.T) {
		ids := list(userScoped(actor, "ListUsers", ugX))
		assert.Contains(t, ids, userIn)
		assert.NotContains(t, ids, userOut)
	})
	t.Run("global caller sees all users", func(t *testing.T) {
		ids := list(globalCtx(actor, "ListUsers"))
		assert.Contains(t, ids, userIn)
		assert.Contains(t, ids, userOut)
	})
}

// ListExecutions: membership-based on the execution's device.
func TestListExecutions_DeviceScopeFiltered(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	dgX := testutil.CreateTestDeviceGroup(t, st, actor, "Plant X")
	devIn := testutil.CreateTestDevice(t, st, "in-scope")
	devOut := testutil.CreateTestDevice(t, st, "out-of-scope")
	testutil.AddDeviceToTestGroup(t, st, actor, dgX, devIn)

	execIn := seedExecution(t, st, actor, devIn)
	execOut := seedExecution(t, st, actor, devOut)

	list := func(ctx context.Context) []string {
		resp, err := h.ListExecutions(ctx, connect.NewRequest(&pm.ListExecutionsRequest{PageSize: 100}))
		require.NoError(t, err)
		ids := make([]string, len(resp.Msg.Executions))
		for i, e := range resp.Msg.Executions {
			ids[i] = e.Id
		}
		assert.Equal(t, int32(len(ids)), resp.Msg.TotalCount, "TotalCount must apply the same scope filter as the list")
		return ids
	}

	t.Run("scoped caller sees only in-scope executions", func(t *testing.T) {
		ids := list(deviceScoped(actor, "ListExecutions", dgX))
		assert.Contains(t, ids, execIn)
		assert.NotContains(t, ids, execOut)
	})
	t.Run("global caller sees all executions", func(t *testing.T) {
		ids := list(globalCtx(actor, "ListExecutions"))
		assert.Contains(t, ids, execIn)
		assert.Contains(t, ids, execOut)
	})
}

// ListDeviceGroups: DIRECT id-match — the scoped caller sees only their scope
// groups.
func TestListDeviceGroups_DirectScopeFiltered(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	dgX := testutil.CreateTestDeviceGroup(t, st, actor, "Plant X")
	dgY := testutil.CreateTestDeviceGroup(t, st, actor, "Plant Y")

	list := func(ctx context.Context) []string {
		resp, err := h.ListDeviceGroups(ctx, connect.NewRequest(&pm.ListDeviceGroupsRequest{PageSize: 100}))
		require.NoError(t, err)
		ids := make([]string, len(resp.Msg.Groups))
		for i, g := range resp.Msg.Groups {
			ids[i] = g.Id
		}
		assert.Equal(t, int32(len(ids)), resp.Msg.TotalCount, "TotalCount must apply the same scope filter as the list")
		return ids
	}

	t.Run("scoped caller sees only the in-scope group", func(t *testing.T) {
		ids := list(deviceScoped(actor, "ListDeviceGroups", dgX))
		assert.Equal(t, []string{dgX}, ids)
	})
	t.Run("global caller sees all groups", func(t *testing.T) {
		ids := list(globalCtx(actor, "ListDeviceGroups"))
		assert.Contains(t, ids, dgX)
		assert.Contains(t, ids, dgY)
	})
}

// ListUserGroups: DIRECT id-match.
func TestListUserGroups_DirectScopeFiltered(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	ugX := testutil.CreateTestUserGroup(t, st, actor, "Team X")
	ugY := testutil.CreateTestUserGroup(t, st, actor, "Team Y")

	list := func(ctx context.Context) []string {
		resp, err := h.ListUserGroups(ctx, connect.NewRequest(&pm.ListUserGroupsRequest{PageSize: 100}))
		require.NoError(t, err)
		ids := make([]string, len(resp.Msg.Groups))
		for i, g := range resp.Msg.Groups {
			ids[i] = g.Id
		}
		assert.Equal(t, int32(len(ids)), resp.Msg.TotalCount, "TotalCount must apply the same scope filter as the list")
		return ids
	}

	t.Run("scoped caller sees only the in-scope group", func(t *testing.T) {
		ids := list(userScoped(actor, "ListUserGroups", ugX))
		assert.Equal(t, []string{ugX}, ids)
	})
	t.Run("global caller sees all groups", func(t *testing.T) {
		ids := list(globalCtx(actor, "ListUserGroups"))
		assert.Contains(t, ids, ugX)
		assert.Contains(t, ids, ugY)
	})
}

// ListDeviceGroupsForDevice: returned groups restricted to the caller's scope
// (DIRECT id-match).
func TestListDeviceGroupsForDevice_DirectScopeFiltered(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDeviceGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	dgX := testutil.CreateTestDeviceGroup(t, st, actor, "Plant X")
	dgY := testutil.CreateTestDeviceGroup(t, st, actor, "Plant Y")
	dev := testutil.CreateTestDevice(t, st, "host")
	testutil.AddDeviceToTestGroup(t, st, actor, dgX, dev)
	testutil.AddDeviceToTestGroup(t, st, actor, dgY, dev)

	list := func(ctx context.Context) []string {
		resp, err := h.ListDeviceGroupsForDevice(ctx, connect.NewRequest(&pm.ListDeviceGroupsForDeviceRequest{DeviceId: dev}))
		require.NoError(t, err)
		ids := make([]string, len(resp.Msg.Groups))
		for i, g := range resp.Msg.Groups {
			ids[i] = g.Id
		}
		return ids
	}

	t.Run("scoped caller sees only the in-scope group for the device", func(t *testing.T) {
		ids := list(deviceScoped(actor, "ListDeviceGroupsForDevice", dgX))
		assert.Equal(t, []string{dgX}, ids)
	})
	t.Run("global caller sees all groups for the device", func(t *testing.T) {
		ids := list(globalCtx(actor, "ListDeviceGroupsForDevice"))
		assert.ElementsMatch(t, []string{dgX, dgY}, ids)
	})
}

// ListUserGroupsForUser: DIRECT id-match.
func TestListUserGroupsForUser_DirectScopeFiltered(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewUserGroupHandler(st, slog.Default())
	actor := testutil.CreateTestUser(t, st, testutil.NewID()+"@a.com", "pass", "admin")

	ugX := testutil.CreateTestUserGroup(t, st, actor, "Team X")
	ugY := testutil.CreateTestUserGroup(t, st, actor, "Team Y")
	member := testutil.CreateTestUser(t, st, testutil.NewID()+"@m.com", "pass", "user")
	testutil.AddUserToTestGroup(t, st, actor, ugX, member)
	testutil.AddUserToTestGroup(t, st, actor, ugY, member)

	list := func(ctx context.Context) []string {
		resp, err := h.ListUserGroupsForUser(ctx, connect.NewRequest(&pm.ListUserGroupsForUserRequest{UserId: member}))
		require.NoError(t, err)
		ids := make([]string, len(resp.Msg.Groups))
		for i, g := range resp.Msg.Groups {
			ids[i] = g.Id
		}
		return ids
	}

	t.Run("scoped caller sees only the in-scope group for the user", func(t *testing.T) {
		ids := list(userScoped(actor, "ListUserGroupsForUser", ugX))
		assert.Equal(t, []string{ugX}, ids)
	})
	t.Run("global caller sees all groups for the user", func(t *testing.T) {
		ids := list(globalCtx(actor, "ListUserGroupsForUser"))
		assert.ElementsMatch(t, []string{ugX, ugY}, ids)
	})
}

// seedExecution materialises an executions_projection row for deviceID by
// appending an ExecutionCreated event, returning the execution id.
func seedExecution(t *testing.T, st *store.Store, actorID, deviceID string) string {
	t.Helper()
	id := ulid.Make().String()
	at := int32(pm.ActionType_ACTION_TYPE_SHELL)
	ds := int32(pm.DesiredState_DESIRED_STATE_PRESENT)
	to := int32(60)
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "execution",
		StreamID:   id,
		EventType:  string(eventtypes.ExecutionCreated),
		Data: payloads.ExecutionCreated{
			DeviceID:       deviceID,
			ActionType:     &at,
			DesiredState:   &ds,
			Params:         []byte(`{}`),
			TimeoutSeconds: &to,
		},
		ActorType: "user",
		ActorID:   actorID,
	}))
	return id
}
