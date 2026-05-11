package api_test

// Coverage for the reshaped ListAvailableVariables handler
// (manchtools/power-manage-server#196 scope correction). The proto
// signature changed from a single device_id to (device_group_ids[],
// user_group_ids[]) so the picker can be driven directly by the group
// IDs operators have selected as targets — variables are exclusively
// a group concept so a device-id intermediary was always wrong.

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// storedVarShape mirrors the on-disk JSONB layout the SET handler
// writes. Duplicated here (rather than imported from the template
// package's resolver_test) so the api package's tests are
// self-contained.
type storedVarShape struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

func setDeviceGroupVarsRaw(t *testing.T, st *store.Store, groupID string, vars []storedVarShape) {
	t.Helper()
	raw, err := json.Marshal(vars)
	require.NoError(t, err)
	require.NoError(t, st.Queries().SetDeviceGroupVariables(context.Background(), db.SetDeviceGroupVariablesParams{
		ID:        groupID,
		Variables: raw,
	}))
}

func setUserGroupVarsRaw(t *testing.T, st *store.Store, groupID string, vars []storedVarShape) {
	t.Helper()
	raw, err := json.Marshal(vars)
	require.NoError(t, err)
	require.NoError(t, st.Queries().SetUserGroupVariables(context.Background(), db.SetUserGroupVariablesParams{
		ID:        groupID,
		Variables: raw,
	}))
}

func TestListAvailableVariables_EmptyRequestRejected(t *testing.T) {
	// Both group-id slices empty → InvalidArgument. Without this guard
	// the handler would happily return an empty result set, masking a
	// caller bug (forgetting to wire the group-id state into the RPC
	// call) as a successful "no variables defined."
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewGroupVariableHandler(st, enc, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.ListAvailableVariables(ctx, connect.NewRequest(&pm.ListAvailableVariablesRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestListAvailableVariables_DeviceGroupOnly(t *testing.T) {
	// Single device-group request returns that group's variables with
	// defined_in_group_ids populated. Locks the basic happy path.
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewGroupVariableHandler(st, enc, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	dgID := testutil.CreateTestDeviceGroup(t, st, adminID, "dg")
	setDeviceGroupVarsRaw(t, st, dgID, []storedVarShape{
		{Name: "env", Type: "string", Value: "prod", Description: "Environment"},
		{Name: "port", Type: "int", Value: "8080"},
	})
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ListAvailableVariables(ctx, connect.NewRequest(&pm.ListAvailableVariablesRequest{
		DeviceGroupIds: []string{dgID},
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Variables, 2)

	// Sorted alphabetically by name.
	assert.Equal(t, "env", resp.Msg.Variables[0].Name)
	assert.Equal(t, pm.VariableType_VARIABLE_TYPE_STRING, resp.Msg.Variables[0].Type)
	assert.Equal(t, "Environment", resp.Msg.Variables[0].Description)
	assert.Equal(t, []string{dgID}, resp.Msg.Variables[0].DefinedInGroupIds)

	assert.Equal(t, "port", resp.Msg.Variables[1].Name)
	assert.Equal(t, pm.VariableType_VARIABLE_TYPE_INT, resp.Msg.Variables[1].Type)
}

func TestListAvailableVariables_UserGroupOnly(t *testing.T) {
	// Single user-group request — same shape as device-group, exercises
	// the user-group branch.
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewGroupVariableHandler(st, enc, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ugID := testutil.CreateTestUserGroup(t, st, adminID, "ug")
	setUserGroupVarsRaw(t, st, ugID, []storedVarShape{
		{Name: "team", Type: "string", Value: "ops"},
	})
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ListAvailableVariables(ctx, connect.NewRequest(&pm.ListAvailableVariablesRequest{
		UserGroupIds: []string{ugID},
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Variables, 1)
	assert.Equal(t, "team", resp.Msg.Variables[0].Name)
	assert.Equal(t, []string{ugID}, resp.Msg.Variables[0].DefinedInGroupIds)
}

func TestListAvailableVariables_DedupesAcrossGroups(t *testing.T) {
	// Same name on two different groups: collapses to one entry whose
	// defined_in_group_ids carries both group IDs (so the picker can
	// surface "this name comes from these groups"). Variables stay
	// distinct otherwise.
	st := testutil.SetupPostgres(t)
	enc := testutil.NewEncryptor(t)
	h := api.NewGroupVariableHandler(st, enc, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	dg1 := testutil.CreateTestDeviceGroup(t, st, adminID, "dg1")
	dg2 := testutil.CreateTestDeviceGroup(t, st, adminID, "dg2")
	ug1 := testutil.CreateTestUserGroup(t, st, adminID, "ug1")
	setDeviceGroupVarsRaw(t, st, dg1, []storedVarShape{{Name: "shared", Type: "string", Value: "a"}})
	setDeviceGroupVarsRaw(t, st, dg2, []storedVarShape{{Name: "shared", Type: "string", Value: "b"}, {Name: "extra", Type: "string", Value: "z"}})
	setUserGroupVarsRaw(t, st, ug1, []storedVarShape{{Name: "shared", Type: "string", Value: "c"}})
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ListAvailableVariables(ctx, connect.NewRequest(&pm.ListAvailableVariablesRequest{
		DeviceGroupIds: []string{dg1, dg2},
		UserGroupIds:   []string{ug1},
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Variables, 2)

	// Sorted alphabetically: "extra", "shared"
	assert.Equal(t, "extra", resp.Msg.Variables[0].Name)
	assert.Len(t, resp.Msg.Variables[0].DefinedInGroupIds, 1)

	assert.Equal(t, "shared", resp.Msg.Variables[1].Name)
	assert.Len(t, resp.Msg.Variables[1].DefinedInGroupIds, 3,
		"a name defined on multiple groups MUST list ALL defining groups so the picker can surface conflicts")
	assert.Contains(t, resp.Msg.Variables[1].DefinedInGroupIds, dg1)
	assert.Contains(t, resp.Msg.Variables[1].DefinedInGroupIds, dg2)
	assert.Contains(t, resp.Msg.Variables[1].DefinedInGroupIds, ug1)
}
