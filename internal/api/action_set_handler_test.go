package api_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestCreateActionSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateActionSet(ctx, connect.NewRequest(&pm.CreateActionSetRequest{
		Name: "Web Server Setup",
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Set.Id)
	assert.Equal(t, "Web Server Setup", resp.Msg.Set.Name)
}

func TestGetActionSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Test Set")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.GetActionSet(ctx, connect.NewRequest(&pm.GetActionSetRequest{Id: setID}))
	require.NoError(t, err)
	assert.Equal(t, setID, resp.Msg.Set.Id)
	assert.Equal(t, "Test Set", resp.Msg.Set.Name)
}

func TestListActionSets(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for i := 0; i < 3; i++ {
		testutil.CreateTestActionSet(t, st, adminID, testutil.NewID())
	}

	resp, err := h.ListActionSets(ctx, connect.NewRequest(&pm.ListActionSetsRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Sets), 3)
}

func TestRenameActionSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Old Name")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.RenameActionSet(ctx, connect.NewRequest(&pm.RenameActionSetRequest{
		Id:   setID,
		Name: "New Name",
	}))
	require.NoError(t, err)
	assert.Equal(t, "New Name", resp.Msg.Set.Name)
}

func TestDeleteActionSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setID := testutil.CreateTestActionSet(t, st, adminID, "To Delete")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteActionSet(ctx, connect.NewRequest(&pm.DeleteActionSetRequest{Id: setID}))
	require.NoError(t, err)

	_, err = h.GetActionSet(ctx, connect.NewRequest(&pm.GetActionSetRequest{Id: setID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAddActionToSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Test Set")
	actionID := testutil.CreateTestAction(t, st, adminID, "Test Action", 1)
	ctx := testutil.AdminContext(adminID)

	_, err := h.AddActionToSet(ctx, connect.NewRequest(&pm.AddActionToSetRequest{
		SetId:     setID,
		ActionId:  actionID,
		SortOrder: 0,
	}))
	require.NoError(t, err)

	// Verify member was added
	resp, err := h.GetActionSet(ctx, connect.NewRequest(&pm.GetActionSetRequest{Id: setID}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.Msg.Set.MemberCount)
}

func TestRemoveActionFromSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Test Set")
	actionID := testutil.CreateTestAction(t, st, adminID, "Test Action", 1)
	ctx := testutil.AdminContext(adminID)

	_, err := h.AddActionToSet(ctx, connect.NewRequest(&pm.AddActionToSetRequest{
		SetId:     setID,
		ActionId:  actionID,
		SortOrder: 0,
	}))
	require.NoError(t, err)

	_, err = h.RemoveActionFromSet(ctx, connect.NewRequest(&pm.RemoveActionFromSetRequest{
		SetId:    setID,
		ActionId: actionID,
	}))
	require.NoError(t, err)
}

func TestReorderActionInSet(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Test Set")
	actionID := testutil.CreateTestAction(t, st, adminID, "Test Action", 1)
	ctx := testutil.AdminContext(adminID)

	_, err := h.AddActionToSet(ctx, connect.NewRequest(&pm.AddActionToSetRequest{
		SetId:     setID,
		ActionId:  actionID,
		SortOrder: 0,
	}))
	require.NoError(t, err)

	_, err = h.ReorderActionInSet(ctx, connect.NewRequest(&pm.ReorderActionInSetRequest{
		SetId:     setID,
		ActionId:  actionID,
		NewOrder: 5,
	}))
	require.NoError(t, err)
}
