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

func TestCreateDefinition(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDefinitionHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateDefinition(ctx, connect.NewRequest(&pm.CreateDefinitionRequest{
		Name: "Full Deploy",
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Definition.Id)
	assert.Equal(t, "Full Deploy", resp.Msg.Definition.Name)
}

func TestGetDefinition(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDefinitionHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	defID := testutil.CreateTestDefinition(t, st, adminID, "Test Def")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.GetDefinition(ctx, connect.NewRequest(&pm.GetDefinitionRequest{Id: defID}))
	require.NoError(t, err)
	assert.Equal(t, defID, resp.Msg.Definition.Id)
	assert.Equal(t, "Test Def", resp.Msg.Definition.Name)
}

func TestListDefinitions(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDefinitionHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for i := 0; i < 3; i++ {
		testutil.CreateTestDefinition(t, st, adminID, testutil.NewID())
	}

	resp, err := h.ListDefinitions(ctx, connect.NewRequest(&pm.ListDefinitionsRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Definitions), 3)
}

func TestRenameDefinition(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDefinitionHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	defID := testutil.CreateTestDefinition(t, st, adminID, "Old")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.RenameDefinition(ctx, connect.NewRequest(&pm.RenameDefinitionRequest{
		Id:   defID,
		Name: "New",
	}))
	require.NoError(t, err)
	assert.Equal(t, "New", resp.Msg.Definition.Name)
}

func TestDeleteDefinition(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDefinitionHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	defID := testutil.CreateTestDefinition(t, st, adminID, "To Delete")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteDefinition(ctx, connect.NewRequest(&pm.DeleteDefinitionRequest{Id: defID}))
	require.NoError(t, err)

	_, err = h.GetDefinition(ctx, connect.NewRequest(&pm.GetDefinitionRequest{Id: defID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAddActionSetToDefinition(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewDefinitionHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	defID := testutil.CreateTestDefinition(t, st, adminID, "Test Def")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Test Set")
	ctx := testutil.AdminContext(adminID)

	_, err := h.AddActionSetToDefinition(ctx, connect.NewRequest(&pm.AddActionSetToDefinitionRequest{
		DefinitionId: defID,
		ActionSetId:  setID,
		SortOrder:    0,
	}))
	require.NoError(t, err)

	resp, err := h.GetDefinition(ctx, connect.NewRequest(&pm.GetDefinitionRequest{Id: defID}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.Msg.Definition.MemberCount)
}
