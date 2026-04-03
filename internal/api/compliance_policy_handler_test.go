package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// createComplianceShellAction creates a shell action with is_compliance=true
// and returns its ID. This is needed because AddCompliancePolicyRule validates
// the action type and params.
func createComplianceShellAction(t *testing.T, st *store.Store, actorID, name string) string {
	t.Helper()
	ctx := context.Background()
	id := testutil.NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   id,
		EventType:  "ActionCreated",
		Data: map[string]any{
			"name":        name,
			"action_type": 200, // ACTION_TYPE_SHELL
			"params": map[string]any{
				"script":       "#!/bin/bash\nexit 0",
				"isCompliance": true,
			},
			"timeout_seconds": 300,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	require.NoError(t, err)
	return id
}

func TestCreateCompliancePolicy(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{
		Name:        "Security Baseline",
		Description: "Ensures all devices meet security baseline",
	}))
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.Policy.Id)
	assert.Equal(t, "Security Baseline", resp.Msg.Policy.Name)
	assert.Equal(t, "Ensures all devices meet security baseline", resp.Msg.Policy.Description)
	assert.Equal(t, int32(0), resp.Msg.Policy.RuleCount)
}

func TestGetCompliancePolicy(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{
		Name: "Fetch Test Policy",
	}))
	require.NoError(t, err)

	getResp, err := h.GetCompliancePolicy(ctx, connect.NewRequest(&pm.GetCompliancePolicyRequest{
		Id: createResp.Msg.Policy.Id,
	}))
	require.NoError(t, err)
	assert.Equal(t, createResp.Msg.Policy.Id, getResp.Msg.Policy.Id)
	assert.Equal(t, "Fetch Test Policy", getResp.Msg.Policy.Name)
}

func TestGetCompliancePolicy_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetCompliancePolicy(ctx, connect.NewRequest(&pm.GetCompliancePolicyRequest{
		Id: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAddCompliancePolicyRule(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Create policy
	policyResp, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{
		Name: "Rule Test Policy",
	}))
	require.NoError(t, err)
	policyID := policyResp.Msg.Policy.Id

	// Create compliance action
	actionID := createComplianceShellAction(t, st, adminID, "Check Firewall")

	// Add rule
	ruleResp, err := h.AddCompliancePolicyRule(ctx, connect.NewRequest(&pm.AddCompliancePolicyRuleRequest{
		PolicyId:         policyID,
		ActionId:         actionID,
		GracePeriodHours: 24,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), ruleResp.Msg.Policy.RuleCount)
	require.Len(t, ruleResp.Msg.Policy.Rules, 1)
	assert.Equal(t, actionID, ruleResp.Msg.Policy.Rules[0].ActionId)
	assert.Equal(t, "Check Firewall", ruleResp.Msg.Policy.Rules[0].ActionName)
	assert.Equal(t, int32(24), ruleResp.Msg.Policy.Rules[0].GracePeriodHours)
}

func TestAddCompliancePolicyRule_NonComplianceActionRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	policyResp, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{
		Name: "Reject Test",
	}))
	require.NoError(t, err)

	// Create a regular (non-compliance) shell action
	actionID := testutil.CreateTestAction(t, st, adminID, "Regular Script", int(pm.ActionType_ACTION_TYPE_SHELL))

	_, err = h.AddCompliancePolicyRule(ctx, connect.NewRequest(&pm.AddCompliancePolicyRuleRequest{
		PolicyId: policyResp.Msg.Policy.Id,
		ActionId: actionID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestDeleteCompliancePolicy_SoftDeletes(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Create
	createResp, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{
		Name: "Deletable Policy",
	}))
	require.NoError(t, err)
	policyID := createResp.Msg.Policy.Id

	// Delete
	_, err = h.DeleteCompliancePolicy(ctx, connect.NewRequest(&pm.DeleteCompliancePolicyRequest{
		Id: policyID,
	}))
	require.NoError(t, err)

	// Verify it's gone from Get
	_, err = h.GetCompliancePolicy(ctx, connect.NewRequest(&pm.GetCompliancePolicyRequest{
		Id: policyID,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	// Verify it's gone from List
	listResp, err := h.ListCompliancePolicies(ctx, connect.NewRequest(&pm.ListCompliancePoliciesRequest{}))
	require.NoError(t, err)
	for _, p := range listResp.Msg.Policies {
		assert.NotEqual(t, policyID, p.Id, "deleted policy must not appear in list")
	}
}

func TestDeleteCompliancePolicy_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteCompliancePolicy(ctx, connect.NewRequest(&pm.DeleteCompliancePolicyRequest{
		Id: testutil.NewID(),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestRenameCompliancePolicy(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	createResp, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{
		Name: "Original Name",
	}))
	require.NoError(t, err)

	renameResp, err := h.RenameCompliancePolicy(ctx, connect.NewRequest(&pm.RenameCompliancePolicyRequest{
		Id:   createResp.Msg.Policy.Id,
		Name: "Renamed Policy",
	}))
	require.NoError(t, err)
	assert.Equal(t, "Renamed Policy", renameResp.Msg.Policy.Name)

	// Verify persistence
	getResp, err := h.GetCompliancePolicy(ctx, connect.NewRequest(&pm.GetCompliancePolicyRequest{
		Id: createResp.Msg.Policy.Id,
	}))
	require.NoError(t, err)
	assert.Equal(t, "Renamed Policy", getResp.Msg.Policy.Name)
}

func TestRemoveCompliancePolicyRule(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Create policy with a rule
	policyResp, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{
		Name: "Remove Rule Test",
	}))
	require.NoError(t, err)
	policyID := policyResp.Msg.Policy.Id

	actionID := createComplianceShellAction(t, st, adminID, "Check Rule")
	_, err = h.AddCompliancePolicyRule(ctx, connect.NewRequest(&pm.AddCompliancePolicyRuleRequest{
		PolicyId: policyID,
		ActionId: actionID,
	}))
	require.NoError(t, err)

	// Remove the rule
	removeResp, err := h.RemoveCompliancePolicyRule(ctx, connect.NewRequest(&pm.RemoveCompliancePolicyRuleRequest{
		PolicyId: policyID,
		ActionId: actionID,
	}))
	require.NoError(t, err)
	assert.Equal(t, int32(0), removeResp.Msg.Policy.RuleCount)
	assert.Empty(t, removeResp.Msg.Policy.Rules)
}

func TestListCompliancePolicies(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewCompliancePolicyHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Create multiple policies
	for i := 0; i < 3; i++ {
		_, err := h.CreateCompliancePolicy(ctx, connect.NewRequest(&pm.CreateCompliancePolicyRequest{
			Name: "List Policy " + testutil.NewID()[:8],
		}))
		require.NoError(t, err)
	}

	resp, err := h.ListCompliancePolicies(ctx, connect.NewRequest(&pm.ListCompliancePoliciesRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Policies), 3)
	assert.GreaterOrEqual(t, resp.Msg.TotalCount, int32(3))
}
