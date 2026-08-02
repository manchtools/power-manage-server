package store_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/actionparams"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authoring"
	"github.com/manchtools/power-manage/server/internal/compliance"
)

type complianceHandlerFixture struct {
	*actionHandlerFixture
	handlers *compliance.Handlers
}

func newComplianceHandlerFixture(t *testing.T) *complianceHandlerFixture {
	t.Helper()
	actionFixture := newActionHandlerFixture(t)
	return &complianceHandlerFixture{
		actionHandlerFixture: actionFixture,
		handlers: compliance.NewHandlers(compliance.HandlersConfig{
			Store:  actionFixture.store,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Now:    func() time.Time { return actionFixture.now },
		}),
	}
}

func createPolicyAction(t *testing.T, state *authoring.Service, name string, isCompliance bool) string {
	t.Helper()
	params, err := actionparams.MarshalActionParams(&pmv1.ShellParams{
		Interpreter: "/bin/sh", DetectionScript: "exit 0", IsCompliance: isCompliance,
	})
	require.NoError(t, err)
	op := actionOperation()
	action, err := state.CreateAction(context.Background(), op, authoring.CreateActionParams{
		Name: name, CreatedBy: op.ActorID, Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pmv1.DesiredState_DESIRED_STATE_PRESENT, Params: params,
	})
	require.NoError(t, err)
	return action.ID
}

func TestCompliancePolicyHandlers_ValidateBeforeAuthentication(t *testing.T) {
	f := newComplianceHandlerFixture(t)
	_, err := f.handlers.GetCompliancePolicy(context.Background(), connect.NewRequest(&pmv1.GetCompliancePolicyRequest{Id: "bad"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.handlers.GetCompliancePolicy(context.Background(), connect.NewRequest(&pmv1.GetCompliancePolicyRequest{Id: newID()}))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestCompliancePolicyHandlers_CRUDRulesAndAudit(t *testing.T) {
	f := newComplianceHandlerFixture(t)
	ctx := f.actor(
		"CreateCompliancePolicy", "GetCompliancePolicy", "ListCompliancePolicies",
		"RenameCompliancePolicy", "UpdateCompliancePolicyDescription", "DeleteCompliancePolicy",
		"AddCompliancePolicyRule", "RemoveCompliancePolicyRule", "UpdateCompliancePolicyRule",
	)
	actionState := authoring.New(authoring.Config{Store: f.store, Now: func() time.Time { return f.now }})
	actionID := createPolicyAction(t, actionState, "detect drift", true)

	created, err := f.handlers.CreateCompliancePolicy(ctx, connect.NewRequest(&pmv1.CreateCompliancePolicyRequest{
		Name: "baseline", Description: "required state",
	}))
	require.NoError(t, err)
	policyID := created.Msg.Policy.Id
	assert.Equal(t, int32(0), created.Msg.Policy.RuleCount)
	assert.True(t, created.Msg.Policy.CreatedAt.AsTime().Equal(f.now))

	added, err := f.handlers.AddCompliancePolicyRule(ctx, connect.NewRequest(&pmv1.AddCompliancePolicyRuleRequest{
		PolicyId: policyID, ActionId: actionID, GracePeriodHours: 24,
	}))
	require.NoError(t, err)
	require.Len(t, added.Msg.Policy.Rules, 1)
	assert.Equal(t, int32(1), added.Msg.Policy.RuleCount)
	assert.Equal(t, "detect drift", added.Msg.Policy.Rules[0].ActionName)
	_, err = f.handlers.AddCompliancePolicyRule(ctx, connect.NewRequest(&pmv1.AddCompliancePolicyRuleRequest{
		PolicyId: policyID, ActionId: actionID,
	}))
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))

	updatedRule, err := f.handlers.UpdateCompliancePolicyRule(ctx, connect.NewRequest(&pmv1.UpdateCompliancePolicyRuleRequest{
		PolicyId: policyID, ActionId: actionID, GracePeriodHours: 48,
	}))
	require.NoError(t, err)
	require.Len(t, updatedRule.Msg.Policy.Rules, 1)
	assert.Equal(t, int32(48), updatedRule.Msg.Policy.Rules[0].GracePeriodHours)

	renamed, err := f.handlers.RenameCompliancePolicy(ctx, connect.NewRequest(&pmv1.RenameCompliancePolicyRequest{
		Id: policyID, Name: "renamed",
	}))
	require.NoError(t, err)
	assert.Equal(t, "renamed", renamed.Msg.Policy.Name)
	described, err := f.handlers.UpdateCompliancePolicyDescription(ctx, connect.NewRequest(&pmv1.UpdateCompliancePolicyDescriptionRequest{
		Id: policyID, Description: "direct state",
	}))
	require.NoError(t, err)
	assert.Equal(t, "direct state", described.Msg.Policy.Description)

	got, err := f.handlers.GetCompliancePolicy(ctx, connect.NewRequest(&pmv1.GetCompliancePolicyRequest{Id: policyID}))
	require.NoError(t, err)
	require.Len(t, got.Msg.Policy.Rules, 1)
	assert.Equal(t, int32(1), got.Msg.Policy.RuleCount)
	listed, err := f.handlers.ListCompliancePolicies(ctx, connect.NewRequest(&pmv1.ListCompliancePoliciesRequest{}))
	require.NoError(t, err)
	require.Len(t, listed.Msg.Policies, 1)
	assert.Equal(t, int32(1), listed.Msg.Policies[0].RuleCount)

	removed, err := f.handlers.RemoveCompliancePolicyRule(ctx, connect.NewRequest(&pmv1.RemoveCompliancePolicyRuleRequest{
		PolicyId: policyID, ActionId: actionID,
	}))
	require.NoError(t, err)
	assert.Empty(t, removed.Msg.Policy.Rules)
	assert.Equal(t, int32(0), removed.Msg.Policy.RuleCount)
	_, err = f.handlers.RemoveCompliancePolicyRule(ctx, connect.NewRequest(&pmv1.RemoveCompliancePolicyRuleRequest{
		PolicyId: policyID, ActionId: actionID,
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	_, err = f.handlers.DeleteCompliancePolicy(ctx, connect.NewRequest(&pmv1.DeleteCompliancePolicyRequest{Id: policyID}))
	require.NoError(t, err)
	_, err = f.handlers.GetCompliancePolicy(ctx, connect.NewRequest(&pmv1.GetCompliancePolicyRequest{Id: policyID}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	for _, procedure := range compliance.MutationProcedures() {
		operation, err := latestOperationFor(t, f.store, f.raw, procedure)
		require.NoError(t, err, procedure)
		effects, err := f.store.ListAuditEffects(context.Background(), operation.OperationID)
		require.NoError(t, err, procedure)
		assert.NotEmpty(t, effects, procedure)
	}
}

func TestCompliancePolicyHandlers_RejectsOrdinaryAndOutOfScopeActions(t *testing.T) {
	f := newComplianceHandlerFixture(t)
	actionState := authoring.New(authoring.Config{Store: f.store})
	nonCompliance := createPolicyAction(t, actionState, "ordinary shell", false)
	inScope := createPolicyAction(t, actionState, "visible compliance", true)
	outOfScope := createPolicyAction(t, actionState, "hidden compliance", true)
	policyState := compliance.NewState(compliance.StateConfig{Store: f.store})
	op := actionOperation()
	policy, err := policyState.Create(context.Background(), op, compliance.CreateParams{
		Name: "target", CreatedBy: op.ActorID,
	})
	require.NoError(t, err)

	global := f.actor("AddCompliancePolicyRule")
	_, err = f.handlers.AddCompliancePolicyRule(global, connect.NewRequest(&pmv1.AddCompliancePolicyRuleRequest{
		PolicyId: policy.ID, ActionId: nonCompliance,
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	groupA, groupB := newID(), newID()
	_, err = f.raw.Exec(context.Background(),
		`INSERT INTO device_groups (id, name) VALUES ($1, 'A'), ($2, 'B')`, groupA, groupB)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO assignments (id, source_type, source_id, target_type, target_id, created_at, created_by)
		VALUES ($1, 'compliance_policy', $2, 'device_group', $3, CURRENT_TIMESTAMP, $4),
		       ($5, 'action', $6, 'device_group', $3, CURRENT_TIMESTAMP, $4),
		       ($7, 'action', $8, 'device_group', $9, CURRENT_TIMESTAMP, $4)`,
		newID(), policy.ID, groupA, f.actorID,
		newID(), inScope, newID(), outOfScope, groupB)
	require.NoError(t, err)
	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser, Permissions: []string{"AddCompliancePolicyRule"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupA,
		}},
	})
	_, err = f.handlers.AddCompliancePolicyRule(scoped, connect.NewRequest(&pmv1.AddCompliancePolicyRuleRequest{
		PolicyId: policy.ID, ActionId: outOfScope,
	}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	_, err = f.handlers.AddCompliancePolicyRule(scoped, connect.NewRequest(&pmv1.AddCompliancePolicyRuleRequest{
		PolicyId: policy.ID, ActionId: inScope,
	}))
	require.NoError(t, err)
}

func TestCompliancePolicyHandlers_KeysetAndDirectScope(t *testing.T) {
	f := newComplianceHandlerFixture(t)
	state := compliance.NewState(compliance.StateConfig{Store: f.store, Now: func() time.Time { return f.now }})
	create := func(name string) string {
		op := actionOperation()
		row, err := state.Create(context.Background(), op, compliance.CreateParams{Name: name, CreatedBy: op.ActorID})
		require.NoError(t, err)
		return row.ID
	}
	directID, outsideID, unassignedID := create("direct"), create("outside"), create("unassigned")
	groupA, groupB := newID(), newID()
	_, err := f.raw.Exec(context.Background(),
		`INSERT INTO device_groups (id, name) VALUES ($1, 'A'), ($2, 'B')`, groupA, groupB)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO assignments (id, source_type, source_id, target_type, target_id, created_at, created_by)
		VALUES ($1, 'compliance_policy', $2, 'device_group', $3, $4, $5),
		       ($6, 'compliance_policy', $7, 'device_group', $8, $4, $5)`,
		newID(), directID, groupA, f.now, f.actorID,
		newID(), outsideID, groupB)
	require.NoError(t, err)

	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetCompliancePolicy", "ListCompliancePolicies", "RenameCompliancePolicy"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupA,
		}},
	})
	_, err = f.handlers.GetCompliancePolicy(scoped, connect.NewRequest(&pmv1.GetCompliancePolicyRequest{Id: directID}))
	require.NoError(t, err)
	for _, id := range []string{outsideID, unassignedID} {
		_, err = f.handlers.GetCompliancePolicy(scoped, connect.NewRequest(&pmv1.GetCompliancePolicyRequest{Id: id}))
		assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), id)
	}
	_, err = f.handlers.RenameCompliancePolicy(scoped, connect.NewRequest(&pmv1.RenameCompliancePolicyRequest{Id: outsideID, Name: "denied"}))
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	_, err = f.handlers.RenameCompliancePolicy(scoped, connect.NewRequest(&pmv1.RenameCompliancePolicyRequest{Id: directID, Name: "allowed"}))
	require.NoError(t, err)

	list, err := f.handlers.ListCompliancePolicies(scoped, connect.NewRequest(&pmv1.ListCompliancePoliciesRequest{}))
	require.NoError(t, err)
	require.Len(t, list.Msg.Policies, 1)
	assert.Equal(t, directID, list.Msg.Policies[0].Id)
	assert.Equal(t, int32(1), list.Msg.TotalCount)

	global := f.actor("ListCompliancePolicies")
	page, err := f.handlers.ListCompliancePolicies(global, connect.NewRequest(&pmv1.ListCompliancePoliciesRequest{PageSize: 1}))
	require.NoError(t, err)
	require.Len(t, page.Msg.Policies, 1)
	assert.NotEmpty(t, page.Msg.NextPageToken)
	assert.Equal(t, int32(3), page.Msg.TotalCount)
	all, err := f.handlers.ListCompliancePolicies(global, connect.NewRequest(&pmv1.ListCompliancePoliciesRequest{}))
	require.NoError(t, err)
	ids := []string{all.Msg.Policies[0].Id, all.Msg.Policies[1].Id, all.Msg.Policies[2].Id}
	sort.Strings(ids)
	want := []string{directID, outsideID, unassignedID}
	sort.Strings(want)
	assert.Equal(t, want, ids)
}

func TestCompliancePolicyRules_FollowLiveActionsAndActionDeletion(t *testing.T) {
	f := newComplianceHandlerFixture(t)
	actionState := authoring.New(authoring.Config{Store: f.store})
	actionID := createPolicyAction(t, actionState, "temporary", true)
	policyState := compliance.NewState(compliance.StateConfig{Store: f.store})
	policyOp := actionOperation()
	policy, err := policyState.Create(context.Background(), policyOp, compliance.CreateParams{
		Name: "policy", CreatedBy: policyOp.ActorID,
	})
	require.NoError(t, err)
	require.NoError(t, policyState.AddRule(context.Background(), actionOperation(), policy.ID, actionID, 0))

	require.NoError(t, actionState.DeleteAction(context.Background(), actionOperation(), actionID, false))
	rules, err := f.store.ListCompliancePolicyRules(context.Background(), policy.ID)
	require.NoError(t, err)
	assert.Empty(t, rules)
}

func TestCompliancePolicyRules_ProvideTransitiveActionReadScope(t *testing.T) {
	f := newComplianceHandlerFixture(t)
	actionState := authoring.New(authoring.Config{Store: f.store})
	actionID := createPolicyAction(t, actionState, "transitive", true)
	policyState := compliance.NewState(compliance.StateConfig{Store: f.store})
	policyOp := actionOperation()
	policy, err := policyState.Create(context.Background(), policyOp, compliance.CreateParams{
		Name: "assigned policy", CreatedBy: policyOp.ActorID,
	})
	require.NoError(t, err)
	require.NoError(t, policyState.AddRule(context.Background(), actionOperation(), policy.ID, actionID, 0))
	groupID := newID()
	_, err = f.raw.Exec(context.Background(), `INSERT INTO device_groups (id, name) VALUES ($1, 'A')`, groupID)
	require.NoError(t, err)
	_, err = f.raw.Exec(context.Background(), `
		INSERT INTO assignments (id, source_type, source_id, target_type, target_id, created_at, created_by)
		VALUES ($1, 'compliance_policy', $2, 'device_group', $3, CURRENT_TIMESTAMP, $4)`,
		newID(), policy.ID, groupID, f.actorID)
	require.NoError(t, err)

	scoped := auth.WithUser(context.Background(), &auth.UserContext{
		ID: f.actorID, Kind: auth.PrincipalUser,
		Permissions: []string{"GetAction", "ListActions"},
		ScopedGrants: []auth.ScopedGrant{{
			Permission: "ListDevices", ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupID,
		}},
	})
	_, err = f.actionHandlerFixture.handlers.GetAction(scoped, connect.NewRequest(&pmv1.GetActionRequest{Id: actionID}))
	require.NoError(t, err)
	listed, err := f.actionHandlerFixture.handlers.ListActions(scoped, connect.NewRequest(&pmv1.ListActionsRequest{}))
	require.NoError(t, err)
	require.Len(t, listed.Msg.Actions, 1)
	assert.Equal(t, actionID, listed.Msg.Actions[0].Id)
}

func TestCompliancePolicyHandlers_MountsExactCRUDSurface(t *testing.T) {
	f := newComplianceHandlerFixture(t)
	assert.Equal(t, []string{
		powermanagev1connect.ControlServiceCreateCompliancePolicyProcedure,
		powermanagev1connect.ControlServiceGetCompliancePolicyProcedure,
		powermanagev1connect.ControlServiceListCompliancePoliciesProcedure,
		powermanagev1connect.ControlServiceRenameCompliancePolicyProcedure,
		powermanagev1connect.ControlServiceUpdateCompliancePolicyDescriptionProcedure,
		powermanagev1connect.ControlServiceDeleteCompliancePolicyProcedure,
		powermanagev1connect.ControlServiceAddCompliancePolicyRuleProcedure,
		powermanagev1connect.ControlServiceRemoveCompliancePolicyRuleProcedure,
		powermanagev1connect.ControlServiceUpdateCompliancePolicyRuleProcedure,
	}, f.handlers.MountPolicies(http.NewServeMux()))
}
