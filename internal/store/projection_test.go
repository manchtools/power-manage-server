package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestProjection_ActionRenameWithSoftDeletedSameName(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	// Create action "Test Action"
	action1ID := testutil.CreateTestAction(t, st, actorID, "Test Action", 1)

	// Delete it
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   action1ID,
		EventType:  "ActionDeleted",
		Data:       map[string]any{},
		ActorType:  "user",
		ActorID:    actorID,
	})
	require.NoError(t, err)

	// Create another action "Other Action"
	action2ID := testutil.CreateTestAction(t, st, actorID, "Other Action", 1)

	// Rename "Other Action" to "Test Action" (same name as the soft-deleted one)
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   action2ID,
		EventType:  "ActionRenamed",
		Data:       map[string]any{"name": "Test Action"},
		ActorType:  "user",
		ActorID:    actorID,
	})
	require.NoError(t, err, "rename should succeed even though a soft-deleted action has the same name")

	// Verify the rename succeeded
	var name string
	err = st.Pool().QueryRow(ctx,
		"SELECT name FROM actions_projection WHERE id = $1",
		action2ID,
	).Scan(&name)
	require.NoError(t, err)
	assert.Equal(t, "Test Action", name)
}

func TestProjection_ActionRenameCascadesToCompliancePolicyRules(t *testing.T) {
	st := testutil.SetupPostgres(t)
	ctx := context.Background()

	actorID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	// Create a compliance policy
	policyID := testutil.NewID()
	err := st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   policyID,
		EventType:  "CompliancePolicyCreated",
		Data: map[string]any{
			"name":        "Test Policy",
			"description": "",
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	require.NoError(t, err)

	// Create an action "Original Name"
	actionID := testutil.CreateTestAction(t, st, actorID, "Original Name", 1)

	// Add the action as a rule to the compliance policy
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "compliance_policy",
		StreamID:   policyID,
		EventType:  "CompliancePolicyRuleAdded",
		Data: map[string]any{
			"action_id":          actionID,
			"action_name":        "Original Name",
			"grace_period_hours": 0,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	require.NoError(t, err)

	// Verify the rule's action_name = "Original Name"
	rules, err := st.Queries().ListCompliancePolicyRules(ctx, policyID)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "Original Name", rules[0].ActionName)

	// Rename the action to "New Name"
	err = st.AppendEvent(ctx, store.Event{
		StreamType: "action",
		StreamID:   actionID,
		EventType:  "ActionRenamed",
		Data:       map[string]any{"name": "New Name"},
		ActorType:  "user",
		ActorID:    actorID,
	})
	require.NoError(t, err)

	// Read the compliance policy rules back
	rules, err = st.Queries().ListCompliancePolicyRules(ctx, policyID)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	// Verify the rule's action_name was cascaded to "New Name"
	assert.Equal(t, "New Name", rules[0].ActionName)
}
