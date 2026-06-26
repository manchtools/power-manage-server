package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// scopedToGroup builds a caller confined to a single device group (#7 spec 14).
// The permission strings are irrelevant to ObjectScopeListFilter (it keys off the
// grant's scope kind/id), but we include the object permission so the context is
// realistic.
func scopedToGroup(id, groupID string, perms ...string) (string, []auth.ScopedGrant) {
	grants := make([]auth.ScopedGrant, 0, len(perms))
	for _, p := range perms {
		grants = append(grants, auth.ScopedGrant{Permission: p, ScopeKind: auth.ScopeKindDeviceGroup, ScopeID: groupID})
	}
	return id, grants
}

func TestObjectScope_GetActionSet_InScope_Allowed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet A")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Set A")
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device_group", dg, 0)

	id, grants := scopedToGroup("scoped-admin", dg, "GetActionSet")
	ctx := testutil.AuthContextScoped(id, "s@test.com", []string{"GetActionSet"}, grants)

	resp, err := h.GetActionSet(ctx, connect.NewRequest(&pm.GetActionSetRequest{Id: setID}))
	require.NoError(t, err)
	assert.Equal(t, setID, resp.Msg.Set.Id)
}

func TestObjectScope_GetActionSet_OutOfScope_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	dgA := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet A")
	dgB := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet B")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Set A")
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device_group", dgA, 0)

	// Caller scoped to a DIFFERENT group than the set is assigned to.
	id, grants := scopedToGroup("scoped-admin", dgB, "GetActionSet")
	ctx := testutil.AuthContextScoped(id, "s@test.com", []string{"GetActionSet"}, grants)

	_, err := h.GetActionSet(ctx, connect.NewRequest(&pm.GetActionSetRequest{Id: setID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "out-of-scope must be NotFound, never PermissionDenied")
}

func TestObjectScope_GetActionSet_Unassigned_NotFound(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet A")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Orphan Set") // never assigned

	id, grants := scopedToGroup("scoped-admin", dg, "GetActionSet")
	ctx := testutil.AuthContextScoped(id, "s@test.com", []string{"GetActionSet"}, grants)

	_, err := h.GetActionSet(ctx, connect.NewRequest(&pm.GetActionSetRequest{Id: setID}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "unassigned object is invisible to a scoped admin (fail closed)")
}

func TestObjectScope_RenameActionSet_OutOfScope_PermissionDenied(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	dgA := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet A")
	dgB := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet B")
	setID := testutil.CreateTestActionSet(t, st, adminID, "Set A")
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device_group", dgA, 0)

	id, grants := scopedToGroup("scoped-admin", dgB, "RenameActionSet")
	ctx := testutil.AuthContextScoped(id, "s@test.com", []string{"RenameActionSet"}, grants)

	_, err := h.RenameActionSet(ctx, connect.NewRequest(&pm.RenameActionSetRequest{Id: setID, Name: "Hijack"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// Sanity: an in-scope caller CAN rename it.
	idOK, grantsOK := scopedToGroup("scoped-ok", dgA, "RenameActionSet")
	ctxOK := testutil.AuthContextScoped(idOK, "ok@test.com", []string{"RenameActionSet"}, grantsOK)
	_, err = h.RenameActionSet(ctxOK, connect.NewRequest(&pm.RenameActionSetRequest{Id: setID, Name: "Renamed"}))
	require.NoError(t, err)
}

// TransitiveRead: an action is only a MEMBER of an assigned set (not directly
// assigned). A scoped admin can READ it (effective scope, criterion 4) but cannot
// WRITE it (direct scope, criterion 6).
func TestObjectScope_TransitiveRead_GetAllowed_WriteDenied(t *testing.T) {
	st := testutil.SetupPostgres(t)
	setH := api.NewActionSetHandler(st, slog.Default())
	actH := api.NewActionHandler(st, slog.Default(), nil)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	adminCtx := testutil.AdminContext(adminID)
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet A")

	actionID := testutil.CreateTestAction(t, st, adminID, "Member Action", 1)
	setID := testutil.CreateTestActionSet(t, st, adminID, "Container Set")
	_, err := setH.AddActionToSet(adminCtx, connect.NewRequest(&pm.AddActionToSetRequest{SetId: setID, ActionId: actionID}))
	require.NoError(t, err)
	// Only the SET is assigned to the group; the action is in-scope only transitively.
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device_group", dg, 0)

	id, grants := scopedToGroup("scoped-admin", dg, "GetAction", "RenameAction")
	ctx := testutil.AuthContextScoped(id, "s@test.com", []string{"GetAction", "RenameAction"}, grants)

	// Read: allowed via the container (effective scope).
	getResp, err := actH.GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{Id: actionID}))
	require.NoError(t, err, "transitively in-scope action must be readable")
	assert.Equal(t, actionID, getResp.Msg.Action.Id)

	// Write: denied — the action is not DIRECTLY assigned to the caller's group.
	_, err = actH.RenameAction(ctx, connect.NewRequest(&pm.RenameActionRequest{Id: actionID, Name: "Hijack"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "transitive visibility must not grant write")
}

// CR (Critical): a scoped admin who owns an in-scope set must not be able to add
// an OUT-OF-SCOPE action to it — that would pull hidden org content into their
// fleet and make it transitively readable. The referenced action gets a
// read-scope check → NotFound (no existence leak).
func TestObjectScope_AddActionToSet_OutOfScopeActionRejected(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewActionSetHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	dg := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet A")
	dgOther := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet B")

	setID := testutil.CreateTestActionSet(t, st, adminID, "My Set")
	testutil.CreateTestAssignment(t, st, adminID, "action_set", setID, "device_group", dg, 0) // set in caller's scope

	outOfScope := testutil.CreateTestAction(t, st, adminID, "Secret Action", 1)
	testutil.CreateTestAssignment(t, st, adminID, "action", outOfScope, "device_group", dgOther, 0) // action out of scope

	id, grants := scopedToGroup("scoped-admin", dg, "AddActionToSet", "GetAction")
	ctx := testutil.AuthContextScoped(id, "s@test.com", []string{"AddActionToSet", "GetAction"}, grants)

	_, err := h.AddActionToSet(ctx, connect.NewRequest(&pm.AddActionToSetRequest{SetId: setID, ActionId: outOfScope}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err), "out-of-scope referenced action must be rejected (NotFound)")

	// Sanity: an in-scope action CAN be added to the set.
	inScope := testutil.CreateTestAction(t, st, adminID, "Own Action", 1)
	testutil.CreateTestAssignment(t, st, adminID, "action", inScope, "device_group", dg, 0)
	_, err = h.AddActionToSet(ctx, connect.NewRequest(&pm.AddActionToSetRequest{SetId: setID, ActionId: inScope}))
	require.NoError(t, err)
}
