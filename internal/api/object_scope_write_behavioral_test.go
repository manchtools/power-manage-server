package api_test

import (
	"context"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// objWriteDriver drives one scopable object type through a representative
// mutation (Rename) for the behavioral out-of-scope confinement sweep.
// readName performs a privileged (admin) read of the object's current name so
// the sweep can assert a denied write did NOT persist and an allowed write did.
type objWriteDriver struct {
	objType  string
	perm     string // the mutation permission the scoped caller holds
	origName string // the name create() assigns
	create   func(t *testing.T, st *store.Store, adminID string) string
	rename   func(ctx context.Context, st *store.Store, id string) error // renames to "Renamed"
	readName func(t *testing.T, st *store.Store, adminID, id string) string
}

func objWriteDrivers() []objWriteDriver {
	logger := slog.Default()
	return []objWriteDriver{
		{
			objType: "action", perm: "RenameAction", origName: "Target Action",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				return testutil.CreateTestAction(t, st, adminID, "Target Action", 1)
			},
			rename: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewActionHandler(st, logger, nil).RenameAction(ctx, connect.NewRequest(&pm.RenameActionRequest{Id: id, Name: "Renamed"}))
				return err
			},
			readName: func(t *testing.T, st *store.Store, adminID, id string) string {
				resp, err := api.NewActionHandler(st, logger, nil).GetAction(testutil.AdminContext(adminID), connect.NewRequest(&pm.GetActionRequest{Id: id}))
				require.NoError(t, err)
				return resp.Msg.GetAction().GetName()
			},
		},
		{
			objType: "action_set", perm: "RenameActionSet", origName: "Target Set",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				return testutil.CreateTestActionSet(t, st, adminID, "Target Set")
			},
			rename: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewActionSetHandler(st, logger).RenameActionSet(ctx, connect.NewRequest(&pm.RenameActionSetRequest{Id: id, Name: "Renamed"}))
				return err
			},
			readName: func(t *testing.T, st *store.Store, adminID, id string) string {
				resp, err := api.NewActionSetHandler(st, logger).GetActionSet(testutil.AdminContext(adminID), connect.NewRequest(&pm.GetActionSetRequest{Id: id}))
				require.NoError(t, err)
				return resp.Msg.GetSet().GetName()
			},
		},
		{
			objType: "definition", perm: "RenameDefinition", origName: "Target Def",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				return testutil.CreateTestDefinition(t, st, adminID, "Target Def")
			},
			rename: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewDefinitionHandler(st, logger).RenameDefinition(ctx, connect.NewRequest(&pm.RenameDefinitionRequest{Id: id, Name: "Renamed"}))
				return err
			},
			readName: func(t *testing.T, st *store.Store, adminID, id string) string {
				resp, err := api.NewDefinitionHandler(st, logger).GetDefinition(testutil.AdminContext(adminID), connect.NewRequest(&pm.GetDefinitionRequest{Id: id}))
				require.NoError(t, err)
				return resp.Msg.GetDefinition().GetName()
			},
		},
		{
			objType: "compliance_policy", perm: "RenameCompliancePolicy", origName: "Target Policy",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				resp, err := api.NewCompliancePolicyHandler(st, logger).CreateCompliancePolicy(
					testutil.AdminContext(adminID),
					connect.NewRequest(&pm.CreateCompliancePolicyRequest{Name: "Target Policy"}))
				require.NoError(t, err)
				return resp.Msg.Policy.Id
			},
			rename: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewCompliancePolicyHandler(st, logger).RenameCompliancePolicy(ctx, connect.NewRequest(&pm.RenameCompliancePolicyRequest{Id: id, Name: "Renamed"}))
				return err
			},
			readName: func(t *testing.T, st *store.Store, adminID, id string) string {
				resp, err := api.NewCompliancePolicyHandler(st, logger).GetCompliancePolicy(testutil.AdminContext(adminID), connect.NewRequest(&pm.GetCompliancePolicyRequest{Id: id}))
				require.NoError(t, err)
				return resp.Msg.GetPolicy().GetName()
			},
		},
	}
}

// TestObjectWriteHandlers_ConfineOutOfScope is the write-side behavioral
// companion to TestObjectReadHandlers_ConfineOutOfScope (spec 30 AC 5). It drives
// every scopable object type's mutation through the real handler with a
// group-scoped caller and an out-of-scope object, and asserts PermissionDenied
// (out-of-scope writes are refused; write authority is the secret, not
// existence). It also reads the object back with a privileged caller to assert
// the denied write did NOT persist, so a handler that appends the mutation before
// returning the error (right code, leaked write) still fails. A per-type in-scope
// positive control proves the gate confines rather than blanket-denies, and that
// an allowed write does persist. Write scope keys on DIRECT group membership.
func TestObjectWriteHandlers_ConfineOutOfScope(t *testing.T) {
	drivers := objWriteDrivers()
	require.NotEmpty(t, drivers, "no object write drivers — the sweep would pass vacuously")

	covered := map[string]bool{}
	for _, d := range drivers {
		covered[d.objType] = true
	}
	requireCoversAllObjectTypes(t, covered)

	for _, d := range drivers {
		t.Run(d.objType, func(t *testing.T) {
			st := testutil.SetupPostgres(t)
			adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
			dgA := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet A")
			dgB := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet B")

			id := d.create(t, st, adminID)
			testutil.CreateTestAssignment(t, st, adminID, d.objType, id, "device_group", dgA, 0)

			// Caller scoped to dgB, a DIFFERENT group than the object is assigned to.
			sid, grants := scopedToGroup("scoped-"+d.objType, dgB, d.perm)
			ctx := testutil.AuthContextScoped(sid, "s@test.com", []string{d.perm}, grants)

			err := d.rename(ctx, st, id)
			require.Errorf(t, err, "%s: out-of-scope write must error", d.objType)
			assert.Equalf(t, connect.CodePermissionDenied, connect.CodeOf(err),
				"%s: out-of-scope write must be PermissionDenied; got %v", d.objType, connect.CodeOf(err))
			assert.Equalf(t, d.origName, d.readName(t, st, adminID, id),
				"%s: a denied write must NOT persist (the mutation leaked despite the error)", d.objType)

			// Positive control: an IN-scope caller (scoped to dgA) can rename it, and
			// the change persists.
			okID, okGrants := scopedToGroup("scoped-ok-"+d.objType, dgA, d.perm)
			okCtx := testutil.AuthContextScoped(okID, "ok@test.com", []string{d.perm}, okGrants)
			require.NoErrorf(t, d.rename(okCtx, st, id), "%s: in-scope write must succeed", d.objType)
			assert.Equalf(t, "Renamed", d.readName(t, st, adminID, id),
				"%s: an allowed write must persist", d.objType)
		})
	}
}
