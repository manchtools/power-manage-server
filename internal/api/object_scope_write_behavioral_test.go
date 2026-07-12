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
type objWriteDriver struct {
	objType string
	perm    string // the mutation permission the scoped caller holds
	create  func(t *testing.T, st *store.Store, adminID string) string
	rename  func(ctx context.Context, st *store.Store, id string) error
}

func objWriteDrivers() []objWriteDriver {
	logger := slog.Default()
	return []objWriteDriver{
		{
			objType: "action", perm: "RenameAction",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				return testutil.CreateTestAction(t, st, adminID, "Target Action", 1)
			},
			rename: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewActionHandler(st, logger, nil).RenameAction(ctx, connect.NewRequest(&pm.RenameActionRequest{Id: id, Name: "Renamed"}))
				return err
			},
		},
		{
			objType: "action_set", perm: "RenameActionSet",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				return testutil.CreateTestActionSet(t, st, adminID, "Target Set")
			},
			rename: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewActionSetHandler(st, logger).RenameActionSet(ctx, connect.NewRequest(&pm.RenameActionSetRequest{Id: id, Name: "Renamed"}))
				return err
			},
		},
		{
			objType: "definition", perm: "RenameDefinition",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				return testutil.CreateTestDefinition(t, st, adminID, "Target Def")
			},
			rename: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewDefinitionHandler(st, logger).RenameDefinition(ctx, connect.NewRequest(&pm.RenameDefinitionRequest{Id: id, Name: "Renamed"}))
				return err
			},
		},
		{
			objType: "compliance_policy", perm: "RenameCompliancePolicy",
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
		},
	}
}

// TestObjectWriteHandlers_ConfineOutOfScope is the write-side behavioral
// companion to TestObjectReadHandlers_ConfineOutOfScope (spec 30 AC 5): it drives
// every scopable object type's mutation through the REAL handler with a
// group-scoped caller and an out-of-scope object, and asserts PermissionDenied
// (out-of-scope writes are refused, not silently NotFound — the object's
// existence within the org is not the secret here; the write authority is). A
// per-type in-scope positive control proves the gate confines rather than
// blanket-denies. Write scope uses DIRECT group membership (no transitive
// container walk), so a caller scoped to a different group than the object's
// direct assignment is refused.
func TestObjectWriteHandlers_ConfineOutOfScope(t *testing.T) {
	drivers := objWriteDrivers()
	require.NotEmpty(t, drivers, "no object write drivers — the sweep would pass vacuously")

	for _, d := range drivers {
		t.Run(d.objType, func(t *testing.T) {
			st := testutil.SetupPostgres(t)
			adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
			dgA := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet A")
			dgB := testutil.CreateTestDeviceGroup(t, st, adminID, "Fleet B")

			id := d.create(t, st, adminID)
			testutil.CreateTestAssignment(t, st, adminID, d.objType, id, "device_group", dgA, 0)

			// Caller scoped to dgB — a DIFFERENT group than the object is assigned to.
			sid, grants := scopedToGroup("scoped-"+d.objType, dgB, d.perm)
			ctx := testutil.AuthContextScoped(sid, "s@test.com", []string{d.perm}, grants)

			err := d.rename(ctx, st, id)
			require.Errorf(t, err, "%s: out-of-scope write must error", d.objType)
			assert.Equalf(t, connect.CodePermissionDenied, connect.CodeOf(err),
				"%s: out-of-scope write must be PermissionDenied; got %v", d.objType, connect.CodeOf(err))

			// Positive control: an IN-scope caller (scoped to dgA) can rename it.
			okID, okGrants := scopedToGroup("scoped-ok-"+d.objType, dgA, d.perm)
			okCtx := testutil.AuthContextScoped(okID, "ok@test.com", []string{d.perm}, okGrants)
			require.NoErrorf(t, d.rename(okCtx, st, id), "%s: in-scope write must succeed", d.objType)
		})
	}
}
