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

// objReadDriver drives one scopable object type through its Get RPC for the
// behavioral out-of-scope confinement sweep. create returns a new object id
// (owned by admin, not yet assigned); get invokes the REAL Get handler under ctx
// and returns the connect error.
type objReadDriver struct {
	objType string // the assignment/object type (== an objectTypeToIndexScope key)
	perm    string // the Get permission the scoped caller holds
	create  func(t *testing.T, st *store.Store, adminID string) string
	get     func(ctx context.Context, st *store.Store, id string) error
}

func objReadDrivers() []objReadDriver {
	logger := slog.Default()
	return []objReadDriver{
		{
			objType: "action", perm: "GetAction",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				return testutil.CreateTestAction(t, st, adminID, "Secret Action", 1)
			},
			get: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewActionHandler(st, logger, nil).GetAction(ctx, connect.NewRequest(&pm.GetActionRequest{Id: id}))
				return err
			},
		},
		{
			objType: "action_set", perm: "GetActionSet",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				return testutil.CreateTestActionSet(t, st, adminID, "Secret Set")
			},
			get: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewActionSetHandler(st, logger).GetActionSet(ctx, connect.NewRequest(&pm.GetActionSetRequest{Id: id}))
				return err
			},
		},
		{
			objType: "definition", perm: "GetDefinition",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				return testutil.CreateTestDefinition(t, st, adminID, "Secret Def")
			},
			get: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewDefinitionHandler(st, logger).GetDefinition(ctx, connect.NewRequest(&pm.GetDefinitionRequest{Id: id}))
				return err
			},
		},
		{
			objType: "compliance_policy", perm: "GetCompliancePolicy",
			create: func(t *testing.T, st *store.Store, adminID string) string {
				resp, err := api.NewCompliancePolicyHandler(st, logger).CreateCompliancePolicy(
					testutil.AdminContext(adminID),
					connect.NewRequest(&pm.CreateCompliancePolicyRequest{Name: "Secret Policy"}))
				require.NoError(t, err)
				return resp.Msg.Policy.Id
			},
			get: func(ctx context.Context, st *store.Store, id string) error {
				_, err := api.NewCompliancePolicyHandler(st, logger).GetCompliancePolicy(ctx, connect.NewRequest(&pm.GetCompliancePolicyRequest{Id: id}))
				return err
			},
		},
	}
}

// TestObjectReadHandlers_ConfineOutOfScope is the behavioral backstop (spec 30
// AC 5) to the AST read guard: it drives every scopable object type's Get RPC
// through the REAL handler with a group-scoped caller and a seeded out-of-scope
// object, and asserts confinement (NotFound — no existence leak), plus an
// in-scope positive control per type. AST presence proves enforceObjectReadScope
// is CALLED; this proves it actually CONFINES — the exact "presence ≠ behavior"
// gap that let spec 29 S1 through a green suite.
//
// Completeness: the AST guard TestObjectGetHandlers_AllReadScopeEnforced
// self-discovers the object-type set from objectTypeToIndexScope and fails if a
// new type's Get is unenforced, which forces a driver to be added here too.
func TestObjectReadHandlers_ConfineOutOfScope(t *testing.T) {
	drivers := objReadDrivers()
	require.NotEmpty(t, drivers, "no object read drivers — the sweep would pass vacuously")

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

			err := d.get(ctx, st, id)
			require.Errorf(t, err, "%s: out-of-scope Get must error", d.objType)
			assert.Equalf(t, connect.CodeNotFound, connect.CodeOf(err),
				"%s: out-of-scope Get must be NotFound (never PermissionDenied — no existence leak); got %v",
				d.objType, connect.CodeOf(err))

			// Positive control: an IN-scope caller (scoped to dgA) can read it —
			// proving the gate confines, not just blanket-denies.
			okID, okGrants := scopedToGroup("scoped-ok-"+d.objType, dgA, d.perm)
			okCtx := testutil.AuthContextScoped(okID, "ok@test.com", []string{d.perm}, okGrants)
			require.NoErrorf(t, d.get(okCtx, st, id), "%s: in-scope Get must succeed", d.objType)
		})
	}
}
