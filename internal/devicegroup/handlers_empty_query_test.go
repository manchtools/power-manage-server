package devicegroup_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/testdb"
)

func seedBareDevice(t *testing.T, raw *testdb.DB, deviceID string) {
	t.Helper()
	_, err := raw.Exec(context.Background(),
		`INSERT INTO devices (id, hostname, agent_sealing_public_key) VALUES ($1, $2, $3)`,
		deviceID, "host-"+deviceID, make([]byte, 32))
	require.NoError(t, err)
}

// TestCreateDeviceGroup_EmptyDynamicQueryIsTheMatchAllRule proves the
// documented empty-query semantics through the real handlers: the parser
// treats the empty string as the always-true tree, the UI advertises "an
// empty query will match all devices", and the user-group path already
// accepts it — but validatedQuery rejected raw == "" for dynamic DEVICE
// groups, so the advertised match-all group was uncreatable. The evaluation
// half then proves the stored empty query really materializes every device.
func TestCreateDeviceGroup_EmptyDynamicQueryIsTheMatchAllRule(t *testing.T) {
	h, raw := newScopeFixture(t)
	ctx := context.Background()

	deviceA, deviceB := newID(), newID()
	seedBareDevice(t, raw, deviceA)
	seedBareDevice(t, raw, deviceB)

	creator := &auth.UserContext{
		ID: newID(), Kind: auth.PrincipalUser,
		Permissions: []string{"CreateDynamicDeviceGroup", "EvaluateDynamicGroup"},
	}
	callerCtx := auth.WithUser(ctx, creator)

	created, err := h.CreateDeviceGroup(callerCtx, connect.NewRequest(&pmv1.CreateDeviceGroupRequest{
		Name: "everything", IsDynamic: true, DynamicQuery: "",
	}))
	require.NoError(t, err, "an empty dynamic query is the documented match-all rule and must be creatable")
	require.NotNil(t, created.Msg.Group)
	assert.True(t, created.Msg.Group.IsDynamic)

	evaluated, err := h.EvaluateDynamicGroup(callerCtx, connect.NewRequest(&pmv1.EvaluateDynamicGroupRequest{
		Id: created.Msg.Group.Id,
	}))
	require.NoError(t, err)
	assert.EqualValues(t, 2, evaluated.Msg.DevicesAdded,
		"the stored empty query must materialize every registered device")

	var members int
	require.NoError(t, raw.QueryRow(ctx,
		`SELECT count(*) FROM device_group_members WHERE group_id = $1`,
		created.Msg.Group.Id).Scan(&members))
	assert.Equal(t, 2, members)
}

// The loosened gate must not admit a genuinely malformed query: garbage still
// fails before any write, as the positive control for the fix above.
func TestCreateDeviceGroup_MalformedDynamicQueryStaysRejected(t *testing.T) {
	h, _ := newScopeFixture(t)
	creator := &auth.UserContext{
		ID: newID(), Kind: auth.PrincipalUser,
		Permissions: []string{"CreateDynamicDeviceGroup"},
	}
	_, err := h.CreateDeviceGroup(auth.WithUser(context.Background(), creator),
		connect.NewRequest(&pmv1.CreateDeviceGroupRequest{
			Name: "broken", IsDynamic: true, DynamicQuery: `device.labels.env equals`,
		}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}
