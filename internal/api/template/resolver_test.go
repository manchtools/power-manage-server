package template_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api/template"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// storedShape mirrors the on-disk JSONB layout the handler writes;
// duplicated here so the tests don't depend on the (unexported)
// shape inside the template package.
type storedShape struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

func setDeviceGroupVars(t *testing.T, st *store.Store, groupID string, vars []storedShape) {
	t.Helper()
	raw, err := json.Marshal(vars)
	require.NoError(t, err)
	require.NoError(t, st.Queries().SetDeviceGroupVariables(context.Background(), db.SetDeviceGroupVariablesParams{
		ID:        groupID,
		Variables: raw,
	}))
}

func setUserGroupVars(t *testing.T, st *store.Store, groupID string, vars []storedShape) {
	t.Helper()
	raw, err := json.Marshal(vars)
	require.NoError(t, err)
	require.NoError(t, st.Queries().SetUserGroupVariables(context.Background(), db.SetUserGroupVariablesParams{
		ID:        groupID,
		Variables: raw,
	}))
}

func TestStoreResolver_EmptyDevice_EmptyVariables(t *testing.T) {
	st := testutil.SetupPostgres(t)
	defer st.Close()

	deviceID := testutil.CreateTestDevice(t, st, "host-empty")
	r := template.NewStoreResolver(st, testutil.NewEncryptor(t), slog.Default())

	vars, err := r.Resolve(context.Background(), deviceID)
	require.NoError(t, err)
	assert.Empty(t, vars)
}

// (Removed: TestStoreResolver_DeviceLabels_Surface +
// TestStoreResolver_PrecedenceLabelOverridesDeviceGroup. Device labels
// do NOT participate in variable resolution any more — variables are
// exclusively a group concept. See manchtools/power-manage-server#196
// scope correction.)

func TestStoreResolver_PrecedenceDeviceGroupOverridesUserGroup(t *testing.T) {
	st := testutil.SetupPostgres(t)
	defer st.Close()

	deviceID := testutil.CreateTestDevice(t, st, "host-prec2")
	dgID := testutil.CreateTestDeviceGroup(t, st, "u", "dg")
	testutil.AddDeviceToTestGroup(t, st, "u", dgID, deviceID)
	ugID := testutil.CreateTestUserGroup(t, st, "u", "ug")
	require.NoError(t, st.AppendEvent(context.Background(), store.Event{
		StreamType: "device", StreamID: deviceID, EventType: "DeviceGroupAssigned",
		Data:      map[string]any{"group_id": ugID},
		ActorType: "user", ActorID: "u",
	}))

	setUserGroupVars(t, st, ugID, []storedShape{{Name: "env", Type: "string", Value: "from-ug"}})
	setDeviceGroupVars(t, st, dgID, []storedShape{{Name: "env", Type: "string", Value: "from-dg"}})

	r := template.NewStoreResolver(st, testutil.NewEncryptor(t), slog.Default())
	vars, err := r.Resolve(context.Background(), deviceID)
	require.NoError(t, err)
	assert.Equal(t, "from-dg", vars["env"].Plaintext, "device-group var must shadow user-group var")
}

func TestStoreResolver_DuplicateNameWithinDeviceGroups_Errors(t *testing.T) {
	st := testutil.SetupPostgres(t)
	defer st.Close()

	deviceID := testutil.CreateTestDevice(t, st, "host-dup")
	g1 := testutil.CreateTestDeviceGroup(t, st, "u", "g1")
	g2 := testutil.CreateTestDeviceGroup(t, st, "u", "g2")
	testutil.AddDeviceToTestGroup(t, st, "u", g1, deviceID)
	testutil.AddDeviceToTestGroup(t, st, "u", g2, deviceID)
	setDeviceGroupVars(t, st, g1, []storedShape{{Name: "shared", Type: "string", Value: "a"}})
	setDeviceGroupVars(t, st, g2, []storedShape{{Name: "shared", Type: "string", Value: "b"}})

	r := template.NewStoreResolver(st, testutil.NewEncryptor(t), slog.Default())
	_, err := r.Resolve(context.Background(), deviceID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shared", "error message must name the offending variable")
}

func TestStoreResolver_SecretDecryptionRoundtrip(t *testing.T) {
	st := testutil.SetupPostgres(t)
	defer st.Close()
	enc := testutil.NewEncryptor(t)

	deviceID := testutil.CreateTestDevice(t, st, "host-secret")
	groupID := testutil.CreateTestDeviceGroup(t, st, "u", "secrets")
	testutil.AddDeviceToTestGroup(t, st, "u", groupID, deviceID)

	ciphertext, err := enc.Encrypt("hunter2")
	require.NoError(t, err)
	setDeviceGroupVars(t, st, groupID, []storedShape{
		{Name: "db_pwd", Type: "secret", Value: ciphertext},
	})

	r := template.NewStoreResolver(st, enc, slog.Default())
	vars, err := r.Resolve(context.Background(), deviceID)
	require.NoError(t, err)
	require.Contains(t, vars, "db_pwd")
	assert.Equal(t, "hunter2", vars["db_pwd"].Plaintext)
	assert.Equal(t, pmv1.VariableType_VARIABLE_TYPE_SECRET, vars["db_pwd"].Type)
}
