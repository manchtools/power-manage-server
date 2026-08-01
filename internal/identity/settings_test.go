package identity_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

func TestServerSettings_DirectAuditedCRUD(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	operator := f.seedActor(grant{Permissions: []string{"GetServerSettings", "UpdateServerSettings"}})

	initial, err := f.client.GetServerSettings(f.ctx(), authed(&pmv1.GetServerSettingsRequest{}, operator.Token))
	require.NoError(t, err)
	assert.False(t, initial.Msg.Settings.UserProvisioningEnabled)
	assert.False(t, initial.Msg.Settings.SshAccessForAll)

	updated, err := f.client.UpdateServerSettings(f.ctx(), authed(&pmv1.UpdateServerSettingsRequest{
		UserProvisioningEnabled: true, SshAccessForAll: true,
	}, operator.Token))
	require.NoError(t, err)
	assert.True(t, updated.Msg.Settings.UserProvisioningEnabled)
	assert.True(t, updated.Msg.Settings.SshAccessForAll)

	stored, err := f.client.GetServerSettings(f.ctx(), authed(&pmv1.GetServerSettingsRequest{}, operator.Token))
	require.NoError(t, err)
	assert.Equal(t, updated.Msg.Settings, stored.Msg.Settings)

	op := f.onlyOperationFor(powermanagev1connect.ControlServiceUpdateServerSettingsProcedure)
	assert.Equal(t, operator.ID, op.ActorID)
	effects := f.effectsOf(op.OperationID)
	provisioning := f.effectWithAction(effects, "SET_USER_PROVISIONING")
	ssh := f.effectWithAction(effects, "SET_SSH_ACCESS")
	assert.Equal(t, "00000000000000000000000003", provisioning.ResourceID)
	require.NotNil(t, provisioning.BeforeFlag)
	require.NotNil(t, provisioning.AfterFlag)
	assert.False(t, *provisioning.BeforeFlag)
	assert.True(t, *provisioning.AfterFlag)
	require.NotNil(t, ssh.BeforeFlag)
	require.NotNil(t, ssh.AfterFlag)
	assert.False(t, *ssh.BeforeFlag)
	assert.True(t, *ssh.AfterFlag)
}
