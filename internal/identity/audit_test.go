package identity_test

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

func TestAuditBoundary_ValidationPrecedesAuthentication(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, err := f.client.ListAuditEvents(f.ctx(), connect.NewRequest(&pmv1.ListAuditEventsRequest{
		ActorId: "not-a-ulid",
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))

	_, err = f.client.ExportAuditEvents(f.ctx(), connect.NewRequest(&pmv1.ExportAuditEventsRequest{
		Format: "xml",
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connectCodeOf(t, err))
}

func TestAuditEvents_ReadTheAppendOnlyEffectLog(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	operator := f.seedActor(grant{Permissions: []string{
		"GetServerSettings", "UpdateServerSettings", "ListAuditEvents",
	}})

	_, err := f.client.UpdateServerSettings(f.ctx(), authed(&pmv1.UpdateServerSettingsRequest{
		UserProvisioningEnabled: true,
	}, operator.Token))
	require.NoError(t, err)

	resp, err := f.client.ListAuditEvents(f.ctx(), authed(&pmv1.ListAuditEventsRequest{
		PageSize:   10,
		StreamType: "server_settings",
		EventType:  "provision",
	}, operator.Token))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Events, 1)
	assert.Equal(t, int32(1), resp.Msg.TotalCount)
	assert.Empty(t, resp.Msg.NextPageToken)

	event := resp.Msg.Events[0]
	assert.Equal(t, "SET_USER_PROVISIONING", event.EventType)
	assert.Equal(t, "server_settings", event.StreamType)
	assert.Equal(t, "00000000000000000000000003", event.StreamId)
	assert.Equal(t, operator.ID, event.ActorId)
	assert.NotNil(t, event.OccurredAt)

	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(event.Data), &data))
	assert.Equal(t, powermanagev1connect.ControlServiceUpdateServerSettingsProcedure, data["request_descriptor"])
	assert.Equal(t, "APPLIED", data["effect_outcome"])
	assert.NotContains(t, event.Data, "sealed_detail")
	assert.NotContains(t, event.Data, "prev_hash")
	assert.NotContains(t, event.Data, "row_hash")
}

func TestAuditEvents_KeepOperationOnlyRejectedAuthentication(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	operator := f.seedActor(grant{Permissions: []string{"ListAuditEvents"}})

	_, err := f.client.GetServerSettings(f.ctx(), authed(&pmv1.GetServerSettingsRequest{}, "invalid-token"))
	require.Error(t, err)

	resp, err := f.client.ListAuditEvents(f.ctx(), authed(&pmv1.ListAuditEventsRequest{
		StreamType: "authentication",
		EventType:  "reject",
	}, operator.Token))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Events, 1)
	event := resp.Msg.Events[0]
	assert.Equal(t, "AUTHENTICATION_REJECTED", event.EventType)
	assert.Equal(t, "authentication", event.StreamType)
	assert.Equal(t, "anonymous", event.ActorType)
	assert.Empty(t, event.ActorId)
	assert.NotEmpty(t, event.StreamId, "the operation id remains the durable target reference")
	assert.Contains(t, event.Data, powermanagev1connect.ControlServiceGetServerSettingsProcedure)
}

func TestAuditEvents_UseStableKeysetPagination(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	operator := f.seedActor(grant{Permissions: []string{
		"GetServerSettings", "UpdateServerSettings", "ListAuditEvents",
	}})

	_, err := f.client.UpdateServerSettings(f.ctx(), authed(&pmv1.UpdateServerSettingsRequest{
		UserProvisioningEnabled: true,
		SshAccessForAll:         true,
	}, operator.Token))
	require.NoError(t, err)

	first, err := f.client.ListAuditEvents(f.ctx(), authed(&pmv1.ListAuditEventsRequest{
		PageSize:   1,
		StreamType: "server_settings",
	}, operator.Token))
	require.NoError(t, err)
	require.Len(t, first.Msg.Events, 1)
	assert.Equal(t, int32(2), first.Msg.TotalCount)
	require.NotEmpty(t, first.Msg.NextPageToken)

	second, err := f.client.ListAuditEvents(f.ctx(), authed(&pmv1.ListAuditEventsRequest{
		PageSize:   1,
		PageToken:  first.Msg.NextPageToken,
		StreamType: "server_settings",
	}, operator.Token))
	require.NoError(t, err)
	require.Len(t, second.Msg.Events, 1)
	assert.NotEqual(t, first.Msg.Events[0].Id, second.Msg.Events[0].Id)
	assert.Empty(t, second.Msg.NextPageToken)
}

func TestExportAuditEvents_UsesTheSameSafeRowsAndAuditsTheRead(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	operator := f.seedActor(grant{Permissions: []string{
		"GetServerSettings", "UpdateServerSettings", "ListAuditEvents",
	}})

	_, err := f.client.UpdateServerSettings(f.ctx(), authed(&pmv1.UpdateServerSettingsRequest{
		UserProvisioningEnabled: true,
	}, operator.Token))
	require.NoError(t, err)

	resp, err := f.client.ExportAuditEvents(f.ctx(), authed(&pmv1.ExportAuditEventsRequest{
		Format: "json",
	}, operator.Token))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.NextPageToken)
	var rows []map[string]any
	require.NoError(t, json.Unmarshal(resp.Msg.Chunk, &rows))
	require.Len(t, rows, 2)
	assert.ElementsMatch(t, []any{"SET_USER_PROVISIONING", "SET_SSH_ACCESS"},
		[]any{rows[0]["event_type"], rows[1]["event_type"]})
	assert.NotContains(t, string(resp.Msg.Chunk), "sealed_detail")

	csvResp, err := f.client.ExportAuditEvents(f.ctx(), authed(&pmv1.ExportAuditEventsRequest{
		Format:      "csv",
		StreamTypes: []string{"server_settings"},
	}, operator.Token))
	require.NoError(t, err)
	records, err := csv.NewReader(strings.NewReader(string(csvResp.Msg.Chunk))).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 3)
	assert.Equal(t, []string{"id", "occurred_at", "actor_type", "actor_id", "stream_type", "stream_id", "event_type", "data"}, records[0])

	ops := f.operationsFor(powermanagev1connect.ControlServiceExportAuditEventsProcedure)
	require.Len(t, ops, 2)
	for _, op := range ops {
		assert.Equal(t, "SENSITIVE_READ", op.Class)
		effects := f.effectsOf(op.OperationID)
		require.Len(t, effects, 1)
		assert.Equal(t, "audit_log", effects[0].ResourceType)
		assert.Equal(t, "EXPORT", effects[0].Action)
	}
}
