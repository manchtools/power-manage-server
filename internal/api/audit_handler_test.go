package api_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestListAuditEvents(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Creating the user above produces a UserCreated event
	resp, err := h.ListAuditEvents(ctx, connect.NewRequest(&pm.ListAuditEventsRequest{}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Msg.Events), 1)
}

func TestListAuditEvents_FilterByStreamType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "audit-host")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ListAuditEvents(ctx, connect.NewRequest(&pm.ListAuditEventsRequest{
		StreamType: "device",
	}))
	require.NoError(t, err)
	for _, e := range resp.Msg.Events {
		assert.Equal(t, "device", e.StreamType)
	}
}

func TestListAuditEvents_FilterByEventType(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ListAuditEvents(ctx, connect.NewRequest(&pm.ListAuditEventsRequest{
		EventType: "UserCreated",
	}))
	require.NoError(t, err)
	for _, e := range resp.Msg.Events {
		assert.Equal(t, "UserCreated", e.EventType)
	}
}

func TestListAuditEvents_Pagination(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st)

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// Create several events
	for i := 0; i < 5; i++ {
		testutil.CreateTestDevice(t, st, testutil.NewID()+"-host")
	}

	resp, err := h.ListAuditEvents(ctx, connect.NewRequest(&pm.ListAuditEventsRequest{
		PageSize: 3,
	}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Events, 3)
	assert.NotEmpty(t, resp.Msg.NextPageToken)

	// Fetch next page
	resp2, err := h.ListAuditEvents(ctx, connect.NewRequest(&pm.ListAuditEventsRequest{
		PageSize:  3,
		PageToken: resp.Msg.NextPageToken,
	}))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp2.Msg.Events), 2)
}
