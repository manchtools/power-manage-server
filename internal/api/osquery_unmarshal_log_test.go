package api_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// captureHandler records every slog record so tests can assert that a code
// path logged (and at what level / with which attrs) instead of swallowing.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// hasRecordAtLeast reports whether any captured record at >= minLevel mentions
// substr (in its message or any attribute value).
func (h *captureHandler) hasRecordAtLeast(minLevel slog.Level, substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Level < minLevel {
			continue
		}
		rendered := r.Message
		r.Attrs(func(a slog.Attr) bool {
			rendered += " " + a.Key + "=" + fmt.Sprint(a.Value.Any())
			return true
		})
		if substr == "" || strings.Contains(rendered, substr) {
			return true
		}
	}
	return false
}

// WS16 #11: GetOSQueryResult (and the device-inventory path) swallowed a JSONB
// decode error (`if err == nil { ... }` with no else), returning empty success
// as if the device reported no rows. A corrupt result must be LOGGED with its
// query_id, not silently reported clean.
func TestGetOSQueryResult_RowsUnmarshalFailure_IsLoggedNotSilentlyEmpty(t *testing.T) {
	st := testutil.SetupPostgres(t)
	cap := &captureHandler{}
	h := api.NewOSQueryHandler(st, slog.New(cap), api.NoOpSigner{})
	h.SetTaskQueueClient(&api.NoOpEnqueuer{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)
	deviceID := testutil.CreateTestDevice(t, st, "corrupt-rows-host")

	dispatchResp, err := h.DispatchOSQuery(ctx, connect.NewRequest(&pm.DispatchOSQueryRequest{
		DeviceId: deviceID,
		Table:    "processes",
	}))
	require.NoError(t, err)
	queryID := dispatchResp.Msg.QueryId

	// Complete the result with INVALID JSON in Rows (a device/relay could send
	// malformed bytes; the column is JSONB-typed but `"…"` is valid JSON that
	// is not the expected array-of-objects).
	_, err = st.Queries().CompleteOSQueryResult(ctx, generated.CompleteOSQueryResultParams{
		QueryID:  queryID,
		Success:  true,
		Error:    "",
		Rows:     []byte(`"not-an-array-of-rows"`),
		DeviceID: deviceID,
	})
	require.NoError(t, err)

	resp, err := h.GetOSQueryResult(ctx, connect.NewRequest(&pm.GetOSQueryResultRequest{QueryId: queryID}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.Rows, "corrupt rows cannot decode into proto rows")

	assert.True(t, cap.hasRecordAtLeast(slog.LevelWarn, queryID),
		"a JSONB rows-decode failure must be logged at Warn/Error with the query_id, not silently returned as a clean empty result")
}
