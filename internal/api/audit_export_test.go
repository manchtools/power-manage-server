package api_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

func TestExportAuditEvents_CSVRespectsFilters(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "export-host-a")
	testutil.CreateTestDevice(t, st, "export-host-b")
	ctx := testutil.AdminContext(adminID)

	var artifact bytes.Buffer
	chunks := 0
	token := ""
	for {
		resp, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
			Format:      "csv",
			StreamTypes: []string{"device"},
			PageToken:   token,
		}))
		require.NoError(t, err)
		artifact.Write(resp.Msg.Chunk)
		chunks++
		token = resp.Msg.NextPageToken
		if token == "" {
			break
		}
	}

	records, err := csv.NewReader(&artifact).ReadAll()
	require.NoError(t, err, "export must be one valid CSV document")
	require.NotEmpty(t, records)
	assert.Equal(t, []string{"id", "occurred_at", "actor_type", "actor_id", "stream_type", "stream_id", "event_type", "data"}, records[0])
	require.GreaterOrEqual(t, len(records), 3, "expected the header plus both seeded device events")
	for _, row := range records[1:] {
		assert.Equal(t, "device", row[4], "stream_types filter must reach the query, row: %v", row)
	}
	_ = chunks
}

func TestExportAuditEvents_JSONChunksConcatenateToOneDocument(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	for i := 0; i < 5; i++ {
		testutil.CreateTestDevice(t, st, testutil.NewID()+"-host")
	}
	ctx := testutil.AdminContext(adminID)

	// Shrink the server-side page so the export must span several
	// chunks — this is what proves AC5 (bounded pages, no full-set
	// buffering) rather than a single lucky chunk.
	restore := api.SetExportPageSizeForTest(2)
	defer restore()

	var artifact bytes.Buffer
	chunks := 0
	token := ""
	for {
		resp, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
			Format:    "json",
			PageToken: token,
		}))
		require.NoError(t, err)
		artifact.Write(resp.Msg.Chunk)
		chunks++
		token = resp.Msg.NextPageToken
		if token == "" {
			break
		}
	}

	require.Greater(t, chunks, 2, "5+ events at page size 2 must take several chunks")

	var rows []map[string]any
	require.NoError(t, json.Unmarshal(artifact.Bytes(), &rows),
		"concatenated chunks must form one valid JSON array: %s", artifact.String())
	require.GreaterOrEqual(t, len(rows), 6, "5 devices + admin user events")

	// Row count must match what the list endpoint reports for the
	// same (empty) filter — the export may not silently drop rows.
	listResp, err := h.ListAuditEvents(ctx, connect.NewRequest(&pm.ListAuditEventsRequest{PageSize: 100}))
	require.NoError(t, err)
	assert.Equal(t, int(listResp.Msg.TotalCount), len(rows))

	// No duplicates: keyset pagination must not repeat rows across
	// chunk boundaries.
	seen := map[string]bool{}
	for _, r := range rows {
		id, _ := r["id"].(string)
		require.NotEmpty(t, id)
		assert.False(t, seen[id], "event %s exported twice", id)
		seen[id] = true
	}
}

// TestExportAuditEvents_RedactionApplied drives the REAL CreateAction
// emit path (like TestListAuditEvents_RedactsActionSecrets) and then
// asserts the export applies the same read-side redaction as
// ListAuditEvents: the secret never appears, in either format.
func TestExportAuditEvents_RedactionApplied(t *testing.T) {
	const sentinel = "SENTINEL_EXPORT_9c2e"

	for _, format := range []string{"csv", "json"} {
		t.Run(format, func(t *testing.T) {
			st := testutil.SetupPostgres(t)
			actionH := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
			h := api.NewAuditHandler(st, slog.Default())
			adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
			ctx := testutil.AdminContext(adminID)

			_, err := actionH.CreateAction(ctx, connect.NewRequest(&pm.CreateActionRequest{
				Name: "export-leak",
				Type: pm.ActionType_ACTION_TYPE_SHELL,
				Params: &pm.CreateActionRequest_Shell{
					Shell: &pm.ShellParams{Script: sentinel},
				},
			}))
			require.NoError(t, err)

			var artifact bytes.Buffer
			token := ""
			for {
				resp, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
					Format:    format,
					PageToken: token,
				}))
				require.NoError(t, err)
				artifact.Write(resp.Msg.Chunk)
				token = resp.Msg.NextPageToken
				if token == "" {
					break
				}
			}

			out := artifact.String()
			assert.NotContains(t, out, sentinel, "secret leaked unredacted into the %s export", format)
			assert.Contains(t, out, "[REDACTED]", "the ActionCreated payload must carry the redaction marker")
		})
	}
}

func TestExportAuditEvents_ActorFilter(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st, slog.Default())
	actionH := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	otherID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// The factories append events as actor "test", so give otherID a
	// REAL handler-emitted event (ActionCreated) — without it a broken
	// actor filter would pass vacuously on an empty result.
	_, err := actionH.CreateAction(testutil.AdminContext(otherID), connect.NewRequest(&pm.CreateActionRequest{
		Name: "actor-filter-probe",
		Type: pm.ActionType_ACTION_TYPE_SHELL,
		Params: &pm.CreateActionRequest_Shell{
			Shell: &pm.ShellParams{Script: "true"},
		},
	}))
	require.NoError(t, err)

	var artifact bytes.Buffer
	token := ""
	for {
		resp, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
			Format:    "json",
			ActorId:   otherID,
			PageToken: token,
		}))
		require.NoError(t, err)
		artifact.Write(resp.Msg.Chunk)
		token = resp.Msg.NextPageToken
		if token == "" {
			break
		}
	}

	var rows []map[string]any
	require.NoError(t, json.Unmarshal(artifact.Bytes(), &rows))
	require.NotEmpty(t, rows, "otherID's ActionCreated event must be exported")
	for _, r := range rows {
		assert.Equal(t, otherID, r["actor_id"], "actor filter must reach the query")
	}
}

func TestExportAuditEvents_DateRangeFilter(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	// A lower bound far in the future matches nothing: the artifact
	// must still be a VALID empty document (header-only CSV, "[]"
	// JSON) with no next page.
	future := timestamppb.New(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))

	respJSON, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
		Format:       "json",
		OccurredFrom: future,
	}))
	require.NoError(t, err)
	assert.Empty(t, respJSON.Msg.NextPageToken)
	var rows []map[string]any
	require.NoError(t, json.Unmarshal(respJSON.Msg.Chunk, &rows))
	assert.Empty(t, rows)

	respCSV, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
		Format:       "csv",
		OccurredFrom: future,
	}))
	require.NoError(t, err)
	assert.Empty(t, respCSV.Msg.NextPageToken)
	records, err := csv.NewReader(bytes.NewReader(respCSV.Msg.Chunk)).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 1, "empty export still carries the header row")

	// And an unbounded export DOES return rows (sanity complement).
	respAll, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
		Format: "json",
	}))
	require.NoError(t, err)
	var allRows []map[string]any
	require.NoError(t, json.Unmarshal(respAll.Msg.Chunk, &allRows))
	assert.NotEmpty(t, allRows)
}

func TestExportAuditEvents_UnsupportedFormat(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for _, format := range []string{"", "xml", "CSV "} {
		_, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
			Format: format,
		}))
		require.Error(t, err, "format %q must be rejected", format)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	}
}

func TestExportAuditEvents_InvalidPageToken(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	for _, token := range []string{"abc", "-5", "1e9"} {
		_, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
			Format:    "csv",
			PageToken: token,
		}))
		require.Error(t, err, "page token %q must be rejected", token)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	}
}

// TestExportAuditEvents_StreamTypesSliceCapped is the regression test
// for the local CR finding on the proto tag: `dive` scopes min/max to
// the ELEMENTS, so the slice itself needs its own max — otherwise an
// arbitrarily long stream_types list reaches the SQL filter.
func TestExportAuditEvents_StreamTypesSliceCapped(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	ctx := testutil.AdminContext(adminID)

	oversized := make([]string, 65)
	for i := range oversized {
		oversized[i] = "device"
	}
	_, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
		Format:      "csv",
		StreamTypes: oversized,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	// 64 entries is the documented ceiling and must pass validation.
	_, err = h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
		Format:      "csv",
		StreamTypes: oversized[:64],
	}))
	require.NoError(t, err)
}

// TestExportAuditEvents_EventTypeFilterEscapesLikeMetachars pins that
// the event_type substring filter keeps ListAuditEvents' ILIKE
// escaping: a literal "_" in the filter must not act as a wildcard.
func TestExportAuditEvents_EventTypeFilter(t *testing.T) {
	st := testutil.SetupPostgres(t)
	h := api.NewAuditHandler(st, slog.Default())

	adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
	testutil.CreateTestDevice(t, st, "evt-filter-host")
	ctx := testutil.AdminContext(adminID)

	resp, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
		Format:    "json",
		EventType: "UserCreated",
	}))
	require.NoError(t, err)
	var rows []map[string]any
	require.NoError(t, json.Unmarshal(resp.Msg.Chunk, &rows))
	require.NotEmpty(t, rows)
	for _, r := range rows {
		et, _ := r["event_type"].(string)
		assert.True(t, strings.Contains(et, "UserCreated"), "event_type filter must reach the query, got %q", et)
	}

	// LIKE-metachar regression: "User_" contains a literal underscore.
	// With correct ILIKE escaping it matches NO event type (none carries
	// "User_" literally); if the escaping regressed, "_" would act as a
	// single-char wildcard and match UserCreatedWithRoles.
	respMeta, err := h.ExportAuditEvents(ctx, connect.NewRequest(&pm.ExportAuditEventsRequest{
		Format:    "json",
		EventType: "User_",
	}))
	require.NoError(t, err)
	var metaRows []map[string]any
	require.NoError(t, json.Unmarshal(respMeta.Msg.Chunk, &metaRows))
	assert.Empty(t, metaRows, "a literal underscore must not act as a LIKE wildcard")
}
