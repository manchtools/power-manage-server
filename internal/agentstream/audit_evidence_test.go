package agentstream

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testdb"
)

// CHARTER — agent-originated audit evidence.
//
// Both writers on this file's path record an operation and a single effect
// through the real store. They are the only durable trace of a device that
// reported tampering or that flooded the single-writer control plane, so a
// test that stops at "the function returned" proves nothing: the assertions
// below read the committed rows back.

// auditFixture opens one real SQLite file and a raw handle onto the same
// database, so a test can read the rows the audited write actually committed.
func auditFixture(t *testing.T) (*store.Store, *testdb.DB) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "power-manage.db")
	st, err := store.New(ctx, path)
	require.NoError(t, err, "initialize SQLite")
	t.Cleanup(st.Close)
	raw, err := testdb.Open(ctx, path)
	require.NoError(t, err, "open raw SQLite handle")
	t.Cleanup(raw.Close)
	return st, raw
}

// auditHandler is the smallest Handler that can reach the audit writers: the
// real store plus a discarding logger. The frame-drop budget is left nil so
// every call records rather than being throttled by the test's own repetition.
func auditHandler(st *store.Store) *Handler {
	return &Handler{store: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// countRows returns the number of rows the query matches.
func countRows(t *testing.T, raw *testdb.DB, query string, args ...any) int {
	t.Helper()
	var count int
	require.NoError(t, raw.QueryRow(context.Background(), query, args...).Scan(&count))
	return count
}

func TestRecordSecurityAlertCommitsOperationAndEffect(t *testing.T) {
	st, raw := auditFixture(t)
	handler := auditHandler(st)
	deviceID := ulid.Make().String()

	// The longest alert name in the enum: 47 characters, which is what makes
	// the discriminator's column choice load-bearing.
	alert := &pmv1.SecurityAlert{
		Type:    pmv1.SecurityAlertType_SECURITY_ALERT_TYPE_SERVER_REASSIGNMENT_ATTEMPT,
		Message: "control endpoint was rewritten under the agent",
	}
	require.NoError(t, handler.recordSecurityAlert(context.Background(), deviceID, alert))

	const descriptor = "powermanage.v1.AgentService.Stream/SecurityAlert"
	assert.Equal(t, 1, countRows(t, raw,
		`SELECT COUNT(*) FROM audit_operations WHERE request_descriptor = $1 AND actor_id = $2`,
		descriptor, deviceID), "the alert must leave exactly one operation row")
	assert.Equal(t, 1, countRows(t, raw, `
		SELECT COUNT(*) FROM audit_effects e
		JOIN audit_operations o ON o.operation_id = e.operation_id
		WHERE o.request_descriptor = $1 AND e.resource_id = $2
		  AND e.resource_type = 'device' AND e.action = 'SECURITY_ALERT'`,
		descriptor, deviceID), "the alert must leave exactly one effect row")

	// The alert TYPE is the whole point of the record; losing it would leave
	// an indistinguishable "something happened" row.
	var resultCode string
	require.NoError(t, raw.QueryRow(context.Background(),
		`SELECT result_code FROM audit_operations WHERE request_descriptor = $1 AND actor_id = $2`,
		descriptor, deviceID).Scan(&resultCode))
	assert.Equal(t, alert.Type.String(), resultCode,
		"the alert type must survive in a column the schema accepts")

	// after_ref names another ROW. A discriminator there is rejected by the
	// schema, which is what silently rolled the whole operation back.
	assert.Equal(t, 0, countRows(t, raw, `
		SELECT COUNT(*) FROM audit_effects e
		JOIN audit_operations o ON o.operation_id = e.operation_id
		WHERE o.request_descriptor = $1 AND e.after_ref IS NOT NULL`, descriptor),
		"a reference column must not carry a discriminator")
}

func TestRecordFrameDropCommitsOperationAndEffect(t *testing.T) {
	st, raw := auditFixture(t)
	handler := auditHandler(st)
	deviceID := ulid.Make().String()

	message := &pmv1.AgentMessage{
		Id: ulid.Make().String(), Payload: &pmv1.AgentMessage_Heartbeat{Heartbeat: &pmv1.Heartbeat{}},
	}
	handler.recordFrameDrop(context.Background(), deviceID, message)

	const descriptor = "powermanage.v1.AgentService.Stream/FrameRateLimit/telemetry"
	assert.Equal(t, 1, countRows(t, raw,
		`SELECT COUNT(*) FROM audit_operations WHERE request_descriptor = $1 AND actor_id = $2`,
		descriptor, deviceID), "a throttled frame must leave exactly one operation row")
	assert.Equal(t, 1, countRows(t, raw, `
		SELECT COUNT(*) FROM audit_effects e
		JOIN audit_operations o ON o.operation_id = e.operation_id
		WHERE o.request_descriptor = $1 AND e.resource_id = $2
		  AND e.resource_type = 'device' AND e.action = 'FRAME_RATE_LIMIT'
		  AND e.outcome = 'REJECTED'`,
		descriptor, deviceID), "a throttled frame must leave exactly one effect row")

	var resultCode, outcome string
	require.NoError(t, raw.QueryRow(context.Background(),
		`SELECT result_code, authorization_outcome FROM audit_operations
		 WHERE request_descriptor = $1 AND actor_id = $2`,
		descriptor, deviceID).Scan(&resultCode, &outcome))
	assert.Equal(t, "RATE_LIMITED.telemetry", resultCode,
		"the dropped frame's class must survive in a column the schema accepts")
	assert.Equal(t, string(store.AuthorizationDenied), outcome)

	assert.Equal(t, 0, countRows(t, raw, `
		SELECT COUNT(*) FROM audit_effects e
		JOIN audit_operations o ON o.operation_id = e.operation_id
		WHERE o.request_descriptor = $1 AND e.after_ref IS NOT NULL`, descriptor),
		"a reference column must not carry a discriminator")
}

// The guard that keeps the next call site from repeating either defect:
// before_ref and after_ref name other rows, and the store refuses anything
// else BEFORE it opens a transaction, so the failure is loud instead of a
// silent rollback that takes the whole operation with it.
func TestAuditEffectReferenceColumnsRejectNonULIDsBeforeAnyWrite(t *testing.T) {
	st, raw := auditFixture(t)
	deviceID := ulid.Make().String()
	discriminator := "SECURITY_ALERT_TYPE_SERVER_REASSIGNMENT_ATTEMPT"

	for name, effect := range map[string]store.AuditEffect{
		"after_ref": {
			ResourceType: "device", ResourceID: deviceID, Action: "SECURITY_ALERT",
			Outcome: store.EffectApplied, AfterRef: &discriminator,
		},
		"before_ref": {
			ResourceType: "device", ResourceID: deviceID, Action: "SECURITY_ALERT",
			Outcome: store.EffectApplied, BeforeRef: &discriminator,
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := countRows(t, raw, `SELECT COUNT(*) FROM audit_operations`)
			_, err := st.RecordOperation(context.Background(),
				agentOperation(deviceID, "SecurityAlert"), effect)
			require.ErrorIs(t, err, store.ErrAuditEffectInvalid)
			assert.Equal(t, before, countRows(t, raw, `SELECT COUNT(*) FROM audit_operations`),
				"a refused effect must perform no database work at all")
		})
	}
}
