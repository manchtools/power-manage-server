package inventorysched_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/inventorysched"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// Spec 22 AC 5/6 — scheduler behavior against real Postgres: one signed
// request per stale connected device per tick, none for fresh /
// disconnected devices, single-flight across replicas, overdue/grace
// policy units.

// noopSigner satisfies ca.ActionSigner without a real CA.
type noopSigner struct{}

func (noopSigner) Sign([]byte) ([]byte, error) { return []byte("noop-sig"), nil }
func (noopSigner) SignDomain(domain string, _ []byte) ([]byte, error) {
	return []byte("noop-sig:" + domain), nil
}

// captureEnqueuer records EnqueueToDevice calls.
type captureEnqueuer struct {
	mu    sync.Mutex
	calls []capturedEnqueue
	err   error
}

type capturedEnqueue struct {
	deviceID string
	taskType string
	payload  taskqueue.InventoryRequestPayload
	opts     int
}

func (c *captureEnqueuer) EnqueueToDevice(deviceID, taskType string, payload any, opts ...asynq.Option) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	// Round-trip through JSON the way the real client marshals payloads.
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var p taskqueue.InventoryRequestPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	c.calls = append(c.calls, capturedEnqueue{deviceID: deviceID, taskType: taskType, payload: p, opts: len(opts)})
	return nil
}

func (c *captureEnqueuer) byDevice() map[string][]capturedEnqueue {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := make(map[string][]capturedEnqueue)
	for _, call := range c.calls {
		m[call.deviceID] = append(m[call.deviceID], call)
	}
	return m
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func markSeen(t *testing.T, st *store.Store, deviceID string, at time.Time) {
	t.Helper()
	_, err := st.TestingPool().Exec(context.Background(),
		"UPDATE devices_projection SET last_seen_at = $2 WHERE id = $1", deviceID, at)
	require.NoError(t, err)
}

func insertInventory(t *testing.T, st *store.Store, deviceID string, collectedAt time.Time) {
	t.Helper()
	_, err := st.TestingPool().Exec(context.Background(),
		`INSERT INTO device_inventory (device_id, table_name, rows, collected_at)
		 VALUES ($1, 'system_info', '[]'::jsonb, $2)
		 ON CONFLICT (device_id, table_name) DO UPDATE SET collected_at = EXCLUDED.collected_at`,
		deviceID, collectedAt)
	require.NoError(t, err)
}

func TestRunOnce_StaleConnectedDeviceGetsOneSignedRequest(t *testing.T) {
	st := testutil.SetupPostgres(t)
	now := time.Now()

	stale := testutil.CreateTestDevice(t, st, "sched-stale")
	markSeen(t, st, stale, now) // connected, never collected → stale (AC 6)

	fresh := testutil.CreateTestDevice(t, st, "sched-fresh")
	markSeen(t, st, fresh, now)
	insertInventory(t, st, fresh, now.Add(-time.Hour))

	gone := testutil.CreateTestDevice(t, st, "sched-gone")
	markSeen(t, st, gone, now.Add(-2*time.Hour)) // disconnected → skipped

	aq := &captureEnqueuer{}
	w := inventorysched.New(st, aq, noopSigner{}, discardLogger())
	w.SetNowForTest(func() time.Time { return now })

	res, err := w.RunOnce(context.Background())
	require.NoError(t, err)
	assert.True(t, res.Ran)

	byDev := aq.byDevice()
	require.Len(t, byDev[stale], 1, "stale device gets exactly one request per tick")
	assert.Empty(t, byDev[fresh], "fresh device gets none")
	assert.Empty(t, byDev[gone], "disconnected device gets none")

	call := byDev[stale][0]
	assert.Equal(t, taskqueue.TypeInventoryRequest, call.taskType)
	assert.NotEmpty(t, call.payload.QueryID, "request must carry a bindable query_id")
	assert.NotEmpty(t, call.payload.Signature, "request must be CA-signed (WS4)")
	assert.Equal(t, 2, call.opts, "MaxRetry + sub-tick Deadline")
}

func TestRunOnce_SingleFlightAcrossReplicas(t *testing.T) {
	st := testutil.SetupPostgres(t)
	now := time.Now()
	d := testutil.CreateTestDevice(t, st, "sched-sf")
	markSeen(t, st, d, now)

	// Simulate "another replica" holding the lock on a SEPARATE session —
	// a raw pool connection, not TryWithAdvisoryLock (same pattern as
	// retention's TestPrune_SingleFlight).
	const key int64 = 0x696e767363686564 // == advisoryKeyInventorySchedule
	holder, err := st.TestingPool().Acquire(context.Background())
	require.NoError(t, err)
	defer holder.Release()
	var got bool
	require.NoError(t, holder.QueryRow(context.Background(),
		"SELECT pg_try_advisory_lock($1)", key).Scan(&got))
	require.True(t, got, "holder session must acquire the schedule lock")

	aq := &captureEnqueuer{}
	w := inventorysched.New(st, aq, noopSigner{}, discardLogger())
	w.SetNowForTest(func() time.Time { return now })

	res, err := w.RunOnce(context.Background())
	require.NoError(t, err)
	assert.False(t, res.Ran, "a concurrent tick must skip without error (single-flight)")
	assert.Empty(t, aq.byDevice(), "the skipping replica must not enqueue")
}

func TestRunOnce_EnqueueFailureAbortsCycle(t *testing.T) {
	st := testutil.SetupPostgres(t)
	now := time.Now()
	d := testutil.CreateTestDevice(t, st, "sched-err")
	markSeen(t, st, d, now)

	aq := &captureEnqueuer{err: errors.New("valkey down")}
	w := inventorysched.New(st, aq, noopSigner{}, discardLogger())
	w.SetNowForTest(func() time.Time { return now })

	_, err := w.RunOnce(context.Background())
	require.Error(t, err, "an enqueue failure must surface, not be swallowed")
}

func TestRunOnce_NilSignerFailsClosed(t *testing.T) {
	st := testutil.SetupPostgres(t)
	now := time.Now()
	d := testutil.CreateTestDevice(t, st, "sched-nosign")
	markSeen(t, st, d, now)

	aq := &captureEnqueuer{}
	w := inventorysched.New(st, aq, nil, discardLogger())
	w.SetNowForTest(func() time.Time { return now })

	_, err := w.RunOnce(context.Background())
	require.Error(t, err, "a nil signer must refuse to dispatch (fail closed)")
	assert.Empty(t, aq.byDevice(), "nothing may be enqueued unsigned")
}

// --- policy units (spec 22 AC 7) ---

func TestGrace(t *testing.T) {
	assert.Equal(t, time.Hour, inventorysched.Grace(2*time.Hour), "floor: max(1h, 25%)")
	assert.Equal(t, 6*time.Hour, inventorysched.Grace(24*time.Hour), "25% of a day")
}

func TestOverdue(t *testing.T) {
	now := time.Now()
	ts := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }

	// 1440-minute interval + 6h grace = 30h threshold.
	assert.False(t, inventorysched.Overdue(ts(29*time.Hour), nil, 1440, now), "just below interval+grace")
	assert.True(t, inventorysched.Overdue(ts(31*time.Hour), nil, 1440, now), "just above interval+grace")

	// Never collected: ages from registered_at.
	assert.False(t, inventorysched.Overdue(nil, ts(time.Hour), 1440, now), "fresh enrollment gets a full window")
	assert.True(t, inventorysched.Overdue(nil, ts(31*time.Hour), 1440, now), "old never-collected device is overdue")

	// Missing both timestamps fails closed.
	assert.True(t, inventorysched.Overdue(nil, nil, 1440, now))
}
