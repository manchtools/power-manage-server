package main

// Smoke coverage for the periodic-worker helpers extracted from main.go
// (audit F043 / #157). These tests don't stand up a real Store —
// they exercise the loop shapes (drainDynamicQueue's terminate-on-more=false,
// runPeriodic's runImmediately + ctx-cancel paths) against fakes,
// which is the part that's actually regression-prone.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/inventorysched"
)

// discardLogger silences periodic-worker log output during tests so a
// failed assertion isn't drowned in expected Info/Error lines.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// =============================================================================
// drainDynamicQueue
// =============================================================================

func TestDrainDynamicQueue_StopsWhenMoreFalse(t *testing.T) {
	// The drain loop's terminate condition is the explicit `more` flag
	// returned from the SQL function. Closes audit F035 / #168 — verify
	// that drain stops the moment more=false, regardless of the count
	// the last batch reported.
	calls := []dynamicQueueBatch{
		{count: 100, more: true},
		{count: 100, more: true},
		{count: 50, more: false}, // partial batch but more=false → must stop
	}
	var idx atomic.Int32
	evalFn := func(_ context.Context) (dynamicQueueBatch, error) {
		i := idx.Add(1) - 1
		require.Less(t, int(i), len(calls), "drain called more times than expected")
		return calls[i], nil
	}

	drainDynamicQueue(context.Background(), "test", discardLogger(), evalFn)
	assert.Equal(t, int32(3), idx.Load(), "drain must run exactly 3 batches before more=false")
}

func TestDrainDynamicQueue_StopsOnError(t *testing.T) {
	// An error must terminate the drain — busy-looping on a wedged DB
	// would amplify backend pressure during an outage. Verify the loop
	// exits after exactly one error.
	var idx atomic.Int32
	evalFn := func(_ context.Context) (dynamicQueueBatch, error) {
		idx.Add(1)
		return dynamicQueueBatch{}, errors.New("DB exploded")
	}

	drainDynamicQueue(context.Background(), "test", discardLogger(), evalFn)
	assert.Equal(t, int32(1), idx.Load(), "drain must terminate after first error, not retry")
}

func TestDrainDynamicQueue_NoOpOnImmediateMoreFalse(t *testing.T) {
	// Empty queue (count=0, more=false) — drain runs once and returns.
	// Verifies we don't busy-loop on an idle queue.
	var idx atomic.Int32
	evalFn := func(_ context.Context) (dynamicQueueBatch, error) {
		idx.Add(1)
		return dynamicQueueBatch{count: 0, more: false}, nil
	}

	drainDynamicQueue(context.Background(), "test", discardLogger(), evalFn)
	assert.Equal(t, int32(1), idx.Load(), "drain must call evalFn exactly once on an empty queue")
}

// =============================================================================
// runPeriodic
// =============================================================================

func TestRunPeriodic_RunImmediatelyFiresBeforeFirstTick(t *testing.T) {
	// runImmediately=true must invoke fn once before the ticker even
	// starts. Used by the dynamic-group safety-net loop and the
	// startup sweep callers — a missed startup invocation would mean
	// the safety net only kicks in after the first 24h tick.
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runPeriodic(ctx, 1*time.Hour, func() { calls.Add(1) }, true)
		close(done)
	}()

	// Give the goroutine time to fire the immediate call but not enough
	// to reach the 1h tick. 50ms is generous on every CI box we run on
	// and tight enough that nobody will yell about test latency.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	assert.Equal(t, int32(1), calls.Load(), "runImmediately=true must fire fn exactly once before ctx cancel")
}

func TestRunPeriodic_RunImmediatelyFalseSkipsFirstCall(t *testing.T) {
	// runImmediately=false → fn must not fire until the first tick.
	// The token-revocation cleanup uses this shape; firing it on boot
	// would burn cycles on a freshly-restarted server with nothing to
	// clean up.
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runPeriodic(ctx, 1*time.Hour, func() { calls.Add(1) }, false)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	assert.Equal(t, int32(0), calls.Load(), "runImmediately=false must not fire fn before first tick")
}

func TestRunPeriodic_StopsOnContextCancel(t *testing.T) {
	// Verifies the ctx.Done() path actually returns. Without this the
	// goroutine would leak across the server's lifetime — the periodic
	// helpers are spawned from main() with no shutdown wait, so a
	// blocked goroutine would survive shutdown indefinitely.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runPeriodic(ctx, 1*time.Hour, func() {}, false)
		close(done)
	}()

	cancel()
	select {
	case <-done:
		// happy path
	case <-time.After(1 * time.Second):
		t.Fatal("runPeriodic did not return within 1s of ctx cancel")
	}
}

// =============================================================================
// inventoryScheduleTick (spec 22)
// =============================================================================

// panickyRunner panics on the first RunOnce and succeeds afterwards.
type panickyRunner struct{ calls atomic.Int32 }

func (p *panickyRunner) RunOnce(context.Context) (inventorysched.RunResult, error) {
	if p.calls.Add(1) == 1 {
		panic("boom")
	}
	return inventorysched.RunResult{Ran: true}, nil
}

// TestInventoryScheduleTick_PanicRecovered — a panic in one cycle must
// not kill the worker: the tick body recovers and the next invocation
// still runs (spec 22 test requirement).
func TestInventoryScheduleTick_PanicRecovered(t *testing.T) {
	r := &panickyRunner{}
	tick := inventoryScheduleTick(context.Background(), r, discardLogger())

	assert.NotPanics(t, func() { tick() }, "first cycle panics internally but must be recovered")
	assert.NotPanics(t, func() { tick() })
	assert.Equal(t, int32(2), r.calls.Load(), "the cycle after a panic must still run")
}

// erroringRunner always fails.
type erroringRunner struct{ calls atomic.Int32 }

func (e *erroringRunner) RunOnce(context.Context) (inventorysched.RunResult, error) {
	e.calls.Add(1)
	return inventorysched.RunResult{}, errors.New("db down")
}

// TestInventoryScheduleTick_ErrorLoggedNotFatal — RunOnce errors are
// logged and swallowed; the loop keeps ticking.
func TestInventoryScheduleTick_ErrorLoggedNotFatal(t *testing.T) {
	r := &erroringRunner{}
	tick := inventoryScheduleTick(context.Background(), r, discardLogger())
	assert.NotPanics(t, func() { tick(); tick() })
	assert.Equal(t, int32(2), r.calls.Load())
}

// TestInventorySchedulerEnvGate — CONTROL_INVENTORY_SCHEDULER_ENABLED
// defaults to true and false disables (spec 22 AC 10). The main() branch
// on this flag is a one-liner; the gate itself is what regresses.
func TestInventorySchedulerEnvGate(t *testing.T) {
	cfg := &Config{InventorySchedulerEnabled: true} // flag default
	t.Setenv("CONTROL_INVENTORY_SCHEDULER_ENABLED", "")
	applyEnvOverrides(cfg)
	assert.True(t, cfg.InventorySchedulerEnabled, "unset env keeps the default (enabled)")

	t.Setenv("CONTROL_INVENTORY_SCHEDULER_ENABLED", "false")
	applyEnvOverrides(cfg)
	assert.False(t, cfg.InventorySchedulerEnabled, "false disables the scheduler")

	t.Setenv("CONTROL_INVENTORY_SCHEDULER_ENABLED", "true")
	applyEnvOverrides(cfg)
	assert.True(t, cfg.InventorySchedulerEnabled)
}
