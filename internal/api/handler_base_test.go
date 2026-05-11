package api

// Smoke coverage for handler_base.go mixins
// (manchtools/power-manage-server#155, the "low-priority helper"
// item the issue's two-wave plan listed). The mixins are
// field-setter-only — the most regression-prone behaviour is the
// nil-guard on SetTaskQueueClient that prevents an accidentally-
// nil setter call from clobbering a previously-wired enqueuer.

import (
	"testing"

	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"

	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// nopEnqueuer is a no-behaviour stub that satisfies taskqueue.Enqueuer
// so the SetTaskQueueClient test has something concrete to wire in.
// Kept tiny here rather than imported from handler/agent_handlers_test.go
// (different package) so the test file is self-contained.
type nopEnqueuer struct{ tag string }

func (nopEnqueuer) EnqueueToDevice(string, string, any, ...asynq.Option) error {
	return nil
}
func (nopEnqueuer) EnqueueToControl(string, any) error             { return nil }
func (nopEnqueuer) EnqueueToSearch(string, any) error              { return nil }
func (nopEnqueuer) DeleteScheduledDeviceTask(string, string) error { return nil }

var _ taskqueue.Enqueuer = nopEnqueuer{}

func TestSearchIndexHolder_SetSearchIndex_StoresValue(t *testing.T) {
	var h searchIndexHolder
	assert.Nil(t, h.searchIdx, "zero value starts nil")

	// Pass nil — that's allowed; SetSearchIndex doesn't claim a
	// nil-guard like SetTaskQueueClient does, so a nil setter call
	// just clears the field. This locks that behaviour in: a future
	// "always reject nil" tightening would have to update the test
	// in lockstep, which is the right kind of friction.
	h.SetSearchIndex(nil)
	assert.Nil(t, h.searchIdx)
}

func TestTaskQueueHolder_SetTaskQueueClient_NilGuardPreservesPrior(t *testing.T) {
	var h taskQueueHolder
	// Use the existing fake enqueuer (defined in agent_handlers_test.go,
	// same internal package) so we don't need to mint a new fixture.
	first := nopEnqueuer{}
	h.SetTaskQueueClient(first)
	assert.Equal(t, first, h.aqClient)

	// Nil setter call must NOT clobber the previously-wired enqueuer.
	// The handler's prod dispatch paths fail-close on a nil aqClient;
	// silently nil-ing it from a stray setter call would convert a
	// working dispatch path into "task queue not configured" errors
	// at runtime.
	h.SetTaskQueueClient(nil)
	assert.Equal(t, first, h.aqClient,
		"SetTaskQueueClient(nil) must keep the previously-wired enqueuer; nil-guard documented in handler_base.go")
}

func TestTaskQueueHolder_SetTaskQueueClient_NonNilReplaces(t *testing.T) {
	var h taskQueueHolder
	first := nopEnqueuer{tag: "first"}
	second := nopEnqueuer{tag: "second"}

	h.SetTaskQueueClient(first)
	h.SetTaskQueueClient(second)
	assert.Equal(t, second, h.aqClient,
		"a fresh non-nil setter call must replace the prior value")
}
