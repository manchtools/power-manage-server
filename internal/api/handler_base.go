package api

import (
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// searchIndexHolder is a mixin for handlers that enqueue search reindex
// tasks. Embedding it promotes SetSearchIndex and the searchIdx field so
// handler code can still reference h.searchIdx directly.
type searchIndexHolder struct {
	searchIdx *search.Index
}

func (h *searchIndexHolder) SetSearchIndex(idx *search.Index) {
	h.searchIdx = idx
}

// taskQueueHolder is a mixin for handlers that enqueue Asynq tasks.
// Same promotion trick — h.aqClient remains accessible in handler
// methods. The field is an interface (taskqueue.Enqueuer) so tests
// can inject a no-op / recording double without a real Valkey, and
// production dispatch paths can refuse requests when the enqueuer
// is nil instead of silently swallowing them.
type taskQueueHolder struct {
	aqClient taskqueue.Enqueuer
}

// SetTaskQueueClient accepts the interface so production (wiring
// *taskqueue.Client from main.go) and tests (wiring
// api.NoOpEnqueuer{}) share one setter. A nil argument keeps the
// holder's current value — callers that want to explicitly clear
// the enqueuer should reconstruct the handler.
func (h *taskQueueHolder) SetTaskQueueClient(c taskqueue.Enqueuer) {
	if c == nil {
		return
	}
	h.aqClient = c
}
