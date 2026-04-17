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

// taskQueueHolder is a mixin for handlers that enqueue Asynq tasks. Same
// promotion trick — h.aqClient remains accessible in handler methods.
type taskQueueHolder struct {
	aqClient *taskqueue.Client
}

func (h *taskQueueHolder) SetTaskQueueClient(c *taskqueue.Client) {
	h.aqClient = c
}
