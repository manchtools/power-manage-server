package search

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

const workerTestKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type workerFixture struct {
	ctx    context.Context
	rdb    *redis.Client
	signer *taskqueue.Signer
	mux    *asynq.ServeMux
}

func newWorkerFixture(t *testing.T) *workerFixture {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })

	signer, err := taskqueue.NewSigner(workerTestKeyHex)
	require.NoError(t, err)
	worker := NewWorker(rdb, signer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := asynq.NewServeMux()
	worker.RegisterHandlers(mux)

	return &workerFixture{ctx: context.Background(), rdb: rdb, signer: signer, mux: mux}
}

func (f *workerFixture) signedTask(t *testing.T, taskType string, payload any) *asynq.Task {
	t.Helper()
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	return asynq.NewTask(taskType, f.signer.Wrap(data), asynq.Queue(taskqueue.SearchQueue))
}

func TestWorker_ReindexRequiresSignedTaskAndWritesHash(t *testing.T) {
	f := newWorkerFixture(t)

	payload := taskqueue.SearchReindexPayload{
		Scope: ScopeAction,
		ID:    "act-1",
		Data: &taskqueue.SearchEntityData{
			Name:        "Install Nginx",
			Description: "package install",
			Type:        100,
		},
	}
	require.NoError(t, f.mux.ProcessTask(f.ctx, f.signedTask(t, taskqueue.TypeSearchReindex, payload)))

	fields, err := f.rdb.HGetAll(f.ctx, prefixAction+"act-1").Result()
	require.NoError(t, err)
	assert.Equal(t, "Install Nginx", fields["name"])
	assert.Equal(t, "package install", fields["description"])
	assert.Equal(t, "100", fields["type"])
}

func TestWorker_MemberChangeUpdatesMembershipAndRebuildsParent(t *testing.T) {
	f := newWorkerFixture(t)
	require.NoError(t, f.rdb.HSet(f.ctx, prefixAction+"act-1", map[string]any{"name": "Install Nginx"}).Err())

	payload := taskqueue.SearchMemberChangePayload{
		ParentScope: ScopeActionSet,
		ParentID:    "set-1",
		ChildScope:  ScopeAction,
		ChildID:     "act-1",
		Action:      "add",
	}
	require.NoError(t, f.mux.ProcessTask(f.ctx, f.signedTask(t, taskqueue.TypeSearchMemberChange, payload)))

	isMember, err := f.rdb.SIsMember(f.ctx, prefixMembersActionSet+"set-1", "act-1").Result()
	require.NoError(t, err)
	assert.True(t, isMember)
	parents, err := f.rdb.SMembers(f.ctx, prefixReverseAction+"act-1").Result()
	require.NoError(t, err)
	assert.Equal(t, []string{"set-1"}, parents)
	fields, err := f.rdb.HGetAll(f.ctx, prefixActionSet+"set-1").Result()
	require.NoError(t, err)
	assert.Equal(t, "Install Nginx", fields["action_names"])
	assert.Equal(t, "1", fields["member_count"])
}

func TestWorker_RemoveDeletesEntityKeys(t *testing.T) {
	f := newWorkerFixture(t)
	require.NoError(t, f.rdb.HSet(f.ctx, prefixAction+"act-1", map[string]any{"name": "Install Nginx"}).Err())
	require.NoError(t, f.rdb.SAdd(f.ctx, prefixReverseAction+"act-1", "set-1").Err())

	payload := taskqueue.SearchRemovePayload{Scope: ScopeAction, ID: "act-1"}
	require.NoError(t, f.mux.ProcessTask(f.ctx, f.signedTask(t, taskqueue.TypeSearchRemove, payload)))

	exists, err := f.rdb.Exists(f.ctx, prefixAction+"act-1", prefixReverseAction+"act-1").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists)
}

func TestWorker_UnsignedTaskIsRejected(t *testing.T) {
	f := newWorkerFixture(t)
	payload := taskqueue.SearchReindexPayload{Scope: ScopeAction, ID: "act-1", Data: &taskqueue.SearchEntityData{Name: "x"}}
	data, err := json.Marshal(payload)
	require.NoError(t, err)

	err = f.mux.ProcessTask(f.ctx, asynq.NewTask(taskqueue.TypeSearchReindex, data))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "task signature")
}
