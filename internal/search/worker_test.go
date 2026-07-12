package search

import (
	"context"
	"encoding/json"
	"errors"
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

	// The queue seam supplies the queue name the mux's VerifyMiddleware binds
	// against, which the real Asynq server would otherwise provide.
	ctx := taskqueue.WithQueue(context.Background(), taskqueue.SearchQueue)
	return &workerFixture{ctx: ctx, rdb: rdb, signer: signer, mux: mux}
}

func (f *workerFixture) signedTask(t *testing.T, taskType string, payload any) *asynq.Task {
	t.Helper()
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	wrapped, err := f.signer.Wrap(taskqueue.SearchQueue, taskType, data)
	require.NoError(t, err)
	return asynq.NewTask(taskType, wrapped, asynq.Queue(taskqueue.SearchQueue))
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

	// A raw (unsigned) payload has no version+HMAC prefix, so it is rejected —
	// its leading byte is not the envelope version — and dead-lettered.
	err = f.mux.ProcessTask(f.ctx, asynq.NewTask(taskqueue.TypeSearchReindex, data))
	require.Error(t, err)
	assert.True(t, errors.Is(err, asynq.SkipRetry),
		"an unsigned/raw task must be rejected and dead-lettered, not retry-loop; got %v", err)
}

// A task signed with a DIFFERENT key (forged, not merely absent) must be
// rejected with asynq.SkipRetry (so it dead-letters rather than retry-loops)
// and must NOT mutate the index — the F-02 HMAC is the sole authenticator for
// search:* tasks against a compromised Valkey relay (actor-4). Driven through
// the real mux for all three task types.
func TestWorker_ForgedKeyTaskRejectedAndNoHSET(t *testing.T) {
	const forgedKeyHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	forged, err := taskqueue.NewSigner(forgedKeyHex)
	require.NoError(t, err)

	cases := []struct {
		name     string
		taskType string
		payload  any
		hashKey  string
	}{
		{"reindex", taskqueue.TypeSearchReindex,
			taskqueue.SearchReindexPayload{Scope: ScopeAction, ID: "act-1", Data: &taskqueue.SearchEntityData{Name: "forged"}},
			prefixAction + "act-1"},
		{"member change", taskqueue.TypeSearchMemberChange,
			taskqueue.SearchMemberChangePayload{ParentScope: ScopeActionSet, ParentID: "set-1", ChildScope: ScopeAction, ChildID: "act-1", Action: "add"},
			prefixActionSet + "set-1"},
		{"remove", taskqueue.TypeSearchRemove,
			taskqueue.SearchRemovePayload{Scope: ScopeAction, ID: "act-1"},
			prefixAction + "act-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newWorkerFixture(t)
			data, err := json.Marshal(tc.payload)
			require.NoError(t, err)
			// Signed with the WRONG key (correct queue/type, so it reaches
			// verification and fails on the signature).
			wrapped, err := forged.Wrap(taskqueue.SearchQueue, tc.taskType, data)
			require.NoError(t, err)
			task := asynq.NewTask(tc.taskType, wrapped, asynq.Queue(taskqueue.SearchQueue))

			err = f.mux.ProcessTask(f.ctx, task)
			require.Error(t, err)
			assert.True(t, errors.Is(err, asynq.SkipRetry),
				"a forged-key task must dead-letter (SkipRetry), not retry-loop; got %v", err)

			exists, err := f.rdb.Exists(f.ctx, tc.hashKey).Result()
			require.NoError(t, err)
			assert.Equal(t, int64(0), exists, "a forged task must not create/mutate the %s hash", tc.hashKey)
		})
	}
}

func TestBuildSearchWorkerMux_NilSignerIsFatal(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })

	mux, err := BuildSearchWorkerMux(rdb, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.Error(t, err, "a nil signer (empty PM_TASK_SIGNING_KEY) must be fatal")
	assert.Nil(t, mux)
	assert.Contains(t, err.Error(), "PM_TASK_SIGNING_KEY")
}

// BuildSearchWorkerMux must mount VerifyMiddleware AHEAD of the handlers, so an
// unsigned or forged task is rejected before any HSET. Drive both through the
// assembled mux and assert SkipRetry + no index mutation.
func TestBuildSearchWorkerMux_VerifiesBeforeHandlers(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })

	signer, err := taskqueue.NewSigner(workerTestKeyHex)
	require.NoError(t, err)
	mux, err := BuildSearchWorkerMux(rdb, signer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	payload := taskqueue.SearchReindexPayload{Scope: ScopeAction, ID: "act-1", Data: &taskqueue.SearchEntityData{Name: "x"}}
	data, err := json.Marshal(payload)
	require.NoError(t, err)

	// Unsigned.
	err = mux.ProcessTask(context.Background(), asynq.NewTask(taskqueue.TypeSearchReindex, data, asynq.Queue(taskqueue.SearchQueue)))
	require.Error(t, err)
	assert.True(t, errors.Is(err, asynq.SkipRetry), "unsigned task rejected before the handler; got %v", err)

	exists, err := rdb.Exists(context.Background(), prefixAction+"act-1").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "verify-middleware must run before any HSET")
}
