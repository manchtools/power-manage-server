package taskqueue

// Integration test for VerifyMiddleware: a real Asynq server + miniredis proves
// that a task whose signed queue/type does NOT match the queue/type it is
// actually processed under never reaches the downstream handler — it is
// rejected by the middleware (SkipRetry) and archived instead (spec 29, AC2).

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/require"
)

func TestVerifyMiddleware_QueueOrTypeReplayNeverReachesHandler(t *testing.T) {
	mr := miniredis.RunT(t)
	signer, err := NewSigner(testKeyHex)
	require.NoError(t, err)
	redisOpt := asynq.RedisClientOpt{Addr: mr.Addr()}

	delivered := make(chan string, 8)
	mux := asynq.NewServeMux()
	mux.Use(signer.VerifyMiddleware())
	mux.HandleFunc(testType, func(ctx context.Context, task *asynq.Task) error {
		delivered <- string(task.Payload())
		return nil
	})

	aclient := asynq.NewClient(redisOpt)
	t.Cleanup(func() { _ = aclient.Close() })

	// 1. A valid task on its correct queue + type.
	validEnv, err := signer.Wrap("device:dev-1", testType, []byte("valid"))
	require.NoError(t, err)
	_, err = aclient.Enqueue(asynq.NewTask(testType, validEnv), asynq.Queue("device:dev-1"))
	require.NoError(t, err)

	// 2. Queue replay: signed for device:dev-1, but enqueued (unchanged bytes)
	//    onto the control-inbox queue.
	queueReplay, err := signer.Wrap("device:dev-1", testType, []byte("queue-replay"))
	require.NoError(t, err)
	_, err = aclient.Enqueue(asynq.NewTask(testType, queueReplay), asynq.Queue(ControlInboxQueue))
	require.NoError(t, err)

	// 3. Type replay: signed for a different task type, but delivered as testType
	//    (so it routes to the handler) on the correct queue.
	typeReplay, err := signer.Wrap("device:dev-1", "some:other-type", []byte("type-replay"))
	require.NoError(t, err)
	_, err = aclient.Enqueue(asynq.NewTask(testType, typeReplay), asynq.Queue("device:dev-1"))
	require.NoError(t, err)

	srv := asynq.NewServer(redisOpt, asynq.Config{
		Concurrency: 2,
		Queues:      map[string]int{"device:dev-1": 1, ControlInboxQueue: 1},
		LogLevel:    asynq.FatalLevel, // keep the test output quiet
	})
	require.NoError(t, srv.Start(mux))
	t.Cleanup(srv.Shutdown)

	// The valid task must be delivered; the two replays must not. Wait for the
	// valid delivery, then give the replays ample time to be (wrongly) delivered
	// if the binding were broken.
	select {
	case got := <-delivered:
		require.Equal(t, "valid", got, "only the correctly-bound task may reach the handler")
	case <-time.After(10 * time.Second):
		t.Fatal("valid task was never delivered — server/handler wiring is broken")
	}

	select {
	case got := <-delivered:
		t.Fatalf("a replayed task reached the handler: %q — the queue/type binding is not enforced", got)
	case <-time.After(1500 * time.Millisecond):
		// No further delivery — the replays were rejected by the middleware.
	}
}
