package handler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// The handler owns the stream only until it returns, and a frame can still be
// on its way out when it does.
//
// Revocation cancels the agent's context (DeviceStreamRevocationListener →
// Manager.Unregister → Agent.Close), and the dispatch loop's select fires on
// <-agent.Done() and returns. Nothing in that path synchronises with the send
// lock, so a per-device dispatch worker or a terminal bridge can be inside
// Agent.Send at that moment — holding the lock at the write, and at the
// deferred deadline clear that drives http.ResponseController on the very
// ResponseWriter net/http forbids touching once ServeHTTP has returned.
// connect.BidiStream.Send has no locking of its own to save us either.
//
// The window is as long as a write can take: up to SendTimeout. It is new on
// this branch — the loop used to block in stream.Receive(), which ignored the
// agent's cancellation entirely, so the handler did not return here at all.
func TestStream_DoesNotReturnWhileASendIsInFlight(t *testing.T) {
	const deviceID = "dev-inflight"
	f := newStreamFixture(t, false)

	stream := f.client.Stream(context.Background())
	require.NoError(t, stream.Send(&pm.AgentMessage{
		Payload: &pm.AgentMessage_Hello{Hello: &pm.Hello{
			DeviceId: &pm.DeviceId{Value: deviceID}, Hostname: "h", AgentVersion: "v",
		}},
	}))
	// Welcome proves the handler registered the connection and reached its loop.
	_, err := stream.Receive()
	require.NoError(t, err, "handler must accept the connection before we wedge a send in it")

	agent, ok := f.manager.Get(deviceID)
	require.True(t, ok, "the handler must have registered the connection")

	// A write that is in flight and stays there until this test releases it.
	// Arming the transport deadline is the first thing Send does under the send
	// lock, so blocking there reproduces the window exactly: the lock is held,
	// the frame has not left, and the deferred deadline clear has not run.
	sendEntered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSend := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseSend)

	var enteredOnce sync.Once
	agent.SetWriteDeadlineFunc(func(d time.Time) error {
		if d.IsZero() { // the post-write clear, not the arming call
			return nil
		}
		enteredOnce.Do(func() { close(sendEntered) })
		<-release
		return nil
	})

	sendDone := make(chan error, 1)
	go func() { sendDone <- f.manager.Send(deviceID, &pm.ServerMessage{}) }()
	<-sendEntered

	// The client observes the handler's return as the end of the RPC.
	handlerReturned := make(chan struct{})
	go func() {
		defer close(handlerReturned)
		for {
			if _, rerr := stream.Receive(); rerr != nil {
				return
			}
		}
	}()

	// The revocation path, exactly as DeviceStreamRevocationListener drives it.
	f.manager.Unregister(deviceID)

	select {
	case <-handlerReturned:
		t.Fatal("the stream handler returned with a Send still in flight — connect finalises the " +
			"response underneath the write, and net/http forbids touching the ResponseWriter " +
			"after ServeHTTP returns")
	case <-time.After(500 * time.Millisecond):
	}

	releaseSend()
	<-sendDone // the frame leaves while the handler is still holding the stream

	select {
	case <-handlerReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never returned after the send drained — waiting for the send lock " +
			"must not outlive the send itself")
	}
}
