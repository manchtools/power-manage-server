package connection

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

func newTestSession(id string) *TerminalSession {
	return NewTerminalSession(id, "dev-1", "user-1", "pm-tty-alice", 80, 24)
}

func outputMsg() *pm.AgentMessage {
	return &pm.AgentMessage{
		Payload: &pm.AgentMessage_TerminalOutput{
			TerminalOutput: &pm.TerminalOutput{SessionId: "s1", Data: []byte("x")},
		},
	}
}

// TestTerminalSessionRegistry_ConcurrentRouteAndUnregister pins the
// lock-discipline contract (finding 12): RouteAgentMessage holds the RLock
// through the channel send and Unregister takes the write lock before close(),
// so a concurrent route/unregister can never panic with send-on-closed-channel.
// Run under -race; the goroutine hammer + the absence of a panic is the proof.
func TestTerminalSessionRegistry_ConcurrentRouteAndUnregister(t *testing.T) {
	for iter := 0; iter < 200; iter++ {
		r := NewTerminalSessionRegistry()
		s := newTestSession("s1")
		r.Register(s)

		// Drain the buffered channel so RouteAgentMessage actually attempts
		// sends rather than only hitting the full-channel default branch.
		drainDone := make(chan struct{})
		go func() {
			for range s.OutputCh {
			}
			close(drainDone)
		}()

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					r.RouteAgentMessage("s1", outputMsg())
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Unregister("s1")
		}()
		wg.Wait()

		// Unregister closes OutputCh, so the drainer terminates.
		r.Unregister("s1") // idempotent second close-attempt guard
		<-drainDone
	}
}

// TestTerminalSessionRegistry_ReregisterSameIDClosesOldChannel pins the
// line 89-91 path: re-Registering the SAME id closes the old channel while a
// reader on the NEW channel still receives, with no send-on-closed panic.
func TestTerminalSessionRegistry_ReregisterSameIDClosesOldChannel(t *testing.T) {
	r := NewTerminalSessionRegistry()
	old := newTestSession("s1")
	r.Register(old)

	// Concurrent routing on s1 while it is being re-registered.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			r.RouteAgentMessage("s1", outputMsg())
		}
	}()

	fresh := newTestSession("s1")
	r.Register(fresh) // closes old.OutputCh, installs fresh
	wg.Wait()

	// The old channel must be closed: draining it (buffered frames may
	// remain) terminates only because Register closed it. A non-closed
	// channel would deadlock here and trip the timeout.
	drained := make(chan struct{})
	go func() {
		for range old.OutputCh { //nolint:revive // intentional drain-until-closed
		}
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("re-register must close the old session's channel")
	}

	// A reader on the NEW channel still receives a routed frame.
	require.True(t, r.RouteAgentMessage("s1", outputMsg()))
	select {
	case msg := <-fresh.OutputCh:
		assert.NotNil(t, msg)
	case <-time.After(time.Second):
		t.Fatal("reader on the new channel did not receive a routed frame")
	}
}

// TestTerminalSessionRegistry_UnregisterIdempotent pins that a double
// Unregister of the same id does not double-close (panic) the channel.
func TestTerminalSessionRegistry_UnregisterIdempotent(t *testing.T) {
	r := NewTerminalSessionRegistry()
	r.Register(newTestSession("s1"))

	assert.NotPanics(t, func() {
		r.Unregister("s1")
		r.Unregister("s1")
		r.Unregister("never-registered")
	})
}

// TestTerminalSessionRegistry_RouteAfterUnregisterReturnsFalse pins that
// routing to an unregistered / already-removed id returns false and never
// panics — covering correct, absent-session, and post-close cases.
func TestTerminalSessionRegistry_RouteAfterUnregisterReturnsFalse(t *testing.T) {
	r := NewTerminalSessionRegistry()

	// Absent session.
	assert.False(t, r.RouteAgentMessage("missing", outputMsg()))

	// Registered → routes true.
	r.Register(newTestSession("s1"))
	assert.True(t, r.RouteAgentMessage("s1", outputMsg()))

	// After Unregister → routes false, no panic.
	r.Unregister("s1")
	assert.False(t, r.RouteAgentMessage("s1", outputMsg()))
}
