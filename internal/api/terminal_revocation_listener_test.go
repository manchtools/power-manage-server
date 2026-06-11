package api_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/store"
)

// fakeSessionTerminator records which user IDs the listener asked to close.
// (Structurally satisfies the unexported userSessionTerminator interface.)
type fakeSessionTerminator struct{ ch chan string }

func (f *fakeSessionTerminator) TerminateUserSessions(_ context.Context, userID string) {
	f.ch <- userID
}

// TestTerminalRevocationListener pins the trigger: a user's live terminal
// sessions are closed on UserDisabled and UserDeleted, and NOT on re-enable or
// any non-user event. (The gateway fan-out itself is exercised by the terminal
// admin RPCs; here we pin only that the right events fire it.)
func TestTerminalRevocationListener(t *testing.T) {
	ft := &fakeSessionTerminator{ch: make(chan string, 1)}
	l := api.TerminalRevocationListener(ft, slog.Default())

	fire := func(streamType, eventType, streamID string) {
		l(context.Background(), store.PersistedEvent{
			StreamType: streamType,
			EventType:  eventType,
			StreamID:   streamID,
		})
	}
	expectClose := func(wantUserID string) {
		t.Helper()
		select {
		case got := <-ft.ch:
			assert.Equal(t, wantUserID, got)
		case <-time.After(2 * time.Second):
			t.Fatalf("expected the listener to close sessions for %q, got none", wantUserID)
		}
	}
	expectNoClose := func() {
		t.Helper()
		select {
		case got := <-ft.ch:
			t.Fatalf("expected NO session close, but it fired for %q", got)
		case <-time.After(100 * time.Millisecond):
		}
	}

	fire("user", "UserDisabled", "u1")
	expectClose("u1")

	fire("user", "UserDeleted", "u2")
	expectClose("u2")

	fire("user", "UserEnabled", "u3") // re-enabling must NOT close sessions
	expectNoClose()

	fire("device", "DeviceDeleted", "d1") // non-user stream is irrelevant
	expectNoClose()
}

// panicTerminator panics, but signals (via defer) that it ran.
type panicTerminator struct{ done chan struct{} }

func (p panicTerminator) TerminateUserSessions(context.Context, string) {
	defer close(p.done)
	panic("boom")
}

// TestTerminalRevocationListener_RecoversPanic pins that a panic in the
// background close does NOT crash the control process — an unrecovered panic in
// a spawned goroutine takes the whole program down. If the recover regressed,
// this test run would abort rather than merely fail.
func TestTerminalRevocationListener_RecoversPanic(t *testing.T) {
	done := make(chan struct{})
	l := api.TerminalRevocationListener(panicTerminator{done: done}, slog.Default())
	l(context.Background(), store.PersistedEvent{StreamType: "user", EventType: "UserDisabled", StreamID: "u1"})
	select {
	case <-done:
		// goroutine ran and the listener's recover swallowed the panic.
	case <-time.After(2 * time.Second):
		t.Fatal("background close goroutine did not run")
	}
}
