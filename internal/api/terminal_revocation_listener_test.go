package api_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
)

// fakeSessionTerminator records which user IDs the listener asked to close.
// (Structurally satisfies the unexported userSessionTerminator interface.)
type fakeSessionTerminator struct{ ch chan string }

func (f *fakeSessionTerminator) TerminateUserSessions(_ context.Context, userID string) {
	f.ch <- userID
}

// fakePermsChecker returns a fixed effective-permission set (or error) for the
// role-revoke recheck. (Satisfies the unexported userPermissionChecker.)
type fakePermsChecker struct {
	perms []string
	err   error
}

func (f fakePermsChecker) Permissions(context.Context, string) ([]string, error) {
	return f.perms, f.err
}

func roleRevokedEvent(userID string) store.PersistedEvent {
	data, _ := json.Marshal(payloads.UserRoleRevoked{UserID: userID})
	return store.PersistedEvent{
		StreamType: "user_role",
		EventType:  "UserRoleRevoked",
		StreamID:   userID + ":someRole",
		Data:       data,
	}
}

func expectClose(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	select {
	case got := <-ch:
		assert.Equal(t, want, got)
	case <-time.After(2 * time.Second):
		t.Fatalf("expected the listener to close sessions for %q, got none", want)
	}
}

func expectNoClose(t *testing.T, ch <-chan string) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("expected NO session close, but it fired for %q", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestTerminalRevocationListener_DisableDelete pins the unconditional triggers:
// UserDisabled and UserDeleted close all the user's sessions; re-enable and
// non-user events don't. (Disable/delete don't consult the permission checker.)
func TestTerminalRevocationListener_DisableDelete(t *testing.T) {
	ft := &fakeSessionTerminator{ch: make(chan string, 1)}
	l := api.TerminalRevocationListener(ft, fakePermsChecker{}, slog.Default())

	l(context.Background(), store.PersistedEvent{StreamType: "user", EventType: "UserDisabled", StreamID: "u1"})
	expectClose(t, ft.ch, "u1")

	l(context.Background(), store.PersistedEvent{StreamType: "user", EventType: "UserDeleted", StreamID: "u2"})
	expectClose(t, ft.ch, "u2")

	l(context.Background(), store.PersistedEvent{StreamType: "user", EventType: "UserEnabled", StreamID: "u3"})
	expectNoClose(t, ft.ch)

	l(context.Background(), store.PersistedEvent{StreamType: "device", EventType: "DeviceDeleted", StreamID: "d1"})
	expectNoClose(t, ft.ch)
}

// TestTerminalRevocationListener_RoleRevoke pins the #391 conditional trigger: a
// UserRoleRevoked closes sessions ONLY if the user no longer holds StartTerminal
// via any remaining role/group — a revoke that leaves it intact must NOT close.
func TestTerminalRevocationListener_RoleRevoke(t *testing.T) {
	t.Run("removed last StartTerminal -> close", func(t *testing.T) {
		ft := &fakeSessionTerminator{ch: make(chan string, 1)}
		l := api.TerminalRevocationListener(ft, fakePermsChecker{perms: []string{"ListDevices"}}, slog.Default())
		l(context.Background(), roleRevokedEvent("u1"))
		expectClose(t, ft.ch, "u1")
	})

	t.Run("still holds StartTerminal via another role -> no close", func(t *testing.T) {
		ft := &fakeSessionTerminator{ch: make(chan string, 1)}
		l := api.TerminalRevocationListener(ft, fakePermsChecker{perms: []string{"StartTerminal", "ListDevices"}}, slog.Default())
		l(context.Background(), roleRevokedEvent("u2"))
		expectNoClose(t, ft.ch)
	})

	t.Run("permission recheck errors -> no close (fail-safe, no spurious kill)", func(t *testing.T) {
		ft := &fakeSessionTerminator{ch: make(chan string, 1)}
		l := api.TerminalRevocationListener(ft, fakePermsChecker{err: assert.AnError}, slog.Default())
		l(context.Background(), roleRevokedEvent("u3"))
		expectNoClose(t, ft.ch)
	})
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
	l := api.TerminalRevocationListener(panicTerminator{done: done}, fakePermsChecker{}, slog.Default())
	l(context.Background(), store.PersistedEvent{StreamType: "user", EventType: "UserDisabled", StreamID: "u1"})
	select {
	case <-done:
		// goroutine ran and the listener's recover swallowed the panic.
	case <-time.After(2 * time.Second):
		t.Fatal("background close goroutine did not run")
	}
}
