package mtls

import (
	"context"
	"reflect"
	"testing"
)

// TestRevocationCheckerIsPerQueryNotSnapshot pins the SHAPE of the revocation
// interface, because the shape is what makes a stale answer expressible.
//
// Spec 41 wrote revocations in the same transaction as the renewal or deletion
// that causes them, to close the window in which a superseded certificate is
// still admitted. That closes the window on the WRITE side only. The first
// implementation of the read side was a periodically-refreshed snapshot
// (IsRevoked(fp) bool + Loaded() bool + Refresh), which kept admitting a
// revoked certificate for up to one refresh interval — the same window,
// relocated, while the commit message claimed it was gone.
//
// A per-query signature that returns an error makes that mistake unavailable:
// there is no snapshot to be stale, and no not-yet-loaded state to reason
// about, only a lookup that succeeds or fails closed. So the guard is on the
// method set rather than on any one implementation — reintroducing a cache
// means reintroducing Loaded/Refresh, and that fails here.
func TestRevocationCheckerIsPerQueryNotSnapshot(t *testing.T) {
	iface := reflect.TypeOf((*RevocationChecker)(nil)).Elem()

	// Matches-zero guard: a reflected empty interface would pass every
	// assertion below vacuously.
	if iface.NumMethod() == 0 {
		t.Fatal("RevocationChecker has no methods — this guard would pass vacuously")
	}
	// Named snapshot-lifecycle methods first, so a reintroduced cache is
	// reported by name rather than as an anonymous method-count mismatch.
	for _, banned := range []string{"Loaded", "Refresh", "Run", "Warm", "Snapshot"} {
		if _, found := iface.MethodByName(banned); found {
			t.Errorf("RevocationChecker gained %q — that is snapshot lifecycle, and a snapshot "+
				"is stale for up to one refresh interval, reopening the window the same-transaction "+
				"write exists to close", banned)
		}
	}

	// Then the count, which catches a differently-named snapshot method.
	if got := iface.NumMethod(); got != 1 {
		t.Errorf("RevocationChecker should expose exactly one method (the query); got %d", got)
	}

	m, ok := iface.MethodByName("IsRevoked")
	if !ok {
		t.Fatal("RevocationChecker must expose IsRevoked")
	}

	// Must take a context: the lookup is real I/O on the handshake path and has
	// to be cancellable with the request.
	if m.Type.NumIn() != 2 ||
		m.Type.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() ||
		m.Type.In(1).Kind() != reflect.String {
		t.Errorf("IsRevoked must be (context.Context, string); got %s", m.Type)
	}

	// Must return an error: an indeterminate answer has to be distinguishable
	// from "not revoked", or the gate cannot fail closed on it.
	if m.Type.NumOut() != 2 ||
		m.Type.Out(0).Kind() != reflect.Bool ||
		m.Type.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Errorf("IsRevoked must return (bool, error) so an indeterminate lookup can fail closed; got %s", m.Type)
	}
}
