package idp

import (
	"os"
	"testing"
)

// TestMain disables the OIDC SSRF dial-control (spec 29 S4) for the whole idp
// test binary: the OIDC integration tests spin up httptest servers on loopback,
// which the guard correctly refuses in production. The guard's logic is covered
// directly by TestSSRFSafeDialControl, so disabling the wiring here loses no
// coverage while letting the loopback-backed tests run.
func TestMain(m *testing.M) {
	oidcDialControl = nil
	os.Exit(m.Run())
}
