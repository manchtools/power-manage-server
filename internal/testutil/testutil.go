// Package testutil provides shared test helpers for integration tests.
//
// Organization (audit F039 / manchtools/power-manage-server#156):
//
//   - testutil.go      — package vars, init, NewID
//   - postgres.go      — testcontainer setup
//   - factories_user.go    — users, roles, user groups, contexts, JWT
//   - factories_device.go  — devices, device groups, device assignments
//   - factories_action.go  — actions, action sets, definitions, assignments, tokens
//   - factories_idp.go     — identity providers, SCIM, TOTP, Encryptor
//
// All public symbols stay on `testutil` — call sites are unchanged.
package testutil

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// entropy is a monotonic ULID source. Shared across all NewID() calls
// so two calls in the same nanosecond still produce distinct ULIDs.
var entropy = ulid.Monotonic(rand.Reader, 0)

// precomputedHash is a bcrypt hash of "pass" computed once at init time.
// This avoids calling auth.HashPassword (bcrypt cost=14) for every test
// user, which would take ~1-2s per call and cause test timeouts.
var precomputedHash string

func init() {
	h, err := auth.HashPassword("pass")
	if err != nil {
		panic("testutil: precompute hash: " + err.Error())
	}
	precomputedHash = h
}

// NewID generates a unique ULID for test isolation.
func NewID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}
