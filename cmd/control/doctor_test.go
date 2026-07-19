package main

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

// `doctor -h` is a help request, not a failure — it must exit 0.
func TestRunDoctor_HelpExitsZero(t *testing.T) {
	assert.Equal(t, 0, runDoctor([]string{"-h"}))
}

// Stray positional args are a usage error, not silently ignored.
func TestRunDoctor_RejectsExtraArgs(t *testing.T) {
	assert.Equal(t, 2, runDoctor([]string{"--env-file=/nonexistent", "stray"}))
}

// A non-numeric CONTROL_VALKEY_DB must fail as a config error rather than being
// silently coerced to database 0 (which would probe the wrong DB).
func TestRunDoctor_RejectsNonNumericValkeyDB(t *testing.T) {
	t.Setenv("CONTROL_VALKEY_DB", "not-a-number")
	assert.Equal(t, 2, runDoctor([]string{"--env-file=/nonexistent"}))
}

// spec 32 audit: a nil TLS config means the probe would dial plaintext — the ACL
// credentials must be withheld in EVERY nil case, including TLS vars entirely
// absent (which yields nil WITHOUT an error), not only the partial-set error path.
func TestValkeyProbeCreds_NilTLSDropsCredentials(t *testing.T) {
	user, pass := valkeyProbeCreds(nil, "pm-control", "secret")
	assert.Empty(t, user)
	assert.Empty(t, pass)
}

func TestValkeyProbeCreds_TLSKeepsCredentials(t *testing.T) {
	user, pass := valkeyProbeCreds(&tls.Config{}, "pm-control", "secret")
	assert.Equal(t, "pm-control", user)
	assert.Equal(t, "secret", pass)
}
