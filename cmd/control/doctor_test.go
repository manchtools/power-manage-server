package main

import (
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
