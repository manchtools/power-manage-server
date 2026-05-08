package projectors_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// jsonOrFail marshals the map for the pure-function tests in this
// package. Centralised here so the per-file test suites do not each
// drag in encoding/json just to build event payloads.
func jsonOrFail(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
