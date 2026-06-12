package api

// WS1b #5 — CommandOutput JSONB blobs are decoded with protojson (the correct
// codec for a proto message), not stdlib encoding/json. The single
// decodeCommandOutput helper replaces four hand-rolled decode sites (two that
// stdlib-unmarshalled straight into the proto, two that re-declared the field
// set as an anonymous struct). The architectural guard
// TestNoStdlibJSONOfProtoMessage prevents the stdlib-json-of-proto smell from
// returning; this test pins the codec is actually protojson.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandOutputUsesProtojson(t *testing.T) {
	// The legacy writer (payloads.RawCommandOutput) emits snake_case keys; the
	// reader must still accept them so existing rows decode.
	legacy := decodeCommandOutput([]byte(`{"stdout":"hello","stderr":"oops","exit_code":7}`))
	require.NotNil(t, legacy)
	assert.Equal(t, "hello", legacy.Stdout)
	assert.Equal(t, "oops", legacy.Stderr)
	assert.Equal(t, int32(7), legacy.ExitCode)

	// A proto-native writer emits the camelCase JSON name `exitCode`. protojson
	// reads it; stdlib json.Unmarshal into pm.CommandOutput only knows the
	// `exit_code` struct tag and would silently leave ExitCode at 0. This is the
	// RED-if-stdlib assertion — it fails the moment the codec regresses to
	// encoding/json.
	camel := decodeCommandOutput([]byte(`{"stdout":"hi","exitCode":9}`))
	require.NotNil(t, camel)
	assert.Equal(t, "hi", camel.Stdout)
	assert.Equal(t, int32(9), camel.ExitCode,
		"protojson must read the camelCase exitCode; stdlib encoding/json would leave it 0")

	// Empty / malformed input → nil (best-effort: a corrupt blob must not fail
	// the whole execution read), never a panic.
	assert.Nil(t, decodeCommandOutput(nil))
	assert.Nil(t, decodeCommandOutput([]byte{}))
	assert.Nil(t, decodeCommandOutput([]byte("{not json")))
}
