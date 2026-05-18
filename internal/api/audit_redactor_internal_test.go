package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedactEventData_ActionParams locks the schema-aware contract:
// each action type has its own redaction schema rooted at `params.`.
// A SHELL action's `script`, a FILE action's `content`, an
// ADMIN_POLICY action's `customConfig`, etc. must NOT appear verbatim
// in the redacted output.
//
// The fixtures here use the **camelCase** keys the production wire
// format actually produces — see audit F-34. Earlier versions of this
// test used snake_case keys that matched a (broken) snake_case
// schema, masking the production leak. The fixtures match what
// `serializeProtoParams` in internal/api/action_params.go emits via
// protojson (`UseProtoNames=false`).
func TestRedactEventData_ActionParams(t *testing.T) {
	cases := []struct {
		name       string
		actionType string
		params     map[string]any
		secrets    []string
	}{
		{
			name:       "SHELL params.script + params.detectionScript",
			actionType: "ACTION_TYPE_SHELL",
			params: map[string]any{
				"script":          "echo SENTINEL_SHELL",
				"detectionScript": "echo SENTINEL_DETECT",
			},
			secrets: []string{"SENTINEL_SHELL", "SENTINEL_DETECT"},
		},
		{
			name:       "FILE params.content",
			actionType: "ACTION_TYPE_FILE",
			params: map[string]any{
				"path":    "/etc/foo",
				"content": "SENTINEL_FILE",
			},
			secrets: []string{"SENTINEL_FILE"},
		},
		{
			name:       "ADMIN_POLICY params.customConfig",
			actionType: "ACTION_TYPE_ADMIN_POLICY",
			params: map[string]any{
				"customConfig": "SENTINEL_SUDO",
			},
			secrets: []string{"SENTINEL_SUDO"},
		},
		{
			name:       "REPOSITORY params.gpgKey",
			actionType: "ACTION_TYPE_REPOSITORY",
			params: map[string]any{
				"url":    "https://example.com/repo",
				"gpgKey": "SENTINEL_GPG",
			},
			secrets: []string{"SENTINEL_GPG"},
		},
		{
			name:       "ENCRYPTION (LUKS) params.presharedKey",
			actionType: "ACTION_TYPE_ENCRYPTION",
			params: map[string]any{
				"devicePath":   "/dev/sda1",
				"presharedKey": "SENTINEL_LUKS_PSK",
			},
			secrets: []string{"SENTINEL_LUKS_PSK"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{
				"name":   "test-action",
				"type":   tc.actionType,
				"params": tc.params,
			}
			raw, err := json.Marshal(payload)
			require.NoError(t, err)
			out := redactEventData("action", "ActionCreated", raw)
			for _, s := range tc.secrets {
				assert.NotContains(t, out, s, "secret %q must not appear in redacted output: %s", s, out)
			}
			assert.Equal(t, strings.Count(out, "[REDACTED]"), len(tc.secrets),
				"expected one [REDACTED] marker per scrubbed secret")
		})
	}
}

// TestRedactEventData_NonActionStreams locks the per-(stream,event)
// schema. The IdentityProvider client_secret_encrypted, the
// User password_hash, and the LPS rotations[].password / LUKS
// passphrase paths must scrub.
func TestRedactEventData_NonActionStreams(t *testing.T) {
	cases := []struct {
		name       string
		streamType string
		eventType  string
		payload    map[string]any
		secret     string
	}{
		{
			name:       "IdentityProviderCreated client_secret_encrypted",
			streamType: "identity_provider",
			eventType:  "IdentityProviderCreated",
			payload: map[string]any{
				"name":                    "okta",
				"client_secret_encrypted": "SENTINEL_IDP",
			},
			secret: "SENTINEL_IDP",
		},
		{
			name:       "UserCreatedWithRoles password_hash",
			streamType: "user",
			eventType:  "UserCreatedWithRoles",
			payload: map[string]any{
				"email":         "alice@example.com",
				"password_hash": "SENTINEL_PWD_HASH",
			},
			secret: "SENTINEL_PWD_HASH",
		},
		{
			name:       "LpsPasswordRotated rotations[].password",
			streamType: "lps_password",
			eventType:  "LpsPasswordRotated",
			payload: map[string]any{
				"rotations": []any{
					map[string]any{"username": "alice", "password": "SENTINEL_LPS_ROT"},
				},
			},
			secret: "SENTINEL_LPS_ROT",
		},
		{
			name:       "LuksKeyRotated passphrase",
			streamType: "luks_key",
			eventType:  "LuksKeyRotated",
			payload: map[string]any{
				"device_path": "/dev/sda1",
				"passphrase":  "SENTINEL_LUKS_ROT",
			},
			secret: "SENTINEL_LUKS_ROT",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.payload)
			require.NoError(t, err)
			out := redactEventData(tc.streamType, tc.eventType, raw)
			assert.NotContains(t, out, tc.secret, "secret must be redacted")
			assert.Contains(t, out, "[REDACTED]", "redacted output must contain redaction marker")
		})
	}
}

// TestRedactEventData_UnknownShapesPassThrough locks the design
// contract that the redactor is fail-closed but conservative: an
// unknown stream/event combination passes through unchanged (the
// audit log is for operators, not consumers, and the schema-aware
// approach explicitly does not over-scrub unrecognized shapes).
func TestRedactEventData_UnknownShapesPassThrough(t *testing.T) {
	in := map[string]any{
		// Not an action emit shape, not in eventRedactionSchemas.
		"name":     "do-thing",
		"password": "this-is-not-actually-redacted-because-we-dont-know-the-schema",
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	out := redactEventData("unknown_stream", "UnknownEvent", raw)
	assert.Equal(t, string(raw), out)
}

// TestRedactEventData_ActionWithoutSecretsPassesThrough locks that
// action types without sensitive params (PACKAGE, USER, GROUP, …)
// never get rewritten — bytes-equal output saves a re-marshal on the
// hot path.
func TestRedactEventData_ActionWithoutSecretsPassesThrough(t *testing.T) {
	in := map[string]any{
		"name": "install-pkg",
		"type": "ACTION_TYPE_PACKAGE",
		"params": map[string]any{
			"package": "vim",
		},
	}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	out := redactEventData("action", "ActionCreated", raw)
	assert.Equal(t, string(raw), out)
}

// TestRedactEventData_EmptyAndInvalid checks defensive paths.
func TestRedactEventData_EmptyAndInvalid(t *testing.T) {
	assert.Equal(t, "", redactEventData("action", "ActionCreated", nil))
	assert.Equal(t, "{not json", redactEventData("action", "ActionCreated", []byte("{not json")))
}

// TestSplitPath_ArraySegments locks the path parser against the four
// shapes that appear in eventRedactionSchemas / actionRedactionSchemas.
func TestSplitPath_ArraySegments(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"params.script", []string{"params", "script"}},
		{"client_secret_encrypted", []string{"client_secret_encrypted"}},
		{"rotations[].password", []string{"rotations", "[]", "password"}},
		{"params.preshared_key", []string{"params", "preshared_key"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, splitPath(tc.in))
		})
	}
}
