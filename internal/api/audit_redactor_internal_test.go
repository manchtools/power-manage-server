package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// actionEnvelope builds an event payload in the SHAPE THE HANDLERS ACTUALLY
// EMIT: an integer `action_type` (NOT a top-level `type` string — that key
// never existed, which is exactly why the redactor was dead) and the params
// nested under `params`. Sourcing the fixture from the real wire shape is the
// point — the prior tests fed `{"type": "..."}` that matched the broken
// dispatch key, so they passed while the control was off.
func actionEnvelope(at pm.ActionType, params map[string]any) []byte {
	raw, _ := json.Marshal(map[string]any{
		"name":        "test-action",
		"action_type": int32(at),
		"params":      params,
	})
	return raw
}

// TestRedactEventData_ActionParams locks the schema-aware contract against
// the real `action_type` wire shape: each secret-bearing action type's
// params secret must not survive into the redacted output, with exactly one
// [REDACTED] marker per scrubbed secret.
func TestRedactEventData_ActionParams(t *testing.T) {
	cases := []struct {
		name       string
		actionType pm.ActionType
		params     map[string]any
		secrets    []string
	}{
		{
			name:       "SHELL params.script + params.detectionScript",
			actionType: pm.ActionType_ACTION_TYPE_SHELL,
			params:     map[string]any{"script": "SENTINEL_SHELL", "detectionScript": "SENTINEL_DETECT"},
			secrets:    []string{"SENTINEL_SHELL", "SENTINEL_DETECT"},
		},
		{
			name:       "SCRIPT_RUN reuses ShellParams script paths",
			actionType: pm.ActionType_ACTION_TYPE_SCRIPT_RUN,
			params:     map[string]any{"script": "SENTINEL_SCRIPTRUN"},
			secrets:    []string{"SENTINEL_SCRIPTRUN"},
		},
		{
			name:       "FILE params.content",
			actionType: pm.ActionType_ACTION_TYPE_FILE,
			params:     map[string]any{"path": "/etc/foo", "content": "SENTINEL_FILE"},
			secrets:    []string{"SENTINEL_FILE"},
		},
		{
			name:       "SERVICE params.unitContent",
			actionType: pm.ActionType_ACTION_TYPE_SERVICE,
			params:     map[string]any{"name": "foo.service", "unitContent": "SENTINEL_UNIT"},
			secrets:    []string{"SENTINEL_UNIT"},
		},
		{
			name:       "ADMIN_POLICY params.customConfig",
			actionType: pm.ActionType_ACTION_TYPE_ADMIN_POLICY,
			params:     map[string]any{"customConfig": "SENTINEL_SUDO"},
			secrets:    []string{"SENTINEL_SUDO"},
		},
		{
			name:       "REPOSITORY params.gpgKey",
			actionType: pm.ActionType_ACTION_TYPE_REPOSITORY,
			params:     map[string]any{"url": "https://example.com/repo", "gpgKey": "SENTINEL_GPG"},
			secrets:    []string{"SENTINEL_GPG"},
		},
		{
			name:       "ENCRYPTION params.presharedKey",
			actionType: pm.ActionType_ACTION_TYPE_ENCRYPTION,
			params:     map[string]any{"devicePath": "/dev/sda1", "presharedKey": "SENTINEL_LUKS_PSK"},
			secrets:    []string{"SENTINEL_LUKS_PSK"},
		},
		{
			name:       "WIFI params.psk + params.clientKey",
			actionType: pm.ActionType_ACTION_TYPE_WIFI,
			params:     map[string]any{"ssid": "corp", "psk": "SENTINEL_WIFI_PSK", "clientKey": "SENTINEL_WIFI_CLIENTKEY", "caCert": "public-ca"},
			secrets:    []string{"SENTINEL_WIFI_PSK", "SENTINEL_WIFI_CLIENTKEY"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := redactEventData("action", "ActionCreated", actionEnvelope(tc.actionType, tc.params))
			for _, s := range tc.secrets {
				assert.NotContainsf(t, out, s, "secret %q must not appear in redacted output: %s", s, out)
			}
			assert.Equal(t, len(tc.secrets), strings.Count(out, "[REDACTED]"),
				"expected one [REDACTED] marker per scrubbed secret")
		})
	}
}

// TestRedactEventData_ExecutionStream locks that execution-stream events —
// which embed the SAME params + action_type as the action stream
// (action_dispatch.go) — are redacted identically. Before #352 the
// execution stream had no schema at all, so dispatched action params leaked
// through the audit log.
func TestRedactEventData_ExecutionStream(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"execution_id": "exec-1",
		"action_type":  int32(pm.ActionType_ACTION_TYPE_SHELL),
		"params":       map[string]any{"script": "SENTINEL_EXEC_SHELL"},
	})
	require.NoError(t, err)
	out := redactEventData("execution", "ExecutionCreated", raw)
	assert.NotContains(t, out, "SENTINEL_EXEC_SHELL")
	assert.Contains(t, out, "[REDACTED]")
}

// TestRedactEventData_ActionParamsUpdated locks that an ActionParamsUpdated
// event (which now carries action_type, #352) has its updated secret params
// scrubbed.
func TestRedactEventData_ActionParamsUpdated(t *testing.T) {
	raw := actionEnvelope(pm.ActionType_ACTION_TYPE_FILE, map[string]any{"content": "SENTINEL_UPDATED_FILE"})
	out := redactEventData("action", "ActionParamsUpdated", raw)
	assert.NotContains(t, out, "SENTINEL_UPDATED_FILE")
	assert.Contains(t, out, "[REDACTED]")
}

// TestRedactEventData_ActionStreamMissingActionTypeFallback locks the
// fail-safe: an action/execution event with NO usable action_type (a legacy
// ActionParamsUpdated emitted before #352, say) still has any known secret
// param scrubbed via the union fallback, rather than leaking it.
func TestRedactEventData_ActionStreamMissingActionTypeFallback(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"params": map[string]any{"content": "SENTINEL_LEGACY_FILE"},
	})
	require.NoError(t, err)
	out := redactEventData("action", "ActionParamsUpdated", raw)
	assert.NotContains(t, out, "SENTINEL_LEGACY_FILE", "legacy event without action_type must still be scrubbed via the union fallback")
	assert.Contains(t, out, "[REDACTED]")
}

// TestRedactEventData_NonActionStreams locks the per-(stream,event) schema:
// IdentityProvider client_secret_encrypted, User password_hash, the flat LPS
// password, and the LUKS passphrase must scrub.
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
			payload:    map[string]any{"name": "okta", "client_secret_encrypted": "SENTINEL_IDP"},
			secret:     "SENTINEL_IDP",
		},
		{
			name:       "UserCreatedWithRoles password_hash",
			streamType: "user",
			eventType:  "UserCreatedWithRoles",
			payload:    map[string]any{"email": "alice@example.com", "password_hash": "SENTINEL_PWD_HASH"},
			secret:     "SENTINEL_PWD_HASH",
		},
		{
			// Real emit is one flat payloads.LpsPasswordRotated per rotation
			// with the credential at top-level "password" (#352 fixed the
			// phantom "rotations[].password" path).
			name:       "LpsPasswordRotated flat password",
			streamType: "lps_password",
			eventType:  "LpsPasswordRotated",
			payload:    map[string]any{"username": "alice", "password": "SENTINEL_LPS_ROT"},
			secret:     "SENTINEL_LPS_ROT",
		},
		{
			name:       "LuksKeyRotated passphrase",
			streamType: "luks_key",
			eventType:  "LuksKeyRotated",
			payload:    map[string]any{"device_path": "/dev/sda1", "passphrase": "SENTINEL_LUKS_ROT"},
			secret:     "SENTINEL_LUKS_ROT",
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

// TestRedactEventData_UnknownShapesPassThrough locks the design contract that
// the redactor is conservative for NON action/execution streams: an unknown
// (stream,event) combination passes through unchanged.
func TestRedactEventData_UnknownShapesPassThrough(t *testing.T) {
	in := map[string]any{"name": "do-thing", "password": "not-redacted-unknown-schema"}
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	out := redactEventData("unknown_stream", "UnknownEvent", raw)
	assert.Equal(t, string(raw), out)
}

// TestRedactEventData_ActionWithoutSecretsPassesThrough locks that a
// recognised action type with no secret params (PACKAGE) is not rewritten —
// bytes-equal output saves a re-marshal on the hot path.
func TestRedactEventData_ActionWithoutSecretsPassesThrough(t *testing.T) {
	raw := actionEnvelope(pm.ActionType_ACTION_TYPE_PACKAGE, map[string]any{"package": "vim"})
	out := redactEventData("action", "ActionCreated", raw)
	assert.Equal(t, string(raw), out)
}

// TestRedactEventData_EmptyAndInvalid checks defensive paths.
func TestRedactEventData_EmptyAndInvalid(t *testing.T) {
	assert.Equal(t, "", redactEventData("action", "ActionCreated", nil))
	assert.Equal(t, "{not json", redactEventData("action", "ActionCreated", []byte("{not json")))
}

// TestEveryActionTypeClassified is self-discovering against the proto enum:
// every ActionType must be consciously classified — either it has a redaction
// schema (secret params) or it is listed as having none. A new action type
// added without classification fails here, forcing a redaction decision and
// preventing a repeat of the SCRIPT_RUN/SERVICE/WIFI omissions (#352).
func TestEveryActionTypeClassified(t *testing.T) {
	// Action types whose params carry NO secret. Curated from the proto, but
	// the test below fails if the enum grows and a value lands in neither set.
	noSecretParams := map[string]bool{
		"ACTION_TYPE_PACKAGE":      true,
		"ACTION_TYPE_UPDATE":       true,
		"ACTION_TYPE_APP_IMAGE":    true,
		"ACTION_TYPE_DEB":          true,
		"ACTION_TYPE_RPM":          true,
		"ACTION_TYPE_FLATPAK":      true,
		"ACTION_TYPE_DIRECTORY":    true,
		"ACTION_TYPE_REBOOT":       true,
		"ACTION_TYPE_SYNC":         true,
		"ACTION_TYPE_USER":         true,
		"ACTION_TYPE_GROUP":        true,
		"ACTION_TYPE_SSH":          true,
		"ACTION_TYPE_SSHD":         true,
		"ACTION_TYPE_LPS":          true, // rotated password surfaces via LpsPasswordRotated event, not params
		"ACTION_TYPE_AGENT_UPDATE": true,
	}
	require.NotEmpty(t, pm.ActionType_name)
	for v, name := range pm.ActionType_name {
		if name == "ACTION_TYPE_UNSPECIFIED" {
			continue
		}
		_, hasSchema := actionRedactionSchemas[name]
		noSec := noSecretParams[name]
		require.Falsef(t, hasSchema && noSec,
			"action type %s (%d) is in BOTH the redaction schema and the no-secret list — pick one", name, v)
		require.Truef(t, hasSchema || noSec,
			"action type %s (%d) is unclassified for audit redaction — add a schema to actionRedactionSchemas or list it in noSecretParams", name, v)
	}
}

// TestActionParamsSecretFieldsCovered is self-discovering against the proto
// MESSAGES: it walks every params message reachable from the
// CreateActionRequest params oneof and asserts that any string field whose
// name looks sensitive has a redaction path in the union. A secret field
// added to any action's params with no matching redaction path fails here.
func TestActionParamsSecretFieldsCovered(t *testing.T) {
	union := map[string]bool{}
	for _, p := range allActionSecretPaths.paths {
		union[p] = true
	}

	desc := (&pm.CreateActionRequest{}).ProtoReflect().Descriptor()
	scanned := 0
	for oi := 0; oi < desc.Oneofs().Len(); oi++ {
		fields := desc.Oneofs().Get(oi).Fields()
		for fi := 0; fi < fields.Len(); fi++ {
			f := fields.Get(fi)
			if f.Kind() != protoreflect.MessageKind {
				continue
			}
			msg := f.Message()
			for mi := 0; mi < msg.Fields().Len(); mi++ {
				pf := msg.Fields().Get(mi)
				if pf.Kind() != protoreflect.StringKind || pf.IsList() {
					continue
				}
				if !isSensitiveParamField(string(pf.Name())) {
					continue
				}
				path := "params." + pf.JSONName()
				require.Truef(t, union[path],
					"params message %s field %q looks secret but has no redaction path %q — add it to actionRedactionSchemas (#352)",
					msg.Name(), pf.Name(), path)
				scanned++
			}
		}
	}
	require.Positivef(t, scanned, "self-discovering scan matched zero sensitive fields — isSensitiveParamField is broken")
}

// isSensitiveParamField classifies a proto params field name (snake_case) as
// secret-bearing. The explicit allowlist covers public material and
// non-secret config that would otherwise match a fragment.
func isSensitiveParamField(name string) bool {
	switch name {
	case "ca_cert", "client_cert", // public PEM certificates
		"ssh_authorized_keys",   // public keys
		"gpg_key_url", "gpgkey", // repository key URLs, not key material
		"checksum_sha256":
		return false
	}
	for _, frag := range []string{
		"script", "content", "custom_config",
		"psk", "preshared_key", "client_key", "private_key", "gpg_key",
		"passphrase", "password", "secret",
	} {
		if strings.Contains(name, frag) {
			return true
		}
	}
	return false
}

// TestSplitPath_ArraySegments locks the path parser against the shapes that
// appear in the schemas (including the array form retained for defensiveness).
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
