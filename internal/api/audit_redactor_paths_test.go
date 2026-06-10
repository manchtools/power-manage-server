package api

// Audit F-34 — schema-vs-wire validator.
//
// `actionRedactionSchemas` claims to scrub specific paths under
// `params.<name>` for each action type. The wire format of `params`
// is produced by serializeProtoParams via protojson with
// `UseProtoNames=false` (camelCase JSON keys). A schema path that
// names a snake_case field — or a field that doesn't exist on the
// underlying proto at all — silently misses the secret. The prior
// schema had exactly that bug for every secret-bearing action type
// (`unit_content`, `gpg_key`, `preshared_key`, the phantom
// `passphrase` / LPS `password`), and the existing tests masked it
// by passing snake_case fixtures matching the broken schema.
//
// This test fails fast on any future schema drift by checking that
// every action-redaction path resolves to a real field on a
// fully-populated emit of the corresponding proto message. If the
// proto field is renamed and the schema isn't updated in lock-step,
// CI catches it.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
)

// fullyPopulatedParamsFor returns one of each secret-bearing
// action's proto message, populated with non-zero values on every
// field that should appear in the protojson emit. We don't try to
// be smart about defaults — protojson's `EmitUnpopulated=false`
// drops zero-value fields, but we set every field to a distinct
// sentinel so the wire emit definitely contains it.
func fullyPopulatedParamsFor(t *testing.T, actionType string) proto.Message {
	t.Helper()
	switch actionType {
	case "ACTION_TYPE_SHELL", "ACTION_TYPE_SCRIPT_RUN":
		return &pm.ShellParams{
			Script:           "S",
			DetectionScript:  "D",
			Interpreter:      "/bin/bash",
			RunAsRoot:        true,
			Environment:      map[string]string{"K": "V"},
			WorkingDirectory: "/tmp",
		}
	case "ACTION_TYPE_SERVICE":
		return &pm.ServiceParams{
			UnitName:    "foo.service",
			UnitContent: "U",
		}
	case "ACTION_TYPE_WIFI":
		return &pm.WifiParams{
			Ssid:       "corp",
			AuthType:   pm.WifiAuthType(1),
			Psk:        "P",
			ClientKey:  "K",
			ClientCert: "C",
			CaCert:     "CA",
		}
	case "ACTION_TYPE_FILE":
		return &pm.FileParams{
			Path:    "/etc/x",
			Content: "C",
			Owner:   "root",
			Group:   "root",
			Mode:    "0644",
		}
	case "ACTION_TYPE_ADMIN_POLICY":
		return &pm.AdminPolicyParams{
			AccessLevel:  pm.AdminAccessLevel(3),
			Users:        []string{"alice"},
			CustomConfig: "C",
		}
	case "ACTION_TYPE_REPOSITORY":
		return &pm.AptRepository{
			Url:          "https://example.com",
			Distribution: "stable",
			Components:   []string{"main"},
			GpgKey:       "K",
			GpgKeyUrl:    "https://example.com/key.asc",
		}
	case "ACTION_TYPE_ENCRYPTION":
		return &pm.EncryptionParams{
			PresharedKey:         "P",
			RotationIntervalDays: 30,
		}
	}
	return nil
}

func TestActionRedactionSchemas_PathsMatchWireFormat(t *testing.T) {
	for actionType, schema := range actionRedactionSchemas {
		actionType, schema := actionType, schema
		t.Run(actionType, func(t *testing.T) {
			msg := fullyPopulatedParamsFor(t, actionType)
			require.NotNil(t, msg,
				"redaction schema names action type %s but the test fixture has no proto for it — add one to fullyPopulatedParamsFor", actionType)

			raw, err := actionparams.MarshalActionParams(msg)
			require.NoError(t, err)

			var params map[string]any
			require.NoError(t, json.Unmarshal(raw, &params))

			// Wrap in the {name, type, params} envelope so the path
			// `params.X` resolves the same way the redactor walks it.
			envelope := map[string]any{
				"name":   "test",
				"type":   actionType,
				"params": params,
			}

			for _, path := range schema.paths {
				if path == "" {
					continue
				}
				resolved, ok := resolveJSONPath(envelope, path)
				require.True(t, ok,
					"redaction schema %s claims to scrub %q but that path does not exist on the wire emit of %T (got keys: %v)",
					actionType, path, msg, sortedKeys(params))
				_, isString := resolved.(string)
				require.True(t, isString,
					"redaction schema %s path %q resolves to %T, not a string — redactor only knows how to scrub string fields",
					actionType, path, resolved)
			}
		})
	}
}

// resolveJSONPath walks a dotted path through a decoded JSON map and
// returns the leaf value. Returns (nil, false) if any segment is
// missing or refers to a non-map.
func resolveJSONPath(root any, path string) (any, bool) {
	segs := strings.Split(path, ".")
	cur := root
	for _, s := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := m[s]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
