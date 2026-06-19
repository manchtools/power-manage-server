package api_test

import (
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestListAuditEvents_RedactsActionSecrets is the real-emit-path proof for
// audit finding #1. It drives the ACTUAL CreateAction handler — which emits
// ActionCreated with `action_type` as an int and `params` nested, the true
// wire shape — then reads the audit log back through ListAuditEvents and
// asserts the secret never appears.
//
// The prior unit tests hand-built a `{"type": "ACTION_TYPE_SHELL", ...}` map
// that matched the redactor's (broken) dispatch key, so they stayed green
// while the redactor was dead against the real `action_type` int the
// handlers actually write. Sourcing the payload from the production emit
// means this test can only pass if the redactor fires on what handlers
// genuinely persist.
func TestListAuditEvents_RedactsActionSecrets(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		req    *pm.CreateActionRequest
	}{
		{
			name:   "SHELL script",
			secret: "SENTINEL_SHELL_8a1f",
			req: &pm.CreateActionRequest{
				Name: "shell-leak",
				Type: pm.ActionType_ACTION_TYPE_SHELL,
				Params: &pm.CreateActionRequest_Shell{
					Shell: &pm.ShellParams{Script: "SENTINEL_SHELL_8a1f"},
				},
			},
		},
		{
			name:   "FILE content",
			secret: "SENTINEL_FILE_8a1f",
			req: &pm.CreateActionRequest{
				Name: "file-leak",
				Type: pm.ActionType_ACTION_TYPE_FILE,
				Params: &pm.CreateActionRequest_File{
					File: &pm.FileParams{Path: "/etc/x", Content: "SENTINEL_FILE_8a1f"},
				},
			},
		},
		{
			name:   "ENCRYPTION presharedKey (plaintext LUKS bootstrap entropy)",
			secret: "SENTINEL_LUKS_8a1f",
			req: &pm.CreateActionRequest{
				Name: "luks-leak",
				Type: pm.ActionType_ACTION_TYPE_ENCRYPTION,
				Params: &pm.CreateActionRequest_Encryption{
					Encryption: &pm.EncryptionParams{
						PresharedKey:         "SENTINEL_LUKS_8a1f",
						RotationIntervalDays: 30,
					},
				},
			},
		},
		{
			// SERVICE/WIFI were among the leaks #352 found beyond the audit's
			// list; cover them end-to-end through the real emit path too.
			name:   "SERVICE unitContent (systemd unit body)",
			secret: "SENTINEL_SERVICE_8a1f",
			req: &pm.CreateActionRequest{
				Name: "service-leak",
				Type: pm.ActionType_ACTION_TYPE_SERVICE,
				Params: &pm.CreateActionRequest_Service{
					Service: &pm.ServiceParams{
						UnitName:    "test.service",
						UnitContent: "SENTINEL_SERVICE_8a1f",
					},
				},
			},
		},
		{
			name:   "WIFI psk (WPA pre-shared key)",
			secret: "SENTINEL_WIFI_8a1f",
			req: &pm.CreateActionRequest{
				Name: "wifi-leak",
				Type: pm.ActionType_ACTION_TYPE_WIFI,
				Params: &pm.CreateActionRequest_Wifi{
					Wifi: &pm.WifiParams{
						Ssid:     "corp",
						AuthType: pm.WifiAuthType(1),
						Psk:      "SENTINEL_WIFI_8a1f",
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := testutil.SetupPostgres(t)
			actionH := api.NewActionHandler(st, slog.Default(), api.NoOpSigner{})
			auditH := api.NewAuditHandler(st, slog.Default())
			adminID := testutil.CreateTestUser(t, st, testutil.NewID()+"@test.com", "pass", "admin")
			ctx := testutil.AdminContext(adminID)

			_, err := actionH.CreateAction(ctx, connect.NewRequest(tc.req))
			require.NoError(t, err)

			resp, err := auditH.ListAuditEvents(ctx, connect.NewRequest(&pm.ListAuditEventsRequest{
				StreamType: "action",
			}))
			require.NoError(t, err)
			require.NotEmpty(t, resp.Msg.Events)

			var sawActionCreated bool
			for _, e := range resp.Msg.Events {
				if e.EventType == "ActionCreated" {
					sawActionCreated = true
				}
				assert.NotContainsf(t, e.Data, tc.secret,
					"secret %q leaked unredacted in audit event %s: %s", tc.secret, e.EventType, e.Data)
			}
			require.True(t, sawActionCreated, "expected an ActionCreated event in the audit log")
		})
	}
}
