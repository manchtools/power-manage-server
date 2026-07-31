package doctor

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runTerminal runs TerminalCheck against vars and fails on a could-not-run.
func runTerminal(t *testing.T, vars map[string]string) []Finding {
	t.Helper()
	fs, err := TerminalCheck{}.Run(context.Background(), NewEnv(vars))
	require.NoError(t, err)
	return fs
}

// worstSev returns the highest severity among findings.
func worstSev(fs []Finding) Severity {
	worst := SeverityOK
	for _, f := range fs {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}

// healthyTerminalVars is the shape a working deployment has: a wss URL on the
// web host, an agent URL on a DIFFERENT host, and Valkey configured so control
// actually mounts the bridge.
func healthyTerminalVars() map[string]string {
	return map[string]string{
		"CONTROL_TERMINAL_URL": "wss://power-manage.example.com/terminal",
		"CONTROL_AGENT_URL":    "https://agents.example.com",
		"CONTROL_VALKEY_ADDR":  "valkey:6379",
	}
}

func TestTerminalCheck_DisabledIsInfo(t *testing.T) {
	fs := runTerminal(t, map[string]string{})
	require.Len(t, fs, 1)
	assert.Equal(t, SeverityInfo, fs[0].Severity, "terminal unconfigured ⇒ info, not a finding")
}

func TestTerminalCheck_HealthyIsOK(t *testing.T) {
	fs := runTerminal(t, healthyTerminalVars())
	require.Len(t, fs, 1)
	assert.Equal(t, SeverityOK, fs[0].Severity)
}

// The failure this check exists for after spec 41: pointing the terminal at the
// agent host puts the browser behind Traefik's TCP-passthrough router, which
// hands it to the mTLS listener and demands a client certificate.
func TestTerminalCheck_TerminalOnAgentHostWarns(t *testing.T) {
	vars := healthyTerminalVars()
	vars["CONTROL_TERMINAL_URL"] = "wss://agents.example.com/terminal"
	fs := runTerminal(t, vars)
	assert.Equal(t, SeverityWarning, worstSev(fs))
	assert.True(t, anyRemediationContains(fs, "CONTROL_DOMAIN"),
		"the collision warning must name the host to move it to")
}

// A terminal URL on a host that merely SHARES a suffix with the agent host is
// fine — only an exact host match is shadowed by the passthrough router.
func TestTerminalCheck_DistinctHostWithSharedSuffixIsOK(t *testing.T) {
	vars := healthyTerminalVars()
	vars["CONTROL_TERMINAL_URL"] = "wss://pm.example.com/terminal"
	vars["CONTROL_AGENT_URL"] = "https://agents.pm.example.com"
	fs := runTerminal(t, vars)
	require.Len(t, fs, 1)
	assert.Equal(t, SeverityOK, fs[0].Severity)
}

func TestTerminalCheck_NonWssSchemeWarns(t *testing.T) {
	vars := healthyTerminalVars()
	vars["CONTROL_TERMINAL_URL"] = "https://power-manage.example.com/terminal"
	fs := runTerminal(t, vars)
	assert.Equal(t, SeverityWarning, worstSev(fs))
}

// The bridge is mounted only when the Valkey token store exists, so a terminal
// URL without Valkey authorises sessions that cannot connect.
func TestTerminalCheck_EnabledWithoutValkeyWarns(t *testing.T) {
	vars := healthyTerminalVars()
	delete(vars, "CONTROL_VALKEY_ADDR")
	fs := runTerminal(t, vars)
	assert.Equal(t, SeverityWarning, worstSev(fs))
	assert.True(t, anyRemediationContains(fs, "CONTROL_VALKEY_ADDR"))
}

func TestTerminalCheck_UnparseableURLWarns(t *testing.T) {
	vars := healthyTerminalVars()
	vars["CONTROL_TERMINAL_URL"] = "wss://%zz"
	fs := runTerminal(t, vars)
	assert.Equal(t, SeverityWarning, worstSev(fs))
}

// The gateway variables this check used to read are gone. If any of them is
// still consulted, a deployment that sets ONLY them would look configured —
// which is exactly how the old check reported "disabled" on every live stack.
func TestTerminalCheck_IgnoresRetiredGatewayVars(t *testing.T) {
	fs := runTerminal(t, map[string]string{
		"GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE": "wss://tty.example.com/gw/{id}/terminal",
		"GATEWAY_WEB_LISTEN_ADDR":              ":8443",
		"GATEWAY_DOMAIN":                       "gateway.example.com",
		"GATEWAY_TTY_DOMAIN":                   "tty.example.com",
		"GATEWAY_TRAEFIK_SELF_REGISTER":        "true",
	})
	require.Len(t, fs, 1)
	assert.Equal(t, SeverityInfo, fs[0].Severity,
		"gateway variables must not enable the terminal — the tier that served it is gone")
}

func anyRemediationContains(fs []Finding, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f.Remediation, sub) {
			return true
		}
	}
	return false
}
