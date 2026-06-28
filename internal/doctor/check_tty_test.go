package doctor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runTerminal runs TerminalCheck against vars + cache and fails on a could-not-run.
func runTerminal(t *testing.T, vars map[string]string, cache CacheProbe) []Finding {
	t.Helper()
	env := NewEnv(vars)
	env.Cache = cache
	fs, err := TerminalCheck{}.Run(context.Background(), env)
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

// healthyTerminalVars is a consistent terminal config (distinct TTY host, web
// listener set) for the cases that vary one thing at a time.
func healthyTerminalVars() map[string]string {
	return map[string]string{
		"GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE": "wss://tty.example.com/gw/{id}/terminal",
		"GATEWAY_WEB_LISTEN_ADDR":              ":8443",
		"GATEWAY_DOMAIN":                       "gateway.example.com",
		"GATEWAY_TTY_DOMAIN":                   "tty.example.com",
	}
}

func TestTerminalCheck_DisabledIsInfo(t *testing.T) {
	fs := runTerminal(t, map[string]string{}, fakeCache{})
	require.Len(t, fs, 1)
	assert.Equal(t, SeverityInfo, fs[0].Severity, "terminal unconfigured ⇒ info, not a finding")
}

func TestTerminalCheck_HealthyIsOK(t *testing.T) {
	fs := runTerminal(t, healthyTerminalVars(), fakeCache{keyspaceNotif: "AKE"})
	require.Len(t, fs, 1)
	assert.Equal(t, SeverityOK, fs[0].Severity)
}

func TestTerminalCheck_WebListenAddrMissingWarns(t *testing.T) {
	vars := healthyTerminalVars()
	delete(vars, "GATEWAY_WEB_LISTEN_ADDR")
	fs := runTerminal(t, vars, fakeCache{keyspaceNotif: "AKE"})
	assert.Equal(t, SeverityWarning, worstSev(fs))
	assert.True(t, anyRemediationContains(fs, "GATEWAY_WEB_LISTEN_ADDR"))
}

func TestTerminalCheck_TTYHostCollisionWarns(t *testing.T) {
	// TTY domain falls back to GATEWAY_DOMAIN ⇒ collides with the mTLS host.
	vars := map[string]string{
		"GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE": "wss://gateway.example.com/gw/{id}/terminal",
		"GATEWAY_WEB_LISTEN_ADDR":              ":8443",
		"GATEWAY_DOMAIN":                       "gateway.example.com",
	}
	fs := runTerminal(t, vars, fakeCache{keyspaceNotif: "AKE"})
	assert.Equal(t, SeverityWarning, worstSev(fs))
}

func TestTerminalCheck_KeyspaceNotificationsOffWarns(t *testing.T) {
	// Empty notify-keyspace-events is the Redis default — the field bug.
	fs := runTerminal(t, healthyTerminalVars(), fakeCache{keyspaceNotif: ""})
	assert.Equal(t, SeverityWarning, worstSev(fs))
	assert.True(t, anyRemediationContains(fs, "notify-keyspace-events"),
		"the keyspace warning must name the fix")
}

func TestTerminalCheck_SelfRegisterFalseSkipsKeyspace(t *testing.T) {
	// Notifications off, but the gateway isn't using the KV provider — so Traefik
	// isn't watching it and the keyspace state is irrelevant.
	vars := healthyTerminalVars()
	vars["GATEWAY_TRAEFIK_SELF_REGISTER"] = "false"
	fs := runTerminal(t, vars, fakeCache{keyspaceNotif: ""})
	require.Len(t, fs, 1)
	assert.Equal(t, SeverityOK, fs[0].Severity)
}

func TestTerminalCheck_KeyspaceProbeErrorIsExecError(t *testing.T) {
	env := NewEnv(healthyTerminalVars())
	env.Cache = fakeCache{keyspaceErr: errors.New("CONFIG GET refused")}
	_, err := TerminalCheck{}.Run(context.Background(), env)
	require.Error(t, err, "a reachable-Valkey CONFIG GET failure is a could-not-run (exit 2), not a clean pass")
}

func TestKeyspaceNotificationsSufficient(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"", false},   // Redis default — off
		{"Ex", false}, // keyevent channel but no event class beyond expired
		{"K", false},  // keyspace channel, no event classes
		{"AKE", true}, // canonical form of "KEA"
		{"KEA", true}, // operator's literal value
		{"Kg", true},  // keyspace + generic events
	} {
		assert.Equalf(t, tc.want, keyspaceNotificationsSufficient(tc.val), "notify-keyspace-events=%q", tc.val)
	}
}

func anyRemediationContains(fs []Finding, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f.Remediation, sub) {
			return true
		}
	}
	return false
}
