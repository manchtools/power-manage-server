package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- fakes -------------------------------------------------------------------

type fakeDB struct {
	pingErr     error
	adminExists bool
	adminErr    error
}

func (f fakeDB) Ping(context.Context) error { return f.pingErr }
func (f fakeDB) AdminUserExists(context.Context, string) (bool, error) {
	return f.adminExists, f.adminErr
}

type fakeCache struct {
	pingErr       error
	missing       []string
	missingErr    error
	schemaCurrent bool
	schemaErr     error
	archived      map[string]int
	archErr       error
}

func (f fakeCache) Ping(context.Context) error { return f.pingErr }
func (f fakeCache) MissingIndexes(context.Context, []string) ([]string, error) {
	return f.missing, f.missingErr
}
func (f fakeCache) SchemaCurrent(context.Context) (bool, error) { return f.schemaCurrent, f.schemaErr }
func (f fakeCache) ArchivedByQueue(context.Context) (map[string]int, error) {
	return f.archived, f.archErr
}

func testEnv(vars map[string]string) *Env {
	e := NewEnv(vars)
	e.Now = func() time.Time { return time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC) }
	return e
}

// a trivial check returning a fixed finding, for engine tests.
type stub struct {
	id string
	f  []Finding
	e  error
}

func (s stub) ID() string { return s.id }
func (s stub) Run(context.Context, *Env) ([]Finding, error) {
	if s.e != nil {
		return nil, s.e
	}
	return s.f, nil
}

// --- engine ------------------------------------------------------------------

func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		rep  Report
		want int
	}{
		{"empty", Report{}, 0},
		{"info only", Report{Findings: []Finding{info("x", "")}}, 0},
		{"warning", Report{Findings: []Finding{warn("x", "", "")}}, 1},
		{"critical", Report{Findings: []Finding{crit("x", "", "")}}, 100},
		{"warning+critical → 100", Report{Findings: []Finding{warn("x", "", ""), crit("y", "", "")}}, 100},
		{"exec error takes precedence over critical → 2", Report{
			Findings:   []Finding{crit("y", "", "")},
			ExecErrors: []ExecError{{ID: "z", Err: "boom"}},
		}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.rep.ExitCode())
		})
	}
}

func TestRun_RecoversPanicAsExecError(t *testing.T) {
	checks := []Check{
		stub{id: "ok", f: []Finding{ok("ok", "fine")}},
		panicCheck{},
	}
	rep := Run(context.Background(), testEnv(nil), checks)
	assert.Len(t, rep.Findings, 1, "the ok check still produced a finding")
	require.Len(t, rep.ExecErrors, 1, "the panicking check became an exec error, not a crash")
	assert.Equal(t, 2, rep.ExitCode(), "exec error → exit 2")
}

type panicCheck struct{}

func (panicCheck) ID() string                                   { return "panic" }
func (panicCheck) Run(context.Context, *Env) ([]Finding, error) { panic("kaboom") }

func TestSeverity_JSONIsString(t *testing.T) {
	b, err := json.Marshal(SeverityCritical)
	require.NoError(t, err)
	assert.Equal(t, `"critical"`, string(b))
}

func TestRenderJSON_ShapeAndExitCode(t *testing.T) {
	rep := Report{
		Findings:   []Finding{crit("secrets", "POSTGRES_PASSWORD is a placeholder", "fix it"), ok("cors", "fine")},
		ExecErrors: []ExecError{{ID: "x", Err: "boom"}},
	}
	var buf bytes.Buffer
	require.NoError(t, RenderJSON(&buf, rep))

	var got struct {
		Summary    map[string]int `json:"summary"`
		Findings   []Finding      `json:"findings"`
		ExecErrors []ExecError    `json:"exec_errors"`
		ExitCode   int            `json:"exit_code"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, 2, got.ExitCode, "exec error → 2")
	assert.Equal(t, 1, got.Summary["critical"])
	assert.Equal(t, 1, got.Summary["ok"])
	require.NotEmpty(t, got.Findings)
	assert.Equal(t, SeverityCritical, got.Findings[0].Severity, "worst-first ordering")
}

// A finding's message names a var but the JSON must never carry the secret VALUE.
func TestRenderJSON_NeverLeaksSecretValue(t *testing.T) {
	const secret = "changeme_DO_NOT_LEAK_THIS_VALUE"
	env := testEnv(map[string]string{"POSTGRES_PASSWORD": secret})
	rep := Run(context.Background(), env, []Check{SecretsCheck{}})
	var buf bytes.Buffer
	require.NoError(t, RenderJSON(&buf, rep))
	assert.NotContains(t, buf.String(), secret, "the secret value must never appear in output")
	assert.Contains(t, buf.String(), "POSTGRES_PASSWORD", "but the variable name is named")
}

func TestRenderHuman_AllClear(t *testing.T) {
	var buf bytes.Buffer
	RenderHuman(&buf, Report{Findings: []Finding{ok("a", ""), ok("b", "")}})
	out := buf.String()
	assert.Contains(t, out, "all checks passed")
	assert.Contains(t, out, "exit 0")
}

func TestRun_ExecErrorFromCheck(t *testing.T) {
	rep := Run(context.Background(), testEnv(nil), []Check{stub{id: "boom", e: errors.New("nope")}})
	require.Len(t, rep.ExecErrors, 1)
	assert.Contains(t, strings.ToLower(rep.ExecErrors[0].Err), "nope")
}
