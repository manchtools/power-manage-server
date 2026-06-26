// Package doctor runs operator-facing stack-health and security-posture checks
// for a Power Manage Control deployment (#322, spec 15). It is invoked as
// `power-manage-control doctor` — a standalone, read-only pass that reports
// findings with a severity and an exit code, and never mutates state.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// Severity ranks a check result. A *finding* is a Warning or Critical.
type Severity int

const (
	SeverityOK Severity = iota
	SeverityInfo
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityOK:
		return "ok"
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MarshalJSON renders the severity as its string form so `--json` consumers read
// "critical", not an opaque integer.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON parses the string form back to a Severity so the JSON report
// round-trips (e.g. a consumer re-reading it).
func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	switch str {
	case "ok":
		*s = SeverityOK
	case "info":
		*s = SeverityInfo
	case "warning":
		*s = SeverityWarning
	case "critical":
		*s = SeverityCritical
	default:
		return fmt.Errorf("unknown severity %q", str)
	}
	return nil
}

// Finding is one check's verdict. Message/Detail must never contain a secret
// VALUE — name the variable/file and report shape only (spec 15, security).
type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
	Detail      string   `json:"detail,omitempty"`
}

// ok / info / warn / crit are small constructors for check authors.
func ok(id, msg string) Finding   { return Finding{ID: id, Severity: SeverityOK, Message: msg} }
func info(id, msg string) Finding { return Finding{ID: id, Severity: SeverityInfo, Message: msg} }
func warn(id, msg, remediation string) Finding {
	return Finding{ID: id, Severity: SeverityWarning, Message: msg, Remediation: remediation}
}
func crit(id, msg, remediation string) Finding {
	return Finding{ID: id, Severity: SeverityCritical, Message: msg, Remediation: remediation}
}

// Check is one diagnostic. Run returns its verdicts (one or more Findings — a
// passing check returns a single OK finding), or a non-nil error when the check
// could not be EXECUTED at all (→ exit 2), distinct from a check that ran and
// reported a problem. A down datastore is a Finding (Critical), not an exec error.
type Check interface {
	ID() string
	Run(ctx context.Context, env *Env) ([]Finding, error)
}

// ExecError records a check that could not run.
type ExecError struct {
	ID  string `json:"id"`
	Err string `json:"error"`
}

// Report is the outcome of a run.
type Report struct {
	Findings   []Finding   `json:"findings"`
	ExecErrors []ExecError `json:"exec_errors,omitempty"`
}

// Run executes every check against env, recovering panics into ExecErrors so one
// broken check never aborts the suite. Findings keep their declared order
// stabilised by severity for rendering.
func Run(ctx context.Context, env *Env, checks []Check) Report {
	var rep Report
	for _, c := range checks {
		fs, err := runOne(ctx, env, c)
		if err != nil {
			rep.ExecErrors = append(rep.ExecErrors, ExecError{ID: c.ID(), Err: err.Error()})
			continue
		}
		rep.Findings = append(rep.Findings, fs...)
	}
	return rep
}

// runOne wraps a single check with panic recovery; a panic becomes an execution
// error (the check "could not run").
func runOne(ctx context.Context, env *Env, c Check) (fs []Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return c.Run(ctx, env)
}

// Worst returns the highest severity among findings (ignores exec errors).
func (r Report) Worst() Severity {
	worst := SeverityOK
	for _, f := range r.Findings {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}

// ExitCode encodes the worst outcome (spec 15, criterion 2):
//   - 2  any check could-not-run (exec error) — highest precedence: the report is
//     incomplete, so "fix the doctor/config" is the first action;
//   - 100 any Critical finding;
//   - 1  worst finding is Warning;
//   - 0  ok/info only.
func (r Report) ExitCode() int {
	if len(r.ExecErrors) > 0 {
		return 2
	}
	switch r.Worst() {
	case SeverityCritical:
		return 100
	case SeverityWarning:
		return 1
	default:
		return 0
	}
}

// Counts returns the number of findings per severity name (for the summary).
func (r Report) Counts() map[string]int {
	out := map[string]int{}
	for _, f := range r.Findings {
		out[f.Severity.String()]++
	}
	if len(r.ExecErrors) > 0 {
		out["exec_error"] = len(r.ExecErrors)
	}
	return out
}

// sortedFindings returns findings worst-first, then by id, for stable rendering.
func (r Report) sortedFindings() []Finding {
	out := append([]Finding(nil), r.Findings...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].ID < out[j].ID
	})
	return out
}
