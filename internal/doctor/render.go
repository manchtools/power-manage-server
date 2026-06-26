package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// jsonReport is the `--json` schema (spec 15, criterion 3).
type jsonReport struct {
	Summary    map[string]int `json:"summary"`
	Findings   []Finding      `json:"findings"`
	ExecErrors []ExecError    `json:"exec_errors,omitempty"`
	ExitCode   int            `json:"exit_code"`
}

// RenderJSON writes the machine-readable report. Findings are worst-first.
func RenderJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		Summary:    r.Counts(),
		Findings:   r.sortedFindings(),
		ExecErrors: r.ExecErrors,
		ExitCode:   r.ExitCode(),
	})
}

// RenderHuman writes the operator-facing report: the actionable findings
// (info/warning/critical) worst-first, any execution errors, then a one-line
// summary ending in the exit code.
func RenderHuman(w io.Writer, r Report) {
	shown := 0
	for _, f := range r.sortedFindings() {
		if f.Severity == SeverityOK {
			continue
		}
		shown++
		fmt.Fprintf(w, "[%s] %s: %s\n", strings.ToUpper(f.Severity.String()), f.ID, f.Message)
		if f.Remediation != "" {
			fmt.Fprintf(w, "    → %s\n", f.Remediation)
		}
		if f.Detail != "" {
			fmt.Fprintf(w, "    (%s)\n", f.Detail)
		}
	}
	for _, e := range r.ExecErrors {
		fmt.Fprintf(w, "[ERROR] %s: could not run — %s\n", e.ID, e.Err)
	}
	if shown == 0 && len(r.ExecErrors) == 0 {
		fmt.Fprintln(w, "No findings — all checks passed.")
	}

	c := r.Counts()
	fmt.Fprintf(w, "\n%d ok · %d info · %d warning · %d critical", c["ok"], c["info"], c["warning"], c["critical"])
	if c["exec_error"] > 0 {
		fmt.Fprintf(w, " · %d could-not-run", c["exec_error"])
	}
	fmt.Fprintf(w, "  →  exit %d\n", r.ExitCode())
}
