package dynamicquery_test

import (
	"testing"

	"github.com/manchtools/power-manage/server/internal/dynamicquery"
)

// FuzzParse exercises the dynamic-query parser against arbitrary
// input. The contract is "never panic": well-formed queries return an
// AST, malformed queries return an error, and *every* input — including
// adversarial UTF-8, deeply nested parens, unbalanced quotes, embedded
// keywords, control characters — must do one or the other. A panic
// here is a parser bug and a denial-of-service vector (the
// ValidateDynamicQuery RPC is admin-only but the same parser also runs
// inside dyngroupeval, which is invoked from the inbox worker / cron
// loop without an explicit user trigger).
//
// The seed corpus covers each grammar production from the table-driven
// happy-path test plus a handful of known boundary cases (deeply nested
// parens, surrogate-pair UTF-8, etc.) so the fuzzer starts from
// guidance rather than only random bytes.
func FuzzParse(f *testing.F) {
	for _, q := range []string{
		``,
		`labels.env equals "production"`,
		`device.labels["my key"] equals "val"`,
		`labels.a equals "1" and labels.b equals "2" or labels.c equals "3"`,
		`(labels.a equals "1" or labels.b equals "2") and labels.c equals "3"`,
		`not labels.role equals "broken"`,
		`labels.environment exists`,
		`device.group in "A,B,C"`,
		`labels.note equals "she said \"hi\""`,
		`user.email equals "alice@example.com"`,
		// Adversarial seeds the parser must handle without panic.
		`((((((((((`,
		`not not not not not`,
		`labels.x equals "` + "\x00\x01\x02" + `"`,
		`labels.🚀 equals "🌍"`,
	} {
		f.Add(q)
	}

	f.Fuzz(func(t *testing.T, q string) {
		// Cap the input so a pathological corpus entry doesn't burn
		// the whole fuzz budget on one case. The handler-side validator
		// limits queries to 10 KB; we stay well under that to keep the
		// per-iteration budget low.
		if len(q) > 4096 {
			return
		}
		// The only contract here is "doesn't panic" — both Parse paths
		// (returns Expr / returns error) are valid outcomes.
		_, _ = dynamicquery.Parse(q)
	})
}

// FuzzEvaluateDevice round-trips a fuzzed query through Parse +
// EvaluateDevice with a fixed device context. The contract is the
// same as FuzzParse — never panic — but adds coverage for the
// evaluator's path: every node type that the parser can produce must
// also be evaluable without panicking. The fixed context exercises
// label lookups, inventory fields, and the device-group set; the
// fuzzer varies the query string, not the context.
func FuzzEvaluateDevice(f *testing.F) {
	for _, q := range []string{
		`labels.env equals "production"`,
		`labels.team contains "platform"`,
		`labels.role notEquals "broken"`,
		`device.os equals "linux" and labels.env equals "prod"`,
		`not device.os equals "windows"`,
		`device.group in "alpha,beta"`,
		`device.labels.region exists`,
		`device.hostname startsWith "web-"`,
		`device.kernel endsWith ".rt"`,
	} {
		f.Add(q)
	}

	inventory := map[string]string{
		"hostname": "web-01",
		"os":       "linux",
		"kernel":   "6.6.0-rt",
	}
	ctx := dynamicquery.DeviceContext{
		DeviceID: "01J0000000000000000000DEVICE",
		Labels: map[string]string{
			"env":    "production",
			"team":   "platform infra",
			"role":   "frontend",
			"region": "eu-central",
		},
		Inventory: func(field string) (string, bool) {
			v, ok := inventory[field]
			return v, ok
		},
		GroupNames: []string{"alpha"},
	}

	f.Fuzz(func(t *testing.T, q string) {
		if len(q) > 4096 {
			return
		}
		expr, err := dynamicquery.Parse(q)
		if err != nil {
			return // parser-rejected inputs are not evaluator's concern
		}
		// The only contract here is "doesn't panic". The boolean
		// result of evaluation is not asserted — we're fuzzing for
		// crashes / out-of-bounds index / nil-deref, not semantics.
		_ = dynamicquery.EvaluateDevice(expr, ctx)
	})
}
