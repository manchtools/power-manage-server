package archtest

import (
	"go/ast"
	"sort"
	"strings"
	"testing"
)

// TestEventPayloadsAreTyped ratchets the F-05 conversion (#507): event
// emit sites must pass a typed struct from internal/eventtypes/payloads
// as Data, not a map[string]any literal. One shared struct between the
// emit site and the projector decoder catches wire-schema drift at
// compile time; a map literal re-opens the renamed-key / typo'd-key /
// dropped-field class the payloads package exists to close. Spec 19's
// pii:"true" reflection also only works over typed structs — an
// untyped PII emit site is invisible to the crypto layer.
//
// Mechanics: any composite literal carrying BOTH an EventType: and a
// Data: key (store.Event, idp.EventInput — every event-append shape in
// the module) whose Data value is a map composite literal is a legacy
// site. The allowlist below holds the not-yet-converted remainder with
// EXACT per-file counts, so the number can only shrink: a NEW map
// emit anywhere fails, a count above the allowance fails, and a count
// below (someone converted a site) fails too until the entry here is
// shrunk in the same commit — keeping the ratchet honest.
//
// internal/testutil is excluded: factories seed legacy wire shapes on
// purpose and are not production emit sites (drift there fails tests,
// not projections). Assigning a map VARIABLE to Data evades the
// syntactic detector — accepted; review catches it, and the projector
// decode contract still holds.
func TestEventPayloadsAreTyped(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "internal/store/generated/") {
			return false
		}
		if strings.HasPrefix(rel, "internal/testutil/") {
			return false
		}
		return true
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	// The F-05 remainder (issue #507, "broader" checkbox): non-PII emit
	// sites pending package-by-package conversion. Exact counts.
	allowed := map[string]int{
		"internal/api/action_crud.go":               2,
		"internal/api/action_dispatch.go":           1,
		"internal/api/action_set_handler.go":        1,
		"internal/api/compliance_policy_handler.go": 1,
		"internal/api/definition_handler.go":        1,
		"internal/api/device_group_handler.go":      1,
		"internal/api/device_handler.go":            1,
		"internal/api/role_handler.go":              2,
		"internal/api/settings_handler.go":          1,
		"internal/api/system_action_store.go":       1,
		"internal/api/token_handler.go":             2,
		"internal/api/user_group_handler.go":        2,
	}

	sawEmitLiteral := 0 // liveness: every EventType+Data literal, typed or not
	found := map[string][]int{}
	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			dataVal, isEmit := eventDataValue(lit)
			if !isEmit {
				return true
			}
			sawEmitLiteral++
			inner, ok := dataVal.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if _, isMap := inner.Type.(*ast.MapType); isMap {
				found[gf.rel] = append(found[gf.rel], gf.line(inner))
			}
			return true
		})
	}
	if sawEmitLiteral == 0 {
		t.Fatal("matches-zero guard: found no event-append composite literal anywhere — the detector is dead, the guard would pass vacuously")
	}

	for rel, lines := range found {
		sort.Ints(lines)
		switch want := allowed[rel]; {
		case want == 0:
			t.Errorf("untyped event payload: %s lines %v pass a map[string]any literal as Data — use a typed struct from internal/eventtypes/payloads (shared with the projector decoder) instead", rel, lines)
		case len(lines) > want:
			t.Errorf("untyped event payloads grew in %s: %d map-literal Data sites (lines %v), allowance is %d — convert the new site to a typed payloads struct", rel, len(lines), lines, want)
		case len(lines) < want:
			t.Errorf("ratchet stale for %s: %d map-literal Data sites remain (lines %v) but the allowance is %d — shrink the entry in this test to %d", rel, len(lines), lines, want, len(lines))
		}
	}
	for rel, want := range allowed {
		if len(found[rel]) == 0 {
			t.Errorf("ratchet stale: %s is allowed %d map-literal Data sites but has none — delete the entry", rel, want)
		}
	}
}

// eventDataValue reports whether lit is an event-append composite
// literal (it names both EventType: and Data: keys) and returns the
// Data value expression.
func eventDataValue(lit *ast.CompositeLit) (ast.Expr, bool) {
	var dataVal ast.Expr
	hasEventType := false
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		switch identName(kv.Key) {
		case "EventType":
			hasEventType = true
		case "Data":
			dataVal = kv.Value
		}
	}
	if !hasEventType || dataVal == nil {
		return nil, false
	}
	return dataVal, true
}
