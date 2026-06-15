package projectors_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// WS16b: decodePayload is the single-source projector payload decoder. This
// self-discovering guard makes the *specific* duplication it replaces —
// hand-rolling json.Unmarshal of an event payload inside a projector decoder —
// structurally impossible to reintroduce: every `*FromEvent` function in this
// package must either route its decode through decodePayload (so it carries no
// direct json.Unmarshal) or be a recorded exception below. A new standard
// decoder that hand-rolls the decode fails this test; an exception that is
// later collapsed onto decodePayload makes its allowlist entry stale and also
// fails it.
//
// The allowlist is the set of `*FromEvent` decoders that legitimately call
// json.Unmarshal directly:
//   - empty payload is VALID: the event carries no body and the decoder
//     returns an envelope-derived default on len(e.Data)==0 (decodePayload
//     rejects empty), then decodes when a body is present; and
//   - non-canonical shape: the decoder builds a DB-params/struct keyed off the
//     envelope with its own validation, not the payload-struct + canonical
//     error form decodePayload provides.
//
// Decoders that don't decode JSON at all, or that route their decode through a
// shared per-cluster sub-decoder (decodeDeviceUserAssignment, decodeTerminal,
// decodeLuksRevocation, decodeUserGroupMember, …), carry no direct
// json.Unmarshal and so are neither flagged nor allowlisted.
var decodePayloadHandRolledAllowlist = map[string]bool{
	// empty-payload-valid (rule: returns an envelope-derived default on empty)
	"ActionDescriptionUpdatedFromEvent":           true,
	"ActionParamsUpdatedFromEvent":                true,
	"ActionSetDescriptionUpdatedFromEvent":        true,
	"ActionSetScheduleUpdatedFromEvent":           true,
	"AssignmentModeChangedFromEvent":              true,
	"AssignmentSortOrderChangedFromEvent":         true,
	"CompliancePolicyDescriptionUpdatedFromEvent": true,
	"DefinitionDescriptionUpdatedFromEvent":       true,
	"DefinitionScheduleUpdatedFromEvent":          true,
	"DeviceSeenFromEvent":                         true,
	"DeviceHeartbeatFromEvent":                    true,
	"DeviceLabelsUpdatedFromEvent":                true,
	"DeviceSyncIntervalSetFromEvent":              true,
	"DeviceGroupDescriptionUpdatedFromEvent":      true,
	"DeviceGroupQueryUpdatedFromEvent":            true,
	"DeviceGroupSyncIntervalSetFromEvent":         true,
	"DeviceGroupMaintenanceWindowSetFromEvent":    true,
	"ExecutionTimedOutFromEvent":                  true,
	"IdentityProviderUpdatedFromEvent":            true,
	"RoleUpdatedFromEvent":                        true,
	"ServerSettingsUpdatedFromEvent":              true,
	"UserProfileUpdatedFromEvent":                 true,
	"UserSshSettingsUpdatedFromEvent":             true,
	"UserProvisioningSettingsUpdatedFromEvent":    true,
	"UserGroupQueryUpdatedFromEvent":              true,
	"UserGroupMaintenanceWindowSetFromEvent":      true,
	"UserGroupMembersRebuiltFromEvent":            true,
	// non-canonical shape (rule: builds DB-params/struct keyed off the envelope)
	"SecurityAlertProjectionFromEvent": true,
	"SecurityAlertAckParamsFromEvent":  true,
	// multi-stream / runtime-eventType: decodePayload takes a single fixed
	// (streamType, eventType); these accept two stream types or a runtime
	// eventType param, so the fixed-arg helper cannot express their guard.
	"DefinitionCreatedFromEvent": true, // streams "definition" OR "action"
	"DefinitionRenamedFromEvent": true, // streams "definition" OR "action"
	"SCIMTokenFromEvent":         true, // eventType is a runtime parameter
}

func TestDecodePayloadHelperUsedByAllProjectors(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read projectors dir: %v", err)
	}

	var fromEventFns int
	var sawDecodePayload bool
	handRolled := map[string]bool{} // *FromEvent funcs with a direct json.Unmarshal

	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasSuffix(fn.Name.Name, "FromEvent") {
				continue
			}
			fromEventFns++
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				// decodePayload[...](...) — the Fun is an IndexExpr/IndexListExpr
				// whose base is the Ident "decodePayload".
				switch fun := call.Fun.(type) {
				case *ast.IndexExpr:
					if id, ok := fun.X.(*ast.Ident); ok && id.Name == "decodePayload" {
						sawDecodePayload = true
					}
				case *ast.IndexListExpr:
					if id, ok := fun.X.(*ast.Ident); ok && id.Name == "decodePayload" {
						sawDecodePayload = true
					}
				case *ast.SelectorExpr:
					if pkg, ok := fun.X.(*ast.Ident); ok && pkg.Name == "json" && fun.Sel.Name == "Unmarshal" {
						handRolled[fn.Name.Name] = true
					}
				}
				return true
			})
		}
	}

	// Matches-zero guards: the walk must reach real code.
	if fromEventFns < 50 {
		t.Fatalf("matches-zero guard: only %d *FromEvent decoders found — the AST walk is mis-scoped", fromEventFns)
	}
	if !sawDecodePayload {
		t.Fatal("matches-zero guard: no decoder uses decodePayload — the helper is unused, the guard would be vacuous")
	}

	// Every hand-rolled decode must be a recorded exception.
	var unexpected []string
	for fn := range handRolled {
		if !decodePayloadHandRolledAllowlist[fn] {
			unexpected = append(unexpected, fn)
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Errorf("these *FromEvent decoders hand-roll json.Unmarshal instead of routing through decodePayload "+
			"(use decodePayload[T], or if the payload is legitimately empty-valid / non-canonical add them to "+
			"decodePayloadHandRolledAllowlist with a reason): %v", unexpected)
	}

	// No stale allowlist entry: every entry must still be a hand-rolling decoder.
	var stale []string
	for fn := range decodePayloadHandRolledAllowlist {
		if !handRolled[fn] {
			stale = append(stale, fn)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("stale decodePayloadHandRolledAllowlist entries (the function was removed or now routes through "+
			"decodePayload — delete the entry): %v", stale)
	}
}
