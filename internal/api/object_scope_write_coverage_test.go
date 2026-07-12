package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestObjectMutationHandlers_AllWriteScopeEnforced generalizes the type-level
// object-write guard (TestObjectScope_EnforcementMatchesIndexFiltering, which
// only asserts enforceObjectWriteScope appears SOMEWHERE per object type) to a
// PER-FUNCTION invariant: every function that appends a MUTATION event on a
// scopable object stream MUST call enforceObjectWriteScope for that same object
// type in the same function body.
//
// This is the write-side analog of spec 29 S1 (spec 30 AC 3). The type-level
// guard is a PRESENCE check — one enforced handler satisfies it, so it cannot
// see a SECOND mutation handler that skips the gate. S1 was exactly this shape on
// the read side (ListActions leaked while GetAction satisfied the presence
// check). Here the unit of verification is the (function, object-append) pair,
// DISCOVERED from the store.Event StreamType literal — not a hand-kept list — so
// no object mutation can silently skip write-scope now or in the future.
//
// CREATE is exempt by construction: a <Object>Created event establishes a new
// object with no prior assignment to confine against (mirrors the group-create
// exemption reasoned in scope_enforcement_parity_test.go). The verb is read from
// the eventtypes.<Verb> selector on the EventType field; anything not ending in
// "Created" is treated as a mutation (fail closed — an unrecognized verb requires
// write-scope, so only an explicit *Created literal earns the exemption).
//
// A small allow-list covers the non-RPC internal machinery that legitimately
// mutates an object stream without a user scope to confine (spec 30 "non-RPC
// internal helpers with no externally reachable entry point"). Each entry is
// keyed by "receiver.method|objectType" — receiver-qualified so exempting the
// system-action store's DeleteAction can never suppress a future gap in the
// user-facing ActionHandler.DeleteAction, AND object-type-qualified so an
// exempted function that later gains a SECOND, unrelated mutation of a DIFFERENT
// object type is NOT silently covered by the original entry. The no-orphan block
// below (staleExempt) guards the list against rot.
var objectWriteScopeExempt = map[string]string{
	"systemActionStore.UpdateAction|action":       "system-managed action machinery: ActorType=system, driven by SystemActionManager role-sync with system-chosen action IDs; a scope-restricted user caller can never reach it (user handlers refuse is_system actions).",
	"systemActionStore.DeleteAction|action":       "system-managed action machinery: same as UpdateAction — system-driven lifecycle, no user scope to confine.",
	"ActionHandler.rollbackUnsignedCreate|action": "compensating rollback for CreateAction's signing-failure path; deletes the action the SAME request just created (caller owns it, no prior assignment to confine). The user-facing DeleteAction handler is separately write-scope enforced.",
}

func TestObjectMutationHandlers_AllWriteScopeEnforced(t *testing.T) {
	// The scopable object stream types (assignment-confined). Reuses the canonical
	// registry so a NEW object type is automatically in scope for this guard too.
	objectStreamTypes := map[string]bool{}
	for objType := range objectTypeToIndexScope {
		objectStreamTypes[objType] = true
	}
	require.NotEmpty(t, objectStreamTypes, "no scopable object types discovered — guard would pass vacuously")

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	type miss struct{ fn, objType, event, pos string }
	var misses []miss
	mutationsSeen := 0
	seenExempt := map[string]bool{}

	sawFile := false
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		sawFile = true
		f, perr := parser.ParseFile(fset, name, nil, 0)
		require.NoErrorf(t, perr, "parse %s", name)

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// Within THIS function: object mutations appended, and the object types
			// passed to enforceObjectWriteScope. Enforcement must be co-located with
			// the append (the handlers already do both inline); a refactor that
			// splits them across functions is itself a finding this guard surfaces.
			mutated := map[string]string{} // objType -> first mutation verb (for the message)
			writeScoped := map[string]bool{}
			recordEvent := func(lit *ast.CompositeLit) {
				streamType, verb, okS := eventStreamAndVerb(lit)
				if !okS || !objectStreamTypes[streamType] {
					return
				}
				if strings.HasSuffix(verb, "Created") {
					return // create establishes ownership — nothing to confine
				}
				mutationsSeen++
				if _, exists := mutated[streamType]; !exists {
					mutated[streamType] = verb
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CompositeLit:
					switch {
					case isStoreEventLit(node):
						recordEvent(node)
					case isStoreEventSliceLit(node):
						// []store.Event{{...}, {...}} — Go elides the element type on
						// inner literals, so those inner CompositeLits have Type==nil
						// and are NOT matched as store.Event on their own. Record the
						// elided ones here; explicitly-typed inner literals are matched
						// when ast.Inspect visits them, so skip those to avoid
						// double-processing.
						for _, elt := range node.Elts {
							if inner, ok := elt.(*ast.CompositeLit); ok && inner.Type == nil {
								recordEvent(inner)
							}
						}
					}
				case *ast.CallExpr:
					if calleeName(node.Fun) == "enforceObjectWriteScope" {
						for _, arg := range node.Args {
							if s, ok := stringLit(arg); ok {
								writeScoped[s] = true
								break
							}
						}
					}
				}
				return true
			})
			key := funcKey(fn)
			for objType, verb := range mutated {
				if writeScoped[objType] {
					continue
				}
				exemptKey := key + "|" + objType
				if _, exempt := objectWriteScopeExempt[exemptKey]; exempt {
					seenExempt[exemptKey] = true
					continue
				}
				misses = append(misses, miss{key, objType, verb, fset.Position(fn.Pos()).String()})
			}
		}
	}
	require.True(t, sawFile, "scanned zero source files — discovery is broken")
	require.Positivef(t, mutationsSeen,
		"no object-mutation appends discovered — the guard would pass vacuously (objectTypeToIndexScope or store.Event AST shape drifted)")

	// No-orphan: every exemption must still name a live function that appends an
	// object mutation WITHOUT co-located write-scope. A rename, a removal, or a
	// later addition of enforcement makes the entry stale — fail so the allow-list
	// can't rot into a silent hole (spec 30 AC 7).
	var staleExempt []string
	for key := range objectWriteScopeExempt {
		if !seenExempt[key] {
			staleExempt = append(staleExempt, key)
		}
	}
	sort.Strings(staleExempt)
	require.Emptyf(t, staleExempt,
		"stale objectWriteScopeExempt entries — these no longer name a live object-mutation function missing write-scope (remove or fix the entry):\n  %s",
		strings.Join(staleExempt, "\n  "))

	sort.Slice(misses, func(i, j int) bool {
		if misses[i].fn != misses[j].fn {
			return misses[i].fn < misses[j].fn
		}
		return misses[i].objType < misses[j].objType
	})
	var lines []string
	for _, m := range misses {
		lines = append(lines, m.fn+" appends "+m.event+" ("+m.objType+") without enforceObjectWriteScope(..., \""+m.objType+"\", id) — "+m.pos)
	}
	require.Emptyf(t, lines,
		"object-mutation functions missing write-scope enforcement (spec 29 S1, write side / spec 30 AC 3):\n  %s\n"+
			"Each must call enforceObjectWriteScope(ctx, objScope(h.store), logger, <objectType>, id) in the SAME function that appends the mutation.",
		strings.Join(lines, "\n  "))
}

// isStoreEventLit reports whether the composite literal constructs a store.Event.
func isStoreEventLit(c *ast.CompositeLit) bool {
	return isStoreEventSelector(c.Type)
}

// isStoreEventSliceLit reports whether c is a []store.Event / [N]store.Event
// composite literal — whose inner element literals may elide the store.Event
// element type (so they need explicit handling; see recordEvent's caller).
func isStoreEventSliceLit(c *ast.CompositeLit) bool {
	arr, ok := c.Type.(*ast.ArrayType)
	return ok && isStoreEventSelector(arr.Elt)
}

// isStoreEventSelector reports whether e is the `store.Event` type expression.
func isStoreEventSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "store" && sel.Sel.Name == "Event"
}

// eventStreamAndVerb extracts the StreamType string literal and the EventType
// verb (the eventtypes.<Verb> selector name) from a store.Event composite
// literal. ok is false when there is no StreamType literal to classify.
func eventStreamAndVerb(c *ast.CompositeLit) (streamType, verb string, ok bool) {
	for _, elt := range c.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "StreamType":
			if s, isLit := stringLit(kv.Value); isLit {
				streamType = s
			}
		case "EventType":
			verb = eventTypesSelectorName(kv.Value)
		}
	}
	return streamType, verb, streamType != ""
}

// funcKey identifies a function for exemption keying: "Receiver.Method" for a
// method (the receiver type without its pointer star), or the bare name for a
// free function. Receiver-qualified so exempting systemActionStore.DeleteAction
// can never suppress a gap in the user-facing ActionHandler.DeleteAction.
func funcKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	if id, ok := recv.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// eventTypesSelectorName pulls "ActionRenamed" out of
// `string(eventtypes.ActionRenamed)` (or a bare eventtypes.ActionRenamed).
// Empty when the shape isn't the eventtypes.<Verb> selector — callers treat empty
// as a mutation (fail closed: only an explicit *Created literal earns the
// create exemption).
func eventTypesSelectorName(e ast.Expr) string {
	found := ""
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "eventtypes" {
				found = sel.Sel.Name
				return false
			}
		}
		return true
	})
	return found
}
