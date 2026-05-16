package dynamicquery

import (
	"strconv"
	"strings"
)

// DeviceContext is the pre-loaded device state the device-query
// evaluator reads. Callers (per-group eval in C.3, queue drain in C.4)
// build one of these per device before walking the AST.
//
// Labels keeps the keys raw (case-preserved at write); lookups go
// through Label() which applies the case-insensitive match the PL/pgSQL
// `device_labels ? key` operator implicitly did (PG JSONB keys are
// case-sensitive, but the dynamic-query string is matched
// case-insensitively against the field path). Use Label("env") with
// the post-extract_label_key key.
//
// Inventory is a function rather than a map so the C.3 caller can
// lazy-load inventory fields by name — building the full row up-front
// would be wasteful when most queries touch zero or one field.
//
// GroupNames is the snapshot of group memberships at evaluation time.
// device.group equals / contains / in / notIn match against this list
// case-insensitively.
type DeviceContext struct {
	DeviceID   string
	Labels     map[string]string
	Inventory  func(field string) (string, bool)
	GroupNames []string
}

// Label looks up a label by key, case-insensitive (PL/pgSQL did the
// equivalent via lower() comparisons in evaluate_condition).
func (c DeviceContext) Label(key string) (string, bool) {
	if v, ok := c.Labels[key]; ok {
		return v, true
	}
	for k, v := range c.Labels {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// UserContext mirrors the 7 user fields evaluate_user_condition reads.
// Boolean fields are serialized to "true" / "false" for binary
// operators (matches PL/pgSQL's `user_disabled::TEXT` cast).
type UserContext struct {
	Email             string
	Disabled          bool
	TotpEnabled       bool
	HasPassword       bool
	DisplayName       string
	PreferredUsername string
	Locale            string
}

// EvaluateDevice evaluates expr against ctx. Matches the PL/pgSQL
// evaluate_dynamic_query_v2 / evaluate_condition_v2 semantics.
func EvaluateDevice(expr Expr, ctx DeviceContext) bool {
	return walkEval(expr, func(a *Atom) bool { return evalDeviceAtom(a, ctx) })
}

// EvaluateUser evaluates expr against ctx. Matches the PL/pgSQL
// evaluate_dynamic_user_query / evaluate_user_condition semantics.
func EvaluateUser(expr Expr, ctx UserContext) bool {
	return walkEval(expr, func(a *Atom) bool { return evalUserAtom(a, ctx) })
}

// walkEval recursively evaluates a boolean expression tree, deferring
// atom semantics to the provided closure. AND short-circuits on FALSE,
// OR on TRUE — matches PL/pgSQL's EXIT-on-mismatch loop.
func walkEval(root Expr, atom func(*Atom) bool) bool {
	switch n := root.(type) {
	case *And:
		return walkEval(n.L, atom) && walkEval(n.R, atom)
	case *Or:
		return walkEval(n.L, atom) || walkEval(n.R, atom)
	case *Not:
		return !walkEval(n.X, atom)
	case *Atom:
		if n.Field == "" {
			// Empty / always-true placeholder produced by Parse("").
			return true
		}
		return atom(n)
	}
	// Unreachable: the parser only emits the four node types above.
	return false
}

// evalDeviceAtom matches evaluate_condition_v2's three-way dispatch:
// device.group, device.<inventory>, then labels.
func evalDeviceAtom(a *Atom, ctx DeviceContext) bool {
	low := strings.ToLower(a.Field)

	switch {
	case low == "device.group":
		return evalDeviceGroup(a, ctx.GroupNames)
	case strings.HasPrefix(low, "device.labels.") ||
		strings.HasPrefix(low, "labels.") ||
		strings.HasPrefix(low, "device.labels[") ||
		strings.HasPrefix(low, "labels["):
		key := extractLabelKey(a.Field)
		val, ok := ctx.Label(key)
		return applyStringOp(a.Op, val, ok, a.Value)
	case strings.HasPrefix(low, "device."):
		field := strings.TrimPrefix(strings.TrimPrefix(a.Field, "device."), "Device.")
		var (
			val string
			ok  bool
		)
		if ctx.Inventory != nil {
			val, ok = ctx.Inventory(field)
		}
		return applyStringOp(a.Op, val, ok, a.Value)
	}
	// Fallback: treat the raw field as a label key (PL/pgSQL
	// extract_label_key returned the unchanged expression for
	// unrecognized prefixes; evaluate_condition then looked it up as
	// a label key, which usually missed and returned FALSE).
	val, ok := ctx.Label(a.Field)
	return applyStringOp(a.Op, val, ok, a.Value)
}

// evalDeviceGroup handles `device.group <op> <value>` against the
// list of group names the device currently belongs to. PL/pgSQL didn't
// implement startsWith/endsWith/numeric compare for this field —
// neither do we.
func evalDeviceGroup(a *Atom, groupNames []string) bool {
	hasMembership := len(groupNames) > 0

	switch a.Op {
	case OpExists:
		return hasMembership
	case OpNotExists:
		return !hasMembership
	}

	if !hasMembership {
		// PL/pgSQL: "negative" operators flip to TRUE on no membership.
		switch a.Op {
		case OpNotEquals, OpNotContains, OpNotIn:
			return true
		default:
			return false
		}
	}

	value := strings.ToLower(a.Value)
	switch a.Op {
	case OpEquals:
		for _, g := range groupNames {
			if strings.EqualFold(g, a.Value) {
				return true
			}
		}
		return false
	case OpNotEquals:
		for _, g := range groupNames {
			if strings.EqualFold(g, a.Value) {
				return false
			}
		}
		return true
	case OpContains:
		for _, g := range groupNames {
			if strings.Contains(strings.ToLower(g), value) {
				return true
			}
		}
		return false
	case OpNotContains:
		for _, g := range groupNames {
			if strings.Contains(strings.ToLower(g), value) {
				return false
			}
		}
		return true
	case OpIn:
		for _, name := range splitTrimLower(a.Value, ",") {
			for _, g := range groupNames {
				if strings.EqualFold(g, name) {
					return true
				}
			}
		}
		return false
	case OpNotIn:
		for _, name := range splitTrimLower(a.Value, ",") {
			for _, g := range groupNames {
				if strings.EqualFold(g, name) {
					return false
				}
			}
		}
		return true
	}
	return false
}

// evalUserAtom matches evaluate_user_condition's 7-field whitelist.
// Booleans are converted to "true" / "false" for binary operators —
// the PL/pgSQL `user_disabled::TEXT` cast produced lowercase strings.
func evalUserAtom(a *Atom, ctx UserContext) bool {
	field := strings.ToLower(a.Field)

	switch a.Op {
	case OpExists:
		switch field {
		case "user.email":
			return ctx.Email != ""
		case "user.disabled", "user.totp_enabled", "user.has_password":
			return true
		case "user.display_name":
			return ctx.DisplayName != ""
		case "user.preferred_username":
			return ctx.PreferredUsername != ""
		case "user.locale":
			return ctx.Locale != ""
		}
		return false
	case OpNotExists:
		switch field {
		case "user.email":
			return ctx.Email == ""
		case "user.display_name":
			return ctx.DisplayName == ""
		case "user.preferred_username":
			return ctx.PreferredUsername == ""
		case "user.locale":
			return ctx.Locale == ""
		}
		return false
	}

	val, ok := userFieldValue(field, ctx)
	if !ok {
		// Unknown field — PL/pgSQL returned FALSE.
		return false
	}
	return applyStringOp(a.Op, val, true, a.Value)
}

// userFieldValue resolves a user.<field> to its string representation,
// or returns ok=false for unknown fields. Boolean fields use "true" /
// "false" so binary comparisons match the PL/pgSQL ::TEXT cast.
func userFieldValue(field string, ctx UserContext) (string, bool) {
	switch field {
	case "user.email":
		return ctx.Email, true
	case "user.disabled":
		return strconv.FormatBool(ctx.Disabled), true
	case "user.totp_enabled":
		return strconv.FormatBool(ctx.TotpEnabled), true
	case "user.has_password":
		return strconv.FormatBool(ctx.HasPassword), true
	case "user.display_name":
		return ctx.DisplayName, true
	case "user.preferred_username":
		return ctx.PreferredUsername, true
	case "user.locale":
		return ctx.Locale, true
	}
	return "", false
}

// applyStringOp implements the binary / unary semantics evaluate_condition
// and evaluate_user_condition share. The PL/pgSQL "NULL field" branches
// map to !present here — present=false short-circuits "negative" ops to
// TRUE and "positive" ops to FALSE.
func applyStringOp(op Op, fieldValue string, present bool, value string) bool {
	switch op {
	case OpExists:
		return present
	case OpNotExists:
		return !present
	}

	if !present {
		switch op {
		case OpNotEquals, OpNotContains, OpNotIn:
			return true
		default:
			return false
		}
	}

	lowField := strings.ToLower(fieldValue)
	lowValue := strings.ToLower(value)

	switch op {
	case OpEquals:
		return lowField == lowValue
	case OpNotEquals:
		return lowField != lowValue
	case OpContains:
		return strings.Contains(lowField, lowValue)
	case OpNotContains:
		return !strings.Contains(lowField, lowValue)
	case OpStartsWith:
		return strings.HasPrefix(lowField, lowValue)
	case OpEndsWith:
		return strings.HasSuffix(lowField, lowValue)
	case OpGT, OpLT, OpGTE, OpLTE:
		return compareOp(op, fieldValue, value)
	case OpIn:
		for _, candidate := range splitTrimLower(value, ",") {
			if lowField == candidate {
				return true
			}
		}
		return false
	case OpNotIn:
		for _, candidate := range splitTrimLower(value, ",") {
			if lowField == candidate {
				return false
			}
		}
		return true
	}
	return false
}

// compareOp handles the four ordering operators. PL/pgSQL tried numeric
// first, fell back to lexicographic on cast failure — mirrored here so
// values like "v1.2" and "v1.10" don't compare as numbers and accidentally
// flip ordering.
func compareOp(op Op, a, b string) bool {
	if na, err := strconv.ParseFloat(a, 64); err == nil {
		if nb, err := strconv.ParseFloat(b, 64); err == nil {
			switch op {
			case OpGT:
				return na > nb
			case OpLT:
				return na < nb
			case OpGTE:
				return na >= nb
			case OpLTE:
				return na <= nb
			}
		}
	}
	switch op {
	case OpGT:
		return a > b
	case OpLT:
		return a < b
	case OpGTE:
		return a >= b
	case OpLTE:
		return a <= b
	}
	return false
}

// extractLabelKey strips the prefix/bracket form to return the bare
// label key. Mirrors the PL/pgSQL extract_label_key function.
func extractLabelKey(fieldExpr string) string {
	low := strings.ToLower(fieldExpr)
	switch {
	case strings.HasPrefix(low, "device.labels."):
		return fieldExpr[len("device.labels."):]
	case strings.HasPrefix(low, "labels."):
		return fieldExpr[len("labels."):]
	case strings.HasPrefix(low, "device.labels["):
		return trimBracketKey(fieldExpr[len("device.labels"):])
	case strings.HasPrefix(low, "labels["):
		return trimBracketKey(fieldExpr[len("labels"):])
	}
	return fieldExpr
}

// trimBracketKey turns `["env"]` or `[env]` into `env`. Whitespace is
// trimmed; surrounding single or double quotes are stripped.
func trimBracketKey(bracketed string) string {
	s := strings.TrimSpace(bracketed)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		first := s[0]
		last := s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			s = s[1 : len(s)-1]
		}
	}
	return s
}

// splitTrimLower splits s on sep, trims each part, and returns the
// lowered slice. Empty values are kept (PL/pgSQL string_to_array did
// the same — though no real query has the trailing comma form).
func splitTrimLower(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.ToLower(strings.TrimSpace(p))
	}
	return out
}
