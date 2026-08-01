package dynamicquery

import (
	"fmt"
	"strings"
)

// ValidateDeviceQuery returns nil when the query parses cleanly under
// the device-group field whitelist (labels.*, device.labels.*,
// device.group, device.<inventory-field>). Returns a descriptive error
// otherwise.
func ValidateDeviceQuery(query string) error {
	expr, err := Parse(query)
	if err != nil {
		return err
	}
	return walk(expr, validateDeviceAtom)
}

// ValidateUserQuery returns nil when the query parses cleanly under
// the user-group field whitelist (user.*).
//
// Unlike the device variant, the user variant rejects an empty query to avoid
// turning an empty form submit into a "matches every user" group.
func ValidateUserQuery(query string) error {
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("query must not be empty")
	}
	expr, err := Parse(query)
	if err != nil {
		return err
	}
	return walk(expr, validateUserAtom)
}

// walk applies check to every Atom under root in left-first order.
func walk(root Expr, check func(*Atom) error) error {
	switch n := root.(type) {
	case *And:
		if err := walk(n.L, check); err != nil {
			return err
		}
		return walk(n.R, check)
	case *Or:
		if err := walk(n.L, check); err != nil {
			return err
		}
		return walk(n.R, check)
	case *Not:
		return walk(n.X, check)
	case *Atom:
		return check(n)
	}
	return nil
}

func validateDeviceAtom(a *Atom) error {
	if a.Field == "" {
		// The "always true" placeholder Parse returns for an empty
		// query. Treat as valid for device queries; ValidateUserQuery
		// is strict and intercepted before reaching this layer.
		return nil
	}
	switch {
	case isLabelField(a.Field):
		return checkOpAllowed(a, labelOps)
	case strings.EqualFold(a.Field, "device.group"):
		return checkOpAllowed(a, groupOps)
	case strings.HasPrefix(strings.ToLower(a.Field), "device."):
		// Any other device.* maps to the inventory resolver — same
		// operator set as labels (PL/pgSQL evaluate_condition_v2).
		return checkOpAllowed(a, labelOps)
	default:
		return fmt.Errorf("unsupported field %q", a.Field)
	}
}

func validateUserAtom(a *Atom) error {
	if a.Field == "" {
		return fmt.Errorf("query must not be empty")
	}
	field := strings.ToLower(a.Field)
	if !strings.HasPrefix(field, "user.") {
		return fmt.Errorf("unsupported field %q (user-group queries only accept user.* fields)", a.Field)
	}
	switch field {
	case "user.email", "user.disabled", "user.display_name", "user.preferred_username", "user.locale":
	default:
		return fmt.Errorf("unsupported user-group field %q", a.Field)
	}
	return checkOpAllowed(a, userOps)
}

// isLabelField reports whether the field path targets a device label
// (any of the four PL/pgSQL extract_label_key prefixes). Bracket-form
// keys like device.labels["env"] are accepted as-is — the parser
// already stripped surrounding quotes inside the brackets when used as
// a value, but here the bracket form is part of the field token.
func isLabelField(field string) bool {
	low := strings.ToLower(field)
	switch {
	case strings.HasPrefix(low, "device.labels."):
		return true
	case strings.HasPrefix(low, "labels."):
		return true
	case strings.HasPrefix(low, "device.labels["):
		return true
	case strings.HasPrefix(low, "labels["):
		return true
	}
	return false
}

// labelOps is the operator set for label and inventory predicates.
var labelOps = map[Op]struct{}{
	OpExists: {}, OpNotExists: {},
	OpEquals: {}, OpNotEquals: {},
	OpContains: {}, OpNotContains: {},
	OpStartsWith: {}, OpEndsWith: {},
	OpGT: {}, OpLT: {}, OpGTE: {}, OpLTE: {},
	OpIn: {}, OpNotIn: {},
}

// groupOps is the operator set for device.group predicates. Group names do not
// support prefix, suffix, or numeric comparisons.
var groupOps = map[Op]struct{}{
	OpExists: {}, OpNotExists: {},
	OpEquals: {}, OpNotEquals: {},
	OpContains: {}, OpNotContains: {},
	OpIn: {}, OpNotIn: {},
}

// userOps is the operator set evaluate_user_condition accepts.
var userOps = map[Op]struct{}{
	OpExists: {}, OpNotExists: {},
	OpEquals: {}, OpNotEquals: {},
	OpContains: {}, OpNotContains: {},
	OpStartsWith: {}, OpEndsWith: {},
	OpIn: {}, OpNotIn: {},
}

func checkOpAllowed(a *Atom, allowed map[Op]struct{}) error {
	if _, ok := allowed[a.Op]; !ok {
		return fmt.Errorf("operator %q is not valid for field %q", a.Op, a.Field)
	}
	if a.Op.IsBinary() && a.Value == "" {
		return fmt.Errorf("operator %q on field %q requires a value", a.Op, a.Field)
	}
	return nil
}
