// Package dynamicquery implements the dynamic-group query language used
// by device groups (labels + device inventory + group membership) and
// user groups (user attributes). The package replaces the PL/pgSQL
// interpreter from migration 004 (tracker manchtools/power-manage-server#242,
// Wave C of the storage-abstraction roadmap).
//
// The Atom shape is intentionally permissive — fields are parsed as
// arbitrary identifier paths so the lexer / parser stays domain-agnostic.
// Domain semantics (which fields exist, what the operators mean against
// each field) live in the Validate / Evaluate entrypoints.
package dynamicquery

// Op is a binary or unary atom operator.
type Op string

const (
	OpExists      Op = "exists"
	OpNotExists   Op = "notExists"
	OpEquals      Op = "equals"
	OpNotEquals   Op = "notEquals"
	OpContains    Op = "contains"
	OpNotContains Op = "notContains"
	OpStartsWith  Op = "startsWith"
	OpEndsWith    Op = "endsWith"
	OpGT          Op = "greaterThan"
	OpLT          Op = "lessThan"
	OpGTE         Op = "greaterThanOrEquals"
	OpLTE         Op = "lessThanOrEquals"
	OpIn          Op = "in"
	OpNotIn       Op = "notIn"
)

// IsUnary reports whether op takes no value argument.
func (op Op) IsUnary() bool { return op == OpExists || op == OpNotExists }

// IsBinary reports whether op is a value-comparing operator.
func (op Op) IsBinary() bool { return !op.IsUnary() && op != "" }

// Expr is one node of the AST. Concrete types: *And, *Or, *Not, *Atom.
type Expr interface{ exprNode() }

// And is left ⋀ right. Constructed left-associative.
type And struct{ L, R Expr }

// Or is left ⋁ right. Constructed left-associative.
type Or struct{ L, R Expr }

// Not is the unary negation of X.
type Not struct{ X Expr }

// Atom is a leaf condition: <Field> <Op> [<Value>].
//
// Field is the raw identifier path as written (case-preserved). The
// PL/pgSQL extract_label_key helper compares the prefix case-insensitively
// — Validate / Evaluate do the same.
//
// Value is the literal that followed a binary operator: unquoted text,
// or the contents of a double / single-quoted string. Empty for unary
// operators.
type Atom struct {
	Field string
	Op    Op
	Value string
}

func (*And) exprNode()  {}
func (*Or) exprNode()   {}
func (*Not) exprNode()  {}
func (*Atom) exprNode() {}
