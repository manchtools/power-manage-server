package dynamicquery

import (
	"fmt"
	"strings"
	"unicode"
)

// Parse turns a query string into an AST. The grammar:
//
//	query   := or
//	or      := and ('or' and)*
//	and     := not ('and' not)*
//	not     := 'not' not | primary
//	primary := '(' or ')' | atom
//	atom    := FIELD (UNARY_OP | BINARY_OP VALUE)
//
// AND binds tighter than OR (the conventional precedence; PL/pgSQL's
// substitution-based parser had the opposite, but every existing query
// in production parses identically under either rule once you read
// PL/pgSQL's actual evaluation order). NOT binds tighter than AND.
//
// Whitespace is the keyword separator. FIELD is any contiguous run of
// non-whitespace, non-paren characters that doesn't start with a quote.
// VALUE is either a single / double-quoted string (the quote determines
// the delimiter; backslash escape supported for the delimiter itself)
// or the remainder of the atom up to the next AND/OR/closing paren.
//
// An empty / whitespace-only query is treated as the always-true tree.
func Parse(query string) (Expr, error) {
	p := &parser{src: query}
	p.skipSpace()
	if p.atEnd() {
		// Empty query parses to a no-op atom that always matches.
		// Matches the PL/pgSQL behaviour where an empty condition
		// is treated as TRUE.
		return &Atom{}, nil
	}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if !p.atEnd() {
		return nil, p.errorf("unexpected trailing content %q", p.src[p.pos:])
	}
	return expr, nil
}

// maxParseDepth caps recursion depth across parseOr / parseAnd /
// parseNot / parsePrimary. Adversarial inputs like `not not not ...`
// or `(((((... )))))` would otherwise consume one Go stack frame per
// nesting level — at ~20 KB per frame, ~100 K nested tokens (well
// within the 10 K-char query length used in production) would
// stack-overflow the process. 100 is comfortably above any
// human-authored query's nesting depth.
const maxParseDepth = 100

type parser struct {
	src   string
	pos   int
	depth int
}

func (p *parser) atEnd() bool { return p.pos >= len(p.src) }

// enterDepth increments the recursion counter and reports an error
// when the cap is exceeded. Pair every call with a `defer p.exitDepth()`
// — the leaveDepth helper symmetry mirrors how Go callers typically
// shape their own depth guards.
func (p *parser) enterDepth() error {
	if p.depth >= maxParseDepth {
		return p.errorf("query nesting depth exceeds %d", maxParseDepth)
	}
	p.depth++
	return nil
}

func (p *parser) exitDepth() { p.depth-- }

func (p *parser) peek() byte {
	if p.atEnd() {
		return 0
	}
	return p.src[p.pos]
}

func (p *parser) skipSpace() {
	for !p.atEnd() && unicode.IsSpace(rune(p.src[p.pos])) {
		p.pos++
	}
}

func (p *parser) errorf(format string, args ...any) error {
	return fmt.Errorf("dynamicquery: pos %d: %s", p.pos, fmt.Sprintf(format, args...))
}

func (p *parser) parseOr() (Expr, error) {
	if err := p.enterDepth(); err != nil {
		return nil, err
	}
	defer p.exitDepth()
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.matchKeyword("or") {
			return left, nil
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &Or{L: left, R: right}
	}
}

func (p *parser) parseAnd() (Expr, error) {
	if err := p.enterDepth(); err != nil {
		return nil, err
	}
	defer p.exitDepth()
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.matchKeyword("and") {
			return left, nil
		}
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &And{L: left, R: right}
	}
}

func (p *parser) parseNot() (Expr, error) {
	if err := p.enterDepth(); err != nil {
		return nil, err
	}
	defer p.exitDepth()
	p.skipSpace()
	if p.matchKeyword("not") {
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &Not{X: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Expr, error) {
	if err := p.enterDepth(); err != nil {
		return nil, err
	}
	defer p.exitDepth()
	p.skipSpace()
	if p.atEnd() {
		return nil, p.errorf("expected condition or '(' but reached end of query")
	}
	if p.peek() == '(' {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.atEnd() || p.peek() != ')' {
			return nil, p.errorf("expected ')' to close grouping")
		}
		p.pos++
		return inner, nil
	}
	return p.parseAtom()
}

func (p *parser) parseAtom() (*Atom, error) {
	field := p.consumeFieldOrValueToken()
	if field == "" {
		return nil, p.errorf("expected a field name")
	}
	p.skipSpace()

	op, err := p.consumeOperator()
	if err != nil {
		return nil, err
	}

	if op.IsUnary() {
		return &Atom{Field: field, Op: op}, nil
	}

	// Binary op — consume the value.
	p.skipSpace()
	if p.atEnd() {
		return nil, p.errorf("operator %q requires a value", op)
	}
	value, err := p.consumeValue()
	if err != nil {
		return nil, err
	}
	return &Atom{Field: field, Op: op, Value: value}, nil
}

// consumeFieldOrValueToken reads a contiguous run of non-whitespace,
// non-paren characters. Quoted content inside a bracket subscript
// (device.labels["my key"]) is consumed in full — the PL/pgSQL
// extract_label_key helper accepted that form for label keys with
// spaces in them.
func (p *parser) consumeFieldOrValueToken() string {
	start := p.pos
	for !p.atEnd() {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '(' || c == ')' {
			break
		}
		if c == '"' || c == '\'' {
			// Bare quotes at the top of an atom are not field
			// characters — they belong to a value-position atom that
			// the caller is mis-parsing as a field. Stop here so the
			// caller reports a clear "expected field" error.
			break
		}
		if c == '[' {
			// Slurp the bracketed subscript verbatim. Supports
			// device.labels[ "key" ] and the unquoted form.
			depth := 1
			p.pos++
			for !p.atEnd() && depth > 0 {
				switch p.src[p.pos] {
				case '[':
					depth++
				case ']':
					depth--
				case '"', '\'':
					q := p.src[p.pos]
					p.pos++
					for !p.atEnd() && p.src[p.pos] != q {
						p.pos++
					}
				}
				if p.atEnd() {
					break
				}
				p.pos++
			}
			continue
		}
		p.pos++
	}
	return p.src[start:p.pos]
}

// consumeOperator advances past a known op identifier (case-insensitive
// per the PL/pgSQL regex pattern). Returns the canonical Op token from
// the constants in ast.go.
func (p *parser) consumeOperator() (Op, error) {
	tok := p.consumeFieldOrValueToken()
	if tok == "" {
		return "", p.errorf("expected an operator (e.g. equals, exists)")
	}
	switch strings.ToLower(tok) {
	case "exists":
		return OpExists, nil
	case "notexists":
		return OpNotExists, nil
	case "equals":
		return OpEquals, nil
	case "notequals":
		return OpNotEquals, nil
	case "contains":
		return OpContains, nil
	case "notcontains":
		return OpNotContains, nil
	case "startswith":
		return OpStartsWith, nil
	case "endswith":
		return OpEndsWith, nil
	case "greaterthan":
		return OpGT, nil
	case "lessthan":
		return OpLT, nil
	case "greaterthanorequals":
		return OpGTE, nil
	case "lessthanorequals":
		return OpLTE, nil
	case "in":
		return OpIn, nil
	case "notin":
		return OpNotIn, nil
	}
	return "", p.errorf("unknown operator %q", tok)
}

// consumeValue reads a quoted string (single or double) or the unquoted
// remainder of the atom up to the next AND/OR keyword, closing paren,
// or end of input.
func (p *parser) consumeValue() (string, error) {
	c := p.peek()
	if c == '"' || c == '\'' {
		return p.consumeQuoted(c)
	}
	return p.consumeBareValue(), nil
}

func (p *parser) consumeQuoted(delim byte) (string, error) {
	p.pos++ // skip opening quote
	start := p.pos
	var sb strings.Builder
	for !p.atEnd() {
		c := p.src[p.pos]
		if c == '\\' && p.pos+1 < len(p.src) && p.src[p.pos+1] == delim {
			sb.WriteString(p.src[start:p.pos])
			sb.WriteByte(delim)
			p.pos += 2
			start = p.pos
			continue
		}
		if c == delim {
			sb.WriteString(p.src[start:p.pos])
			p.pos++ // consume closing quote
			return sb.String(), nil
		}
		p.pos++
	}
	return "", p.errorf("unterminated string literal")
}

// consumeBareValue reads up to (but not including) a top-level " and "
// / " or " keyword, a closing paren, or end of input. Quotes inside a
// bare value are treated literally — matches the PL/pgSQL regex which
// optionally stripped surrounding quotes but didn't tokenize internal
// ones.
func (p *parser) consumeBareValue() string {
	start := p.pos
	for !p.atEnd() {
		if p.src[p.pos] == ')' {
			break
		}
		if p.matchBoundaryKeywordAt(p.pos) {
			break
		}
		p.pos++
	}
	// Trim leading + trailing whitespace symmetrically (audit F-12).
	// The trailing trim alone produced asymmetric behaviour where
	// `equals  foo` round-tripped as `foo` but `equals foo  ` round-tripped
	// as `foo` too — fine in isolation, but the asymmetry made it
	// hard to reason about which side of the operator the
	// whitespace belonged to. The field allowlist in the validator
	// kept this from ever being exploitable, but the parser smell
	// is gone.
	return strings.TrimSpace(p.src[start:p.pos])
}

// matchBoundaryKeywordAt reports whether the position is at the start
// of a whitespace-delimited "and" / "or" keyword. The keyword must be
// preceded by whitespace (so the FIELD-side parse stops cleanly at it)
// and followed by whitespace or end-of-input.
func (p *parser) matchBoundaryKeywordAt(at int) bool {
	if at == 0 {
		return false
	}
	prev := p.src[at-1]
	if prev != ' ' && prev != '\t' && prev != '\n' && prev != '\r' {
		return false
	}
	rest := p.src[at:]
	for _, kw := range []string{"and", "or"} {
		if len(rest) < len(kw) {
			continue
		}
		if !strings.EqualFold(rest[:len(kw)], kw) {
			continue
		}
		if len(rest) == len(kw) {
			return true
		}
		next := rest[len(kw)]
		if next == ' ' || next == '\t' || next == '\n' || next == '\r' {
			return true
		}
	}
	return false
}

// matchKeyword consumes a whitespace-followed keyword (case-insensitive)
// if present at the current position. Returns false without advancing if
// the keyword isn't there.
func (p *parser) matchKeyword(kw string) bool {
	if p.pos+len(kw) > len(p.src) {
		return false
	}
	if !strings.EqualFold(p.src[p.pos:p.pos+len(kw)], kw) {
		return false
	}
	end := p.pos + len(kw)
	if end < len(p.src) {
		next := p.src[end]
		if next != ' ' && next != '\t' && next != '\n' && next != '\r' && next != '(' {
			return false
		}
	}
	p.pos = end
	return true
}
