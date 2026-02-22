package scim

import (
	"fmt"
	"strings"
)

// filter represents a parsed SCIM filter expression.
type filter struct {
	Attribute string
	Operator  string
	Value     string
}

// parseFilter parses a simple SCIM filter expression.
// Only supports: attribute eq "value" for userName, externalId, and displayName.
func parseFilter(expr string) (filter, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return filter{}, fmt.Errorf("empty filter expression")
	}

	// Find the operator (only "eq" is supported)
	// The expression format is: attribute op "value"
	parts := strings.SplitN(expr, " ", 3)
	if len(parts) < 3 {
		return filter{}, fmt.Errorf("filter must be in format: attribute op \"value\"")
	}

	attribute := parts[0]
	operator := strings.ToLower(parts[1])
	value := strings.Join(parts[2:], " ")

	// Only "eq" operator is supported
	if operator != "eq" {
		return filter{}, fmt.Errorf("unsupported operator %q, only \"eq\" is supported", operator)
	}

	// Only these attributes are supported
	switch attribute {
	case "userName", "externalId", "displayName":
		// OK
	default:
		return filter{}, fmt.Errorf("unsupported filter attribute %q, supported: userName, externalId, displayName", attribute)
	}

	// Remove surrounding quotes from value
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}

	return filter{
		Attribute: attribute,
		Operator:  operator,
		Value:     value,
	}, nil
}
