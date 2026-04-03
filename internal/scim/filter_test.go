package scim

import "testing"

func TestParseFilter_ValidExpressions(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantAttr  string
		wantOp    string
		wantValue string
	}{
		{
			name:      "userName eq",
			expr:      `userName eq "john@example.com"`,
			wantAttr:  "userName",
			wantOp:    "eq",
			wantValue: "john@example.com",
		},
		{
			name:      "externalId eq",
			expr:      `externalId eq "ext-123"`,
			wantAttr:  "externalId",
			wantOp:    "eq",
			wantValue: "ext-123",
		},
		{
			name:      "displayName eq",
			expr:      `displayName eq "Engineering"`,
			wantAttr:  "displayName",
			wantOp:    "eq",
			wantValue: "Engineering",
		},
		{
			name:      "case insensitive operator",
			expr:      `userName EQ "test@test.com"`,
			wantAttr:  "userName",
			wantOp:    "eq",
			wantValue: "test@test.com",
		},
		{
			name:      "value with spaces",
			expr:      `displayName eq "My Team Name"`,
			wantAttr:  "displayName",
			wantOp:    "eq",
			wantValue: "My Team Name",
		},
		{
			name:      "value without quotes",
			expr:      `userName eq unquoted`,
			wantAttr:  "userName",
			wantOp:    "eq",
			wantValue: "unquoted",
		},
		{
			name:      "leading/trailing whitespace",
			expr:      `  userName eq "trimmed@test.com"  `,
			wantAttr:  "userName",
			wantOp:    "eq",
			wantValue: "trimmed@test.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := parseFilter(tt.expr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if f.Attribute != tt.wantAttr {
				t.Errorf("Attribute = %q, want %q", f.Attribute, tt.wantAttr)
			}
			if f.Operator != tt.wantOp {
				t.Errorf("Operator = %q, want %q", f.Operator, tt.wantOp)
			}
			if f.Value != tt.wantValue {
				t.Errorf("Value = %q, want %q", f.Value, tt.wantValue)
			}
		})
	}
}

func TestParseFilter_Errors(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{"empty expression", ""},
		{"whitespace only", "   "},
		{"missing value", "userName eq"},
		{"single token", "userName"},
		{"unsupported operator", `userName ne "test"`},
		{"unsupported attribute", `email eq "test@test.com"`},
		{"unsupported attribute id", `id eq "123"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFilter(tt.expr)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParseFilter_QuoteHandling(t *testing.T) {
	// Double-quoted value should have quotes stripped
	f, err := parseFilter(`userName eq "quoted"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Value != "quoted" {
		t.Errorf("Value = %q, want %q", f.Value, "quoted")
	}

	// Single character value in quotes
	f2, err := parseFilter(`userName eq "x"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f2.Value != "x" {
		t.Errorf("Value = %q, want %q", f2.Value, "x")
	}
}
