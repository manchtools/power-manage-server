package dynamicquery_test

import (
	"strings"
	"testing"

	"github.com/manchtools/power-manage/server/internal/dynamicquery"
)

func TestParse_HappyPath(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"empty", ""},
		{"single equals", `labels.env equals "production"`},
		{"single equals unquoted", `labels.env equals production`},
		{"bracket key", `device.labels["my key"] equals "val"`},
		{"single quoted value", `device.os equals 'linux'`},
		{"and chain", `labels.env equals "prod" and labels.role equals "web"`},
		{"or chain", `labels.env equals "dev" or labels.env equals "staging"`},
		{"precedence", `labels.a equals "1" and labels.b equals "2" or labels.c equals "3"`},
		{"parenthesized", `(labels.a equals "1" or labels.b equals "2") and labels.c equals "3"`},
		{"unary exists", `labels.environment exists`},
		{"unary notExists", `device.labels.environment notExists`},
		{"negated atom", `not labels.role equals "broken"`},
		{"in op", `device.group in "A,B,C"`},
		{"value with spaces", `labels.team equals "platform infra"`},
		{"value with embedded quote", `labels.note equals "she said \"hi\""`},
		{"user query", `user.email equals "alice@example.com" and user.disabled equals "false"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dynamicquery.Parse(tc.query); err != nil {
				t.Fatalf("Parse(%q) returned error: %v", tc.query, err)
			}
		})
	}
}

func TestParse_Errors(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		errSub string
	}{
		{"unbalanced open", `(labels.a equals "1"`, "expected ')'"},
		{"unbalanced close", `labels.a equals "1")`, "trailing"},
		{"unknown operator", `labels.a maybe "1"`, "unknown operator"},
		{"binary op no value", `labels.a equals`, "requires a value"},
		{"unterminated string", `labels.a equals "value`, "unterminated"},
		{"bare op", `equals "1"`, "expected an operator"},
		{"only and", `and`, "expected an operator"},
		{"trailing or", `labels.a equals "1" or`, "expected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dynamicquery.Parse(tc.query)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded; expected error containing %q", tc.query, tc.errSub)
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("Parse(%q) error %q did not contain %q", tc.query, err.Error(), tc.errSub)
			}
		})
	}
}

func TestValidateDeviceQuery(t *testing.T) {
	valid := []string{
		"",
		`labels.env equals "prod"`,
		`device.labels.env equals "prod"`,
		`device.os equals "linux"`,
		`device.group in "production-fleet,staging-fleet"`,
		`device.group exists`,
		`(labels.env equals "prod" or labels.env equals "staging") and labels.role equals "web"`,
	}
	for _, q := range valid {
		t.Run("ok/"+q, func(t *testing.T) {
			if err := dynamicquery.ValidateDeviceQuery(q); err != nil {
				t.Fatalf("ValidateDeviceQuery(%q) = %v; want nil", q, err)
			}
		})
	}

	invalid := []struct {
		query  string
		errSub string
	}{
		{`labels.env strangeOp "x"`, "unknown operator"},
		{`device.group startsWith "prod"`, "not valid for field"},
		{`(labels.env equals "x"`, "expected ')'"},
	}
	for _, tc := range invalid {
		t.Run("err/"+tc.query, func(t *testing.T) {
			err := dynamicquery.ValidateDeviceQuery(tc.query)
			if err == nil {
				t.Fatalf("ValidateDeviceQuery(%q) = nil; want error %q", tc.query, tc.errSub)
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("ValidateDeviceQuery(%q) error %q does not contain %q", tc.query, err.Error(), tc.errSub)
			}
		})
	}
}

func TestValidateUserQuery(t *testing.T) {
	if err := dynamicquery.ValidateUserQuery(""); err == nil {
		t.Fatalf("ValidateUserQuery(\"\") = nil; want non-empty error")
	}

	if err := dynamicquery.ValidateUserQuery(`user.email equals "a@b.com"`); err != nil {
		t.Fatalf("ValidateUserQuery happy path = %v; want nil", err)
	}

	err := dynamicquery.ValidateUserQuery(`labels.env equals "prod"`)
	if err == nil {
		t.Fatalf("ValidateUserQuery rejected non-user field returned nil; want error")
	}
	if !strings.Contains(err.Error(), "user.*") {
		t.Fatalf("ValidateUserQuery error %q does not mention user.* prefix", err.Error())
	}
}
