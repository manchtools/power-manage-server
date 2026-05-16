package dynamicquery_test

import (
	"testing"

	"github.com/manchtools/power-manage/server/internal/dynamicquery"
)

func mustParse(t *testing.T, q string) dynamicquery.Expr {
	t.Helper()
	expr, err := dynamicquery.Parse(q)
	if err != nil {
		t.Fatalf("Parse(%q) failed: %v", q, err)
	}
	return expr
}

func TestEvaluateDevice_LabelOps(t *testing.T) {
	ctx := dynamicquery.DeviceContext{
		Labels: map[string]string{
			"environment": "Production",
			"role":        "web",
			"version":     "2",
		},
	}

	cases := []struct {
		query string
		want  bool
	}{
		{`labels.environment exists`, true},
		{`labels.missing exists`, false},
		{`labels.environment notExists`, false},
		{`labels.missing notExists`, true},
		{`labels.environment equals "production"`, true}, // case-insensitive
		{`labels.environment notEquals "dev"`, true},
		{`labels.environment notEquals "production"`, false},
		{`labels.environment contains "prod"`, true},
		{`labels.environment notContains "dev"`, true},
		{`labels.environment startsWith "prod"`, true},
		{`labels.environment endsWith "tion"`, true},
		{`labels.role in "web,db,cache"`, true},
		{`labels.role notIn "web,db"`, false},
		{`labels.version greaterThan "1"`, true},
		{`labels.version lessThan "10"`, true}, // numeric
		{`labels.version greaterThanOrEquals "2"`, true},
		{`labels.version lessThanOrEquals "2"`, true},
		{`device.labels.environment equals "production"`, true},
		{`device.labels["environment"] equals "production"`, true},
		{`labels["environment"] equals "production"`, true},
		// Missing-field semantics: negative ops flip to true.
		{`labels.missing equals "x"`, false},
		{`labels.missing notEquals "x"`, true},
		{`labels.missing in "a,b"`, false},
		{`labels.missing notIn "a,b"`, true},
	}

	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			got := dynamicquery.EvaluateDevice(mustParse(t, tc.query), ctx)
			if got != tc.want {
				t.Fatalf("EvaluateDevice(%q) = %v; want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestEvaluateDevice_DeviceGroup(t *testing.T) {
	ctx := dynamicquery.DeviceContext{
		GroupNames: []string{"Prod Fleet", "Linux Servers"},
	}
	cases := []struct {
		query string
		want  bool
	}{
		{`device.group exists`, true},
		{`device.group notExists`, false},
		{`device.group equals "prod fleet"`, true},
		{`device.group equals "test fleet"`, false},
		{`device.group notEquals "test fleet"`, true},
		{`device.group contains "linux"`, true},
		{`device.group notContains "windows"`, true},
		{`device.group in "Prod Fleet,Dev Fleet"`, true},
		{`device.group notIn "Test Fleet,Stage Fleet"`, true},
		{`device.group in "Test,Stage"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			got := dynamicquery.EvaluateDevice(mustParse(t, tc.query), ctx)
			if got != tc.want {
				t.Fatalf("EvaluateDevice(%q) = %v; want %v", tc.query, got, tc.want)
			}
		})
	}

	// Empty membership: negative ops flip to true.
	emptyCtx := dynamicquery.DeviceContext{}
	if !dynamicquery.EvaluateDevice(mustParse(t, `device.group notEquals "anything"`), emptyCtx) {
		t.Fatalf("device.group notEquals on empty membership should return true")
	}
	if dynamicquery.EvaluateDevice(mustParse(t, `device.group equals "anything"`), emptyCtx) {
		t.Fatalf("device.group equals on empty membership should return false")
	}
}

func TestEvaluateDevice_Inventory(t *testing.T) {
	ctx := dynamicquery.DeviceContext{
		Inventory: func(field string) (string, bool) {
			switch field {
			case "os":
				return "linux", true
			case "ram_gb":
				return "32", true
			}
			return "", false
		},
	}
	cases := []struct {
		query string
		want  bool
	}{
		{`device.os equals "linux"`, true},
		{`device.os equals "windows"`, false},
		{`device.ram_gb greaterThan "16"`, true},
		{`device.ram_gb lessThan "16"`, false},
		{`device.unknown exists`, false},
		{`device.unknown notExists`, true},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			got := dynamicquery.EvaluateDevice(mustParse(t, tc.query), ctx)
			if got != tc.want {
				t.Fatalf("EvaluateDevice(%q) = %v; want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestEvaluateDevice_BooleanComposition(t *testing.T) {
	ctx := dynamicquery.DeviceContext{
		Labels: map[string]string{"env": "prod", "role": "web"},
	}
	cases := []struct {
		query string
		want  bool
	}{
		{`labels.env equals "prod" and labels.role equals "web"`, true},
		{`labels.env equals "prod" and labels.role equals "db"`, false},
		{`labels.env equals "prod" or labels.role equals "db"`, true},
		{`labels.env equals "dev" or labels.role equals "db"`, false},
		{`not labels.env equals "dev"`, true},
		{`(labels.env equals "prod" or labels.env equals "dev") and labels.role equals "web"`, true},
		// AND binds tighter than OR (standard precedence).
		{`labels.env equals "dev" or labels.env equals "prod" and labels.role equals "web"`, true},
		{`labels.env equals "dev" or labels.env equals "prod" and labels.role equals "db"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			got := dynamicquery.EvaluateDevice(mustParse(t, tc.query), ctx)
			if got != tc.want {
				t.Fatalf("EvaluateDevice(%q) = %v; want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestEvaluateUser_Fields(t *testing.T) {
	ctx := dynamicquery.UserContext{
		Email:             "alice@example.com",
		Disabled:          false,
		TotpEnabled:       true,
		HasPassword:       true,
		DisplayName:       "Alice",
		PreferredUsername: "alice",
		Locale:            "en",
	}
	cases := []struct {
		query string
		want  bool
	}{
		{`user.email exists`, true},
		{`user.email equals "alice@example.com"`, true},
		{`user.email endsWith "@example.com"`, true},
		{`user.email in "alice@example.com,bob@example.com"`, true},
		{`user.disabled equals "false"`, true},
		{`user.totp_enabled equals "true"`, true},
		{`user.has_password equals "true"`, true},
		{`user.display_name contains "lic"`, true},
		{`user.locale equals "en"`, true},
		{`user.locale notExists`, false},
		{`user.unknown exists`, false},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			got := dynamicquery.EvaluateUser(mustParse(t, tc.query), ctx)
			if got != tc.want {
				t.Fatalf("EvaluateUser(%q) = %v; want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestEvaluate_EmptyQuery(t *testing.T) {
	// Parse("") returns an always-true placeholder. Both evaluators
	// must agree: empty matches every device / user.
	if !dynamicquery.EvaluateDevice(mustParse(t, ""), dynamicquery.DeviceContext{}) {
		t.Fatalf("empty device query should match every device")
	}
	if !dynamicquery.EvaluateUser(mustParse(t, ""), dynamicquery.UserContext{}) {
		t.Fatalf("empty user query should match every user")
	}
}
