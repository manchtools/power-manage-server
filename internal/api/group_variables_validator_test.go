package api

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestValidateVariable_HappyPath locks the per-type happy paths. Each
// VariableType has at least one round-trip case where ValidateVariable
// returns nil — if a future tightening over-rejects, this table fires
// the regression first.
func TestValidateVariable_HappyPath(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		v    *pm.Variable
	}{
		{"string short", &pm.Variable{Name: "deploy_env", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: "prod"}},
		{"string max len", &pm.Variable{Name: "long_string", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: strings.Repeat("a", stringMaxLen)}},
		{"string empty allowed", &pm.Variable{Name: "deploy_env", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: ""}},
		{"int unbounded", &pm.Variable{Name: "nginx_port", Type: pm.VariableType_VARIABLE_TYPE_INT, Value: "8080"}},
		{"int bounded", &pm.Variable{Name: "nginx_port", Type: pm.VariableType_VARIABLE_TYPE_INT, Value: "443", IntMin: 1, IntMax: 65535}},
		{"int negative", &pm.Variable{Name: "offset", Type: pm.VariableType_VARIABLE_TYPE_INT, Value: "-5", IntMin: -10, IntMax: 10}},
		{"bool true", &pm.Variable{Name: "enabled", Type: pm.VariableType_VARIABLE_TYPE_BOOL, Value: "true"}},
		{"bool false", &pm.Variable{Name: "enabled", Type: pm.VariableType_VARIABLE_TYPE_BOOL, Value: "false"}},
		{"hostname plain", &pm.Variable{Name: "ldap_host", Type: pm.VariableType_VARIABLE_TYPE_HOSTNAME, Value: "ldap"}},
		{"hostname fqdn", &pm.Variable{Name: "ldap_host", Type: pm.VariableType_VARIABLE_TYPE_HOSTNAME, Value: "ldap.example.com"}},
		{"path simple", &pm.Variable{Name: "config_path", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: "/etc/myapp/config.yaml"}},
		{"path with dots in element", &pm.Variable{Name: "config_path", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: "/etc/.myapp/file..name"}},
		{"choice", &pm.Variable{Name: "deploy_env", Type: pm.VariableType_VARIABLE_TYPE_CHOICE, Value: "prod", ChoiceValues: []string{"prod", "staging", "dev"}}},
		{"secret", &pm.Variable{Name: "ldap_pwd", Type: pm.VariableType_VARIABLE_TYPE_SECRET, Value: "hunter2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateVariable(ctx, tc.v); err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
		})
	}
}

// TestValidateVariable_Rejections covers at least one rejection path
// per type plus the cross-cutting name and type-enum failures.
func TestValidateVariable_Rejections(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		v       *pm.Variable
		wantSub string
	}{
		{"nil variable", nil, "variable is required"},
		{"empty name", &pm.Variable{Name: "", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: "x"}, "name is required"},
		{"name uppercase", &pm.Variable{Name: "Nginx_Port", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: "x"}, "match"},
		{"name leading digit", &pm.Variable{Name: "1port", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: "x"}, "match"},
		{"name dash", &pm.Variable{Name: "deploy-env", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: "x"}, "match"},
		{"name too long", &pm.Variable{Name: strings.Repeat("a", variableNameMaxLen+1), Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: "x"}, "at most"},
		{"type unspecified", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_UNSPECIFIED, Value: "y"}, "type is required"},

		{"string with control char", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: "ab\x01cd"}, "control characters"},
		{"string non-ascii", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: "café"}, "printable ASCII"},
		{"string too long", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_STRING, Value: strings.Repeat("a", stringMaxLen+1)}, "at most"},

		{"int empty", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_INT, Value: ""}, "value is required"},
		{"int not parseable", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_INT, Value: "abc"}, "base-10 int64"},
		{"int out of range", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_INT, Value: "1000", IntMin: 1, IntMax: 100}, "out of range"},
		{"int min > max", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_INT, Value: "5", IntMin: 10, IntMax: 1}, "<="},

		{"bool TRUE", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_BOOL, Value: "TRUE"}, "true\" or \"false"},
		{"bool 1", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_BOOL, Value: "1"}, "true\" or \"false"},

		{"hostname empty", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_HOSTNAME, Value: ""}, "value is required"},
		{"hostname uppercase", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_HOSTNAME, Value: "Host.example.com"}, "RFC 1123"},
		{"hostname underscore", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_HOSTNAME, Value: "ldap_host"}, "RFC 1123"},

		{"path empty", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: ""}, "value is required"},
		{"path relative", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: "etc/foo"}, "absolute"},
		{"path dot dot", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: "/etc/../etc/passwd"}, "\"..\""},
		{"path shell meta dollar", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: "/etc/$(id)"}, "shell metacharacters"},
		{"path shell meta backtick", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: "/etc/`id`"}, "shell metacharacters"},
		{"path shell meta semicolon", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: "/etc/foo;rm"}, "shell metacharacters"},
		{"path shell meta pipe", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: "/etc/foo|cat"}, "shell metacharacters"},
		{"path shell meta nul", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_PATH, Value: "/etc/\x00foo"}, "shell metacharacters"},

		{"choice no values", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_CHOICE, Value: "prod"}, "choice_values must be non-empty"},
		{"choice not in set", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_CHOICE, Value: "qa", ChoiceValues: []string{"prod", "dev"}}, "not in choice_values"},

		{"secret empty", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_SECRET, Value: ""}, "value is required"},
		{"secret too long", &pm.Variable{Name: "x", Type: pm.VariableType_VARIABLE_TYPE_SECRET, Value: strings.Repeat("a", secretMaxLen+1)}, "at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateVariable(ctx, tc.v)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("expected CodeInvalidArgument, got %v", connect.CodeOf(err))
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected error containing %q, got %q", tc.wantSub, err.Error())
			}
		})
	}
}
