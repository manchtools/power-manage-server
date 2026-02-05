package auth

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"

	"github.com/manchtools/power-manage/server/internal/auth/policies"
)

// Authorizer provides authorization decisions using embedded OPA policies.
type Authorizer struct {
	query rego.PreparedEvalQuery
}

// AuthzInput represents the input to the authorization policy.
type AuthzInput struct {
	Role          string `json:"role"`
	SubjectID     string `json:"subject_id"`
	Action        string `json:"action"`
	ResourceID    string `json:"resource_id,omitempty"`
	ResourceOwner string `json:"resource_owner,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
}

// NewAuthorizer creates a new Authorizer with embedded policies.
func NewAuthorizer() (*Authorizer, error) {
	policyContent, err := policies.FS.ReadFile("authz.rego")
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	query, err := rego.New(
		rego.Query("data.authz.allow"),
		rego.Module("authz.rego", string(policyContent)),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("prepare rego query: %w", err)
	}

	return &Authorizer{query: query}, nil
}

// Authorize checks if the given input is authorized.
func (a *Authorizer) Authorize(ctx context.Context, input AuthzInput) (bool, error) {
	results, err := a.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, fmt.Errorf("evaluate policy: %w", err)
	}

	if len(results) == 0 {
		return false, nil
	}

	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected policy result type")
	}

	return allowed, nil
}

// IsAdmin checks if the role is admin.
func IsAdmin(role string) bool {
	return role == "admin"
}

// IsUser checks if the role is user.
func IsUser(role string) bool {
	return role == "user"
}

// IsDevice checks if the role is device.
func IsDevice(role string) bool {
	return role == "device"
}
