package store

import (
	"context"
	"encoding/json"
	"time"
)

// ComplianceCheckResult is a per-action compliance evaluation record
// for a single device, as returned by the device-compliance projection.
type ComplianceCheckResult struct {
	ActionID   string
	ActionName string
	Compliant  bool
	CheckedAt  time.Time
	// DetectionOutput carries the raw JSON payload captured during
	// the compliance probe (stdout/stderr/exit_code shape). Stays
	// json.RawMessage at the repository boundary so each backend
	// chooses how to materialize the column — JSONB on Postgres,
	// JSON on MySQL, TEXT on SQLite/libSQL — without leaking that
	// choice to handlers.
	DetectionOutput json.RawMessage
}

// ComplianceSummary is the aggregate compliance state for a device
// across all assigned compliance policies. Status is the
// pm.ComplianceStatus enum value; Total / Passing are populated by
// the projection.
type ComplianceSummary struct {
	Status    int32
	Total     int32
	Passing   int32
	CheckedAt *time.Time
}

// CompliancePolicy is a CRUD-side compliance policy row. Rules are
// fetched separately via ListPolicyRules to keep the list/get paths
// cheap when only the policy header is needed.
type CompliancePolicy struct {
	ID          string
	Name        string
	Description string
	RuleCount   int32
	CreatedAt   *time.Time
	CreatedBy   string
}

// CompliancePolicyRule is one rule (action + grace period) belonging
// to a compliance policy.
type CompliancePolicyRule struct {
	PolicyID         string
	ActionID         string
	ActionName       string
	GracePeriodHours int32
	AddedAt          *time.Time
}

// ListCompliancePoliciesFilter is the pagination shape for the
// policy list endpoint.
type ListCompliancePoliciesFilter struct {
	Limit  int32
	Offset int32
}

// DevicePolicyEvaluation is the per-(device,policy,rule) evaluation
// row, joined with policy_name + rule fields. Shape matches what
// GetDeviceCompliancePolicyStatus needs to build its proto response.
type DevicePolicyEvaluation struct {
	DeviceID         string
	PolicyID         string
	PolicyName       string
	ActionID         string
	ActionName       string
	Compliant        bool
	Status           int32
	GracePeriodHours int32
	CheckedAt        *time.Time
	FirstFailedAt    *time.Time
}

// ComplianceRepo reads device-compliance state and compliance-policy
// definitions from the projection. Writes flow through the event
// store + projector pipeline, not through this interface — the read
// path stays narrowly scoped so future backends only need to satisfy
// this small surface.
//
// Part of the storage-abstraction tracker (#242). The Postgres
// implementation lives in internal/store/postgres.
type ComplianceRepo interface {
	// DeviceResults returns the per-action check results for the
	// given device, ordered by action_name. Returns an empty slice
	// (not ErrNotFound) when the device has no evaluated actions.
	DeviceResults(ctx context.Context, deviceID string) ([]ComplianceCheckResult, error)

	// DeviceSummary returns the aggregate compliance status for the
	// given device. Returns ErrNotFound if the device row itself is
	// missing from the projection. Test the error via IsNotFound.
	DeviceSummary(ctx context.Context, deviceID string) (ComplianceSummary, error)

	// GetPolicy returns the policy header. Returns ErrNotFound when
	// no such policy exists.
	GetPolicy(ctx context.Context, id string) (CompliancePolicy, error)

	// ListPolicies returns a page of policies (excluding soft-deleted).
	// Caller pairs this with CountPolicies for total-count pagination.
	ListPolicies(ctx context.Context, filter ListCompliancePoliciesFilter) ([]CompliancePolicy, error)

	// CountPolicies returns the total count of non-deleted policies
	// for pagination.
	CountPolicies(ctx context.Context) (int64, error)

	// ListPolicyRules returns the rules belonging to a policy,
	// ordered as the projection emits them. Empty slice when the
	// policy has no rules yet.
	ListPolicyRules(ctx context.Context, policyID string) ([]CompliancePolicyRule, error)

	// ListDeviceEvaluations returns the per-(policy, rule)
	// evaluation rows for a device, joined with policy_name /
	// action_name / grace_period_hours. Empty slice when the device
	// has no policy assignments evaluated yet.
	ListDeviceEvaluations(ctx context.Context, deviceID string) ([]DevicePolicyEvaluation, error)
}
