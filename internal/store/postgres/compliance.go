// Package postgres provides sqlc-backed implementations of the domain
// repository interfaces declared in internal/store. Per the
// storage-abstraction tracker (manchtools/power-manage-server#242),
// the only place pgx + sqlc-generated types are allowed to surface
// is inside this package — every other caller depends on the
// interfaces in internal/store.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Compliance implements store.ComplianceRepo against the Postgres
// projection via sqlc-generated queries.
type Compliance struct {
	q *generated.Queries
}

// NewCompliance returns a Compliance repo bound to the given sqlc
// handle. The handle may be pool-bound (long-lived) or
// transaction-bound; both are supported because Queries.WithTx swaps
// only the underlying executor.
func NewCompliance(q *generated.Queries) *Compliance {
	return &Compliance{q: q}
}

// DeviceResults returns the projection rows for the given device,
// translating sqlc row types into the domain shape. Returns an
// empty slice (not an error) when the device has no compliance
// results — matches the underlying :many query semantics.
func (c *Compliance) DeviceResults(ctx context.Context, deviceID string) ([]store.ComplianceCheckResult, error) {
	rows, err := c.q.GetDeviceComplianceResults(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("compliance: list device results: %w", err)
	}
	out := make([]store.ComplianceCheckResult, len(rows))
	for i, r := range rows {
		out[i] = store.ComplianceCheckResult{
			ActionID:        r.ActionID,
			ActionName:      r.ActionName,
			Compliant:       r.Compliant,
			CheckedAt:       r.CheckedAt,
			DetectionOutput: json.RawMessage(r.DetectionOutput),
		}
	}
	return out, nil
}

// DeviceSummary returns the aggregate compliance row for the device.
// pgx.ErrNoRows is translated to store.ErrNotFound so callers depend
// only on store.IsNotFound; pgx never leaks past this boundary.
func (c *Compliance) DeviceSummary(ctx context.Context, deviceID string) (store.ComplianceSummary, error) {
	row, err := c.q.GetDeviceComplianceSummary(ctx, deviceID)
	if err != nil {
		return store.ComplianceSummary{}, fmt.Errorf("compliance: get device summary: %w", translateNotFound(err))
	}
	return store.ComplianceSummary{
		Status:    row.ComplianceStatus,
		Total:     row.ComplianceTotal,
		Passing:   row.CompliancePassing,
		CheckedAt: row.ComplianceCheckedAt,
	}, nil
}

// GetPolicy returns the policy header by ID. pgx.ErrNoRows is
// translated to store.ErrNotFound.
func (c *Compliance) GetPolicy(ctx context.Context, id string) (store.CompliancePolicy, error) {
	row, err := c.q.GetCompliancePolicyByID(ctx, id)
	if err != nil {
		return store.CompliancePolicy{}, fmt.Errorf("compliance: get policy: %w", translateNotFound(err))
	}
	return policyFromRow(row), nil
}

// ListPolicies returns the paginated policy list. Empty slice when
// the offset is past the end; no ErrNotFound.
func (c *Compliance) ListPolicies(ctx context.Context, filter store.ListCompliancePoliciesFilter) ([]store.CompliancePolicy, error) {
	rows, err := c.q.ListCompliancePolicies(ctx, generated.ListCompliancePoliciesParams{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("compliance: list policies: %w", err)
	}
	out := make([]store.CompliancePolicy, len(rows))
	for i, r := range rows {
		out[i] = policyFromRow(r)
	}
	return out, nil
}

// CountPolicies returns the total count of non-deleted policies. The
// COUNT(*) :one query never returns ErrNoRows in practice but the
// translateNotFound wrap keeps the contract symmetric with sibling
// counts elsewhere.
func (c *Compliance) CountPolicies(ctx context.Context) (int64, error) {
	n, err := c.q.CountCompliancePolicies(ctx)
	if err != nil {
		return 0, fmt.Errorf("compliance: count policies: %w", translateNotFound(err))
	}
	return n, nil
}

// ListPolicyRules returns the rules for a policy in the order the
// projection emits them. Empty slice when the policy has no rules.
func (c *Compliance) ListPolicyRules(ctx context.Context, policyID string) ([]store.CompliancePolicyRule, error) {
	rows, err := c.q.ListCompliancePolicyRules(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("compliance: list policy rules: %w", err)
	}
	out := make([]store.CompliancePolicyRule, len(rows))
	for i, r := range rows {
		out[i] = store.CompliancePolicyRule{
			PolicyID:         r.PolicyID,
			ActionID:         r.ActionID,
			ActionName:       r.ActionName,
			GracePeriodHours: r.GracePeriodHours,
			AddedAt:          r.AddedAt,
		}
	}
	return out, nil
}

// ListDeviceEvaluations returns the per-(policy, rule) evaluation
// rows for a device, joined with policy_name + action_name + grace.
// Empty slice when no policies are assigned to the device yet.
func (c *Compliance) ListDeviceEvaluations(ctx context.Context, deviceID string) ([]store.DevicePolicyEvaluation, error) {
	rows, err := c.q.GetDeviceCompliancePolicyEvaluations(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("compliance: list device evaluations: %w", err)
	}
	out := make([]store.DevicePolicyEvaluation, len(rows))
	for i, r := range rows {
		out[i] = store.DevicePolicyEvaluation{
			DeviceID:         r.DeviceID,
			PolicyID:         r.PolicyID,
			PolicyName:       r.PolicyName,
			ActionID:         r.ActionID,
			ActionName:       r.ActionName,
			Compliant:        r.Compliant,
			Status:           r.Status,
			GracePeriodHours: r.GracePeriodHours,
			CheckedAt:        r.CheckedAt,
			FirstFailedAt:    r.FirstFailedAt,
		}
	}
	return out, nil
}

// policyFromRow translates a sqlc projection row to the domain shape.
// Shared by GetPolicy and ListPolicies so the field-mapping lives in
// one place.
func policyFromRow(r generated.CompliancePoliciesProjection) store.CompliancePolicy {
	return store.CompliancePolicy{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		RuleCount:   r.RuleCount,
		CreatedAt:   r.CreatedAt,
		CreatedBy:   r.CreatedBy,
	}
}

// translateNotFound maps pgx.ErrNoRows to store.ErrNotFound at the
// repository boundary. The original error is dropped intentionally
// — handlers depend on store.IsNotFound and have no need for the
// backend-specific cause. Non-not-found errors pass through
// unchanged so wrapping callers retain the underlying %w chain.
func translateNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}
