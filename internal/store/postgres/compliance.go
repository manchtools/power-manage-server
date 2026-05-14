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
