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

// ComplianceRepo reads device-compliance state from the projection.
// Writes flow through the event store + projector pipeline, not
// through this interface — the read path stays narrowly scoped so
// future backends only need to satisfy this small surface.
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
}
