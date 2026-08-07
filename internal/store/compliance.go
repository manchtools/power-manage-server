package store

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// RefreshDeviceCompliance recomputes each named device's compliance summary
// from the rows that remain and refreshes its search document, in the caller's
// transaction.
//
// Compliance evidence is removed from more than one place — an action retires,
// a policy retires — and the summary derived from it must not outlive the rows
// it summarises: a device left reporting NON_COMPLIANT with no failing check to
// point at is as wrong as one reporting UNKNOWN after it failed.
//
// Deletion carries no check time, so the stored one is left alone unless the
// device has no live check at all, in which case it is cleared with the rest.
func RefreshDeviceCompliance(ctx context.Context, tx *Tx, rec *AuditRecorder, deviceIDs ...[]string) error {
	seen := make(map[string]struct{})
	for _, ids := range deviceIDs {
		for _, id := range ids {
			if _, done := seen[id]; done {
				continue
			}
			seen[id] = struct{}{}
			if _, err := tx.RefreshDeviceComplianceStatus(ctx, generated.RefreshDeviceComplianceStatusParams{
				DeviceID: id,
			}); err != nil {
				return fmt.Errorf("refresh device compliance: %w", err)
			}
			rec.RefreshSearch("device", id)
		}
	}
	return nil
}
