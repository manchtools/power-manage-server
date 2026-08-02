package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const heartbeatTelemetryBatchSize = 1000

// RecordHeartbeatTelemetry is the sole unaudited state writer. Heartbeats are
// high-rate liveness telemetry, not security evidence; callers coalesce live
// connection timestamps before reaching this bounded batch path.
func (s *Store) RecordHeartbeatTelemetry(ctx context.Context, snapshot map[string]time.Time) error {
	if ctx == nil || s == nil {
		return errors.New("heartbeat telemetry requires a store and context")
	}
	ids := make([]string, 0, len(snapshot))
	for id, at := range snapshot {
		if id == "" || at.IsZero() {
			return errors.New("heartbeat telemetry contains an invalid device")
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for start := 0; start < len(ids); start += heartbeatTelemetryBatchSize {
		end := min(start+heartbeatTelemetryBatchSize, len(ids))
		times := make([]pgtype.Timestamptz, end-start)
		for i, id := range ids[start:end] {
			times[i] = pgtype.Timestamptz{Time: snapshot[id].UTC().Truncate(time.Microsecond), Valid: true}
		}
		if _, err := s.queries.RecordDeviceHeartbeats(ctx, db.RecordDeviceHeartbeatsParams{
			DeviceIds: ids[start:end], LastSeenAts: times,
		}); err != nil {
			return err
		}
	}
	return nil
}
