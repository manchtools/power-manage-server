package store

import (
	"context"
	"errors"
	"sort"
	"time"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

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
	for _, id := range ids {
		seenAt := snapshot[id].UTC().Truncate(time.Microsecond)
		if _, err := s.queries.RecordDeviceHeartbeat(ctx, db.RecordDeviceHeartbeatParams{
			DeviceID: id, LastSeenAt: &seenAt,
		}); err != nil {
			return err
		}
	}
	return nil
}
