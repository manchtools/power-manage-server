package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// heartbeatBatchSize bounds one telemetry transaction. The store serializes
// writers, so flushing a whole fleet in one transaction holds the writer for
// the entire snapshot and delays dispatch, revocation, identity and terminal
// state. Bounding it caps that wait at one batch instead of the fleet.
const heartbeatBatchSize = 256

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
	slices.Sort(ids)
	for batch := range slices.Chunk(ids, heartbeatBatchSize) {
		if err := s.withTx(ctx, func(raw *sql.Tx, queries *db.Queries) error {
			for _, id := range batch {
				seenAt := snapshot[id].UTC().Truncate(time.Microsecond)
				if _, err := queries.RecordDeviceHeartbeat(ctx, db.RecordDeviceHeartbeatParams{
					DeviceID: id, LastSeenAt: &seenAt,
				}); err != nil {
					return err
				}
				if err := refreshSearchDocument(ctx, raw, "devices", id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
