package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/manchtools/power-manage/server/internal/agentsync"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/delivery"
)

// connectedSyncer registers a live connection for the fixture device and
// returns a syncer whose clock is pinned to the fixture timeline so
// future-scheduled availability is meaningful.
func connectedSyncer(t *testing.T, f *deliveryFixture) (*agentsync.Service, *connection.Agent) {
	t.Helper()
	manager := connection.NewManager()
	agent := manager.Register(context.Background(), f.deviceID, "device", "v1", nil)
	t.Cleanup(agent.Close)
	syncer := agentsync.New(agentsync.Config{
		Store: f.store, Manager: manager, Deliveries: f.service,
		Now: func() time.Time { return f.now },
	})
	return syncer, agent
}

func offeredDeliveryIDs(t *testing.T, syncer *agentsync.Service, deviceID string) map[string]struct{} {
	t.Helper()
	resp, err := syncer.Sync(context.Background(), deviceID)
	require.NoError(t, err)
	ids := make(map[string]struct{}, len(resp.Deliveries))
	for _, d := range resp.Deliveries {
		ids[d.DeliveryId] = struct{}{}
	}
	return ids
}

// TestAgentSync_DoesNotPullFutureScheduledDeliveriesForward proves the sync
// path honours the same availability/epoch guard the dispatcher enforces: a
// future PENDING row is neither offered nor mutated, a due row is, and a PUSHED
// row awaiting redelivery on a newer epoch is still offered.
func TestAgentSync_DoesNotPullFutureScheduledDeliveriesForward(t *testing.T) {
	ctx := context.Background()

	t.Run("future pending stays scheduled and untouched", func(t *testing.T) {
		f := newDeliveryFixture(t)
		syncer, _ := connectedSyncer(t, f)
		payload, err := protojson.Marshal(f.manifest)
		require.NoError(t, err)

		futureID := newID()
		_, err = f.raw.Exec(ctx, `
			INSERT INTO deliveries (delivery_id, device_id, manifest_id, manifest, state, available_at)
			VALUES ($1, $2, $3, $4, 'PENDING', $5)`,
			futureID, f.deviceID, f.manifest.ManifestId, payload, f.now.Add(24*time.Hour))
		require.NoError(t, err)

		offered := offeredDeliveryIDs(t, syncer, f.deviceID)
		_, present := offered[futureID]
		assert.False(t, present, "a future-scheduled delivery must not be pulled forward")

		row, err := f.store.GetDelivery(ctx, futureID)
		require.NoError(t, err)
		assert.Equal(t, delivery.StatePending, row.State, "a future delivery must remain PENDING")
		assert.Equal(t, int64(0), row.PushEpoch, "a future delivery must not be marked pushed")
	})

	t.Run("due pending is offered and marked pushed", func(t *testing.T) {
		f := newDeliveryFixture(t)
		syncer, agent := connectedSyncer(t, f)

		offered := offeredDeliveryIDs(t, syncer, f.deviceID)
		_, present := offered[f.deliveryID]
		assert.True(t, present, "a due delivery must be offered")

		row, err := f.store.GetDelivery(ctx, f.deliveryID)
		require.NoError(t, err)
		assert.Equal(t, delivery.StatePushed, row.State)
		assert.Equal(t, agent.Epoch, row.PushEpoch)
	})

	t.Run("future pushed on a newer epoch is still redelivered", func(t *testing.T) {
		f := newDeliveryFixture(t)
		syncer, agent := connectedSyncer(t, f)
		require.Greater(t, agent.Epoch, int64(1))
		payload, err := protojson.Marshal(f.manifest)
		require.NoError(t, err)

		staleID := newID()
		_, err = f.raw.Exec(ctx, `
			INSERT INTO deliveries
				(delivery_id, device_id, manifest_id, manifest, state, push_epoch, pushed_at, available_at)
			VALUES ($1, $2, $3, $4, 'PUSHED', 1, $5, $6)`,
			staleID, f.deviceID, f.manifest.ManifestId, payload, f.now, f.now.Add(30*time.Second))
		require.NoError(t, err)

		offered := offeredDeliveryIDs(t, syncer, f.deviceID)
		_, present := offered[staleID]
		assert.True(t, present, "a PUSHED row awaiting redelivery on a newer epoch must still be offered")

		row, err := f.store.GetDelivery(ctx, staleID)
		require.NoError(t, err)
		assert.Equal(t, agent.Epoch, row.PushEpoch, "redelivery must re-stamp the current epoch")
	})
}
