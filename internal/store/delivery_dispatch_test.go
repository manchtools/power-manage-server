package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/agentsync"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/delivery"
)

type deliveryRouter struct {
	mu                sync.Mutex
	agent             *connection.Agent
	replaceOnNextSend bool
	sent              chan *pmv1.ServerMessage
}

func newDeliveryRouter() *deliveryRouter {
	return &deliveryRouter{sent: make(chan *pmv1.ServerMessage, 8)}
}

func (r *deliveryRouter) connect(deviceID string, epoch int64) {
	r.mu.Lock()
	r.agent = &connection.Agent{DeviceID: deviceID, Epoch: epoch}
	r.mu.Unlock()
}

func (r *deliveryRouter) Get(deviceID string) (*connection.Agent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.agent == nil || r.agent.DeviceID != deviceID {
		return nil, false
	}
	return &connection.Agent{DeviceID: r.agent.DeviceID, Epoch: r.agent.Epoch}, true
}

func (r *deliveryRouter) List() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.agent == nil {
		return nil
	}
	return []string{r.agent.DeviceID}
}

func (r *deliveryRouter) SendAtEpoch(deviceID string, epoch int64, message *pmv1.ServerMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.agent == nil || r.agent.DeviceID != deviceID {
		return connection.ErrAgentNotConnected
	}
	if r.replaceOnNextSend {
		r.replaceOnNextSend = false
		r.agent.Epoch++
	}
	if r.agent.Epoch != epoch {
		return connection.ErrStaleConnection
	}
	r.sent <- message
	return nil
}

func newDispatcher(f *deliveryFixture, router *deliveryRouter, sweep time.Duration) *delivery.Dispatcher {
	return delivery.NewDispatcher(delivery.DispatcherConfig{
		Store: f.store, State: f.service, Router: router,
		Now: func() time.Time { return f.now }, SweepInterval: sweep,
		Workers: 1, QueueSize: 8, BatchSize: 32,
	})
}

func TestAgentSync_UsesDurableDeliveriesAndLiveEpoch(t *testing.T) {
	f := newDeliveryFixture(t)
	ctx := context.Background()
	groupID := newID()
	_, err := f.raw.Exec(ctx, `UPDATE devices SET sync_interval_minutes = 17 WHERE id = $1`, f.deviceID)
	require.NoError(t, err)
	_, err = f.raw.Exec(ctx, `
		INSERT INTO device_groups (id, name, maintenance_window)
		VALUES ($1, 'maintenance', '{"schedule":[{"days":["mon"],"allow":"09:00-10:00"}]}')`, groupID)
	require.NoError(t, err)
	_, err = f.raw.Exec(ctx, `
		INSERT INTO device_group_members (group_id, device_id, added_at)
		VALUES ($1, $2, $3)`, groupID, f.deviceID, f.now)
	require.NoError(t, err)

	manager := connection.NewManager()
	agent := manager.Register(ctx, f.deviceID, "device", "v1", nil)
	t.Cleanup(agent.Close)
	syncer := agentsync.New(agentsync.Config{Store: f.store, Manager: manager, Deliveries: f.service})

	response, err := syncer.Sync(ctx, f.deviceID)
	require.NoError(t, err)
	assert.Equal(t, int32(17), response.SyncIntervalMinutes)
	require.Len(t, response.Deliveries, 1)
	assert.Equal(t, f.deliveryID, response.Deliveries[0].DeliveryId)
	assert.True(t, proto.Equal(f.manifest, response.Deliveries[0].Manifest))
	require.NotNil(t, response.MaintenanceWindow)
	require.Len(t, response.MaintenanceWindow.Schedule, 1)
	assert.Equal(t, []string{"mon"}, response.MaintenanceWindow.Schedule[0].Days)

	row, err := f.store.GetDelivery(ctx, f.deliveryID)
	require.NoError(t, err)
	assert.Equal(t, delivery.StatePushed, row.State)
	assert.Equal(t, agent.Epoch, row.PushEpoch)

	_, err = f.service.AcknowledgeReceipt(ctx, f.deliveryID, f.deviceID)
	require.NoError(t, err)
	response, err = syncer.Sync(ctx, f.deviceID)
	require.NoError(t, err)
	assert.Empty(t, response.Deliveries, "durably received work is not offered again")
}

func TestDispatcher_OfflineDeliveryArrivesAfterReconnect(t *testing.T) {
	f := newDeliveryFixture(t)
	router := newDeliveryRouter()
	dispatcher := newDispatcher(f, router, time.Hour)
	ctx := context.Background()

	require.NoError(t, dispatcher.Dispatch(ctx, f.deliveryID))
	row, err := f.store.GetDelivery(ctx, f.deliveryID)
	require.NoError(t, err)
	assert.Equal(t, delivery.StatePending, row.State)

	router.connect(f.deviceID, 1)
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- dispatcher.Run(runCtx) }()
	require.NoError(t, dispatcher.WakeDevice(ctx, f.deviceID))
	var message *pmv1.ServerMessage
	select {
	case message = <-router.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("reconnect wake did not deliver pending work")
	}
	cancel()
	require.NoError(t, <-done)
	require.NotNil(t, message.GetManifestDelivery())
	assert.Equal(t, f.deliveryID, message.GetManifestDelivery().DeliveryId)
	assert.True(t, proto.Equal(f.manifest, message.GetManifestDelivery().Manifest))
	row, err = f.store.GetDelivery(ctx, f.deliveryID)
	require.NoError(t, err)
	assert.Equal(t, delivery.StatePushed, row.State)
	assert.Equal(t, int64(1), row.PushEpoch)
}

func TestDispatcher_StaleConnectionCannotReceiveAndReconnectRetriesImmediately(t *testing.T) {
	f := newDeliveryFixture(t)
	router := newDeliveryRouter()
	router.connect(f.deviceID, 1)
	router.replaceOnNextSend = true
	dispatcher := newDispatcher(f, router, time.Hour)
	ctx := context.Background()

	require.NoError(t, dispatcher.Dispatch(ctx, f.deliveryID))
	select {
	case <-router.sent:
		t.Fatal("the replaced epoch received a delivery")
	default:
	}
	require.NoError(t, dispatcher.Dispatch(ctx, f.deliveryID), "a newer connection must bypass the retry delay")
	var message *pmv1.ServerMessage
	select {
	case message = <-router.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("new connection did not receive the retry")
	}
	assert.Equal(t, f.deliveryID, message.GetManifestDelivery().DeliveryId)
	row, err := f.store.GetDelivery(ctx, f.deliveryID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), row.PushEpoch)
	assert.Equal(t, int32(2), row.AttemptCount)
}

func TestDispatcher_WakeAndSweepBothFeedBoundedWorkers(t *testing.T) {
	t.Run("wake", func(t *testing.T) {
		f := newDeliveryFixture(t)
		router := newDeliveryRouter()
		router.connect(f.deviceID, 1)
		dispatcher := newDispatcher(f, router, time.Hour)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		done := make(chan error, 1)
		go func() { done <- dispatcher.Run(ctx) }()
		require.True(t, dispatcher.Wake(f.deliveryID))
		select {
		case message := <-router.sent:
			assert.Equal(t, f.deliveryID, message.GetManifestDelivery().DeliveryId)
		case <-time.After(2 * time.Second):
			t.Fatal("in-process wake did not dispatch")
		}
		assert.ErrorIs(t, dispatcher.Run(context.Background()), delivery.ErrAlreadyRunning)
		cancel()
		require.NoError(t, <-done)
	})

	t.Run("missed wake recovered by sweep", func(t *testing.T) {
		f := newDeliveryFixture(t)
		router := newDeliveryRouter()
		router.connect(f.deviceID, 1)
		dispatcher := newDispatcher(f, router, 10*time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		done := make(chan error, 1)
		go func() { done <- dispatcher.Run(ctx) }()
		select {
		case message := <-router.sent:
			assert.Equal(t, f.deliveryID, message.GetManifestDelivery().DeliveryId)
		case <-time.After(2 * time.Second):
			t.Fatal("database sweep did not recover the missed wake")
		}
		cancel()
		require.NoError(t, <-done)
	})
}

func TestDispatcher_WakeQueueIsBounded(t *testing.T) {
	f := newDeliveryFixture(t)
	router := newDeliveryRouter()
	dispatcher := delivery.NewDispatcher(delivery.DispatcherConfig{
		Store: f.store, State: f.service, Router: router, SweepInterval: time.Hour,
		Workers: 1, QueueSize: 1, BatchSize: 1,
	})
	assert.True(t, dispatcher.Wake(f.deliveryID))
	assert.False(t, dispatcher.Wake(newID()), "a full wake queue must not grow without bound")
}

func TestDispatcher_OfflineBacklogCannotStarveConnectedSweep(t *testing.T) {
	f := newDeliveryFixture(t)
	ctx := context.Background()
	row, err := f.store.GetDelivery(ctx, f.deliveryID)
	require.NoError(t, err)
	for range 2 {
		offlineDevice := seedDevice(t, f.raw)
		_, err := f.raw.Exec(ctx, `
			INSERT INTO deliveries
				(delivery_id, device_id, manifest_id, manifest, state, available_at)
			VALUES ($1, $2, $3, $4, 'PENDING', $5)
		`, newID(), offlineDevice, row.ManifestID, row.Manifest, f.now.Add(-time.Hour))
		require.NoError(t, err)
	}

	router := newDeliveryRouter()
	router.connect(f.deviceID, 1)
	dispatcher := delivery.NewDispatcher(delivery.DispatcherConfig{
		Store: f.store, State: f.service, Router: router,
		Now: func() time.Time { return f.now }, SweepInterval: 10 * time.Millisecond,
		Workers: 1, QueueSize: 8, BatchSize: 2,
	})
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- dispatcher.Run(runCtx) }()
	select {
	case message := <-router.sent:
		assert.Equal(t, f.deliveryID, message.GetManifestDelivery().DeliveryId)
	case <-time.After(2 * time.Second):
		t.Fatal("offline due rows starved a connected device's missed wake")
	}
	cancel()
	require.NoError(t, <-done)
}
