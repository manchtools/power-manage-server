package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	defaultSweepInterval = 30 * time.Second
	defaultWorkers       = 8
	defaultQueueSize     = 1024
	defaultBatchSize     = int32(256)
)

// ErrAlreadyRunning means Run was called twice on one dispatcher.
var ErrAlreadyRunning = errors.New("delivery dispatcher already running")

// Router is the process-local agent connection surface the dispatcher needs.
type Router interface {
	Get(deviceID string) (*connection.Agent, bool)
	List() []string
	SendAtEpoch(deviceID string, epoch int64, message *pmv1.ServerMessage) error
}

// DispatcherConfig supplies the durable state and bounded process-local work
// queue. A missed queue notification is harmless because the database sweep is
// the correctness path.
type DispatcherConfig struct {
	Store         *store.Store
	State         *Service
	Router        Router
	Logger        *slog.Logger
	Now           func() time.Time
	SweepInterval time.Duration
	Workers       int
	QueueSize     int
	BatchSize     int32
}

// Dispatcher wakes connected devices and periodically recovers any delivery a
// process-local notification missed.
type Dispatcher struct {
	store         *store.Store
	state         *Service
	router        Router
	logger        *slog.Logger
	now           func() time.Time
	sweepInterval time.Duration
	batchSize     int32
	workers       int
	queue         chan string
	running       atomic.Bool
}

// NewDispatcher constructs a bounded dispatcher.
func NewDispatcher(cfg DispatcherConfig) *Dispatcher {
	if cfg.Store == nil || cfg.State == nil || cfg.Router == nil {
		panic("delivery dispatcher: store, state, and router are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SweepInterval == 0 {
		cfg.SweepInterval = defaultSweepInterval
	}
	if cfg.Workers == 0 {
		cfg.Workers = defaultWorkers
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.SweepInterval < 0 || cfg.Workers < 1 || cfg.QueueSize < 1 || cfg.BatchSize < 1 {
		panic("delivery dispatcher: invalid bounds")
	}
	return &Dispatcher{
		store: cfg.Store, state: cfg.State, router: cfg.Router, logger: cfg.Logger,
		now: cfg.Now, sweepInterval: cfg.SweepInterval, batchSize: cfg.BatchSize,
		workers: cfg.Workers, queue: make(chan string, cfg.QueueSize),
	}
}

// Wake queues one committed delivery without blocking its creating request.
// False means the id was invalid or the bounded queue was full; the periodic
// database sweep will still recover a committed due row.
func (d *Dispatcher) Wake(deliveryID string) bool {
	if !validID(deliveryID) {
		return false
	}
	select {
	case d.queue <- deliveryID:
		return true
	default:
		return false
	}
}

// WakeDevice queues the unfinished deliveries for a newly connected device.
func (d *Dispatcher) WakeDevice(ctx context.Context, deviceID string) error {
	if ctx == nil || !validID(deviceID) {
		return ErrInvalidInput
	}
	rows, err := d.store.ListDeviceDeliveries(ctx, deviceID, d.batchSize)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if !d.Wake(row.DeliveryID) {
			break
		}
	}
	return nil
}

// Run starts the bounded workers and periodic database sweep. Cancellation is
// a clean shutdown; one Dispatcher may have only one active Run call.
func (d *Dispatcher) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInput
	}
	if !d.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer d.running.Store(false)

	var workers sync.WaitGroup
	for range d.workers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			d.worker(ctx)
		}()
	}
	ticker := time.NewTicker(d.sweepInterval)
	defer ticker.Stop()
	defer workers.Wait()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := d.queueDue(ctx); err != nil && !errors.Is(err, context.Canceled) {
				d.logger.Error("delivery sweep failed", "error", err)
			}
		}
	}
}

func (d *Dispatcher) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case deliveryID := <-d.queue:
			if err := d.Dispatch(ctx, deliveryID); err != nil && !errors.Is(err, context.Canceled) {
				d.logger.Error("delivery dispatch failed", "delivery_id", deliveryID, "error", err)
			}
		}
	}
}

func (d *Dispatcher) queueDue(ctx context.Context) error {
	connected := d.router.List()
	if len(connected) == 0 {
		return nil
	}
	rows, err := d.store.ListDueDeliveries(ctx, connected, d.now().UTC(), d.batchSize)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if !d.Wake(row.DeliveryID) {
			break
		}
	}
	return nil
}

// Dispatch attempts one delivery against the device's current connection. An
// offline or just-replaced connection is normal: the row remains durable and a
// reconnect notification or sweep retries it.
func (d *Dispatcher) Dispatch(ctx context.Context, deliveryID string) error {
	if ctx == nil || !validID(deliveryID) {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	row, err := d.store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return err
	}
	if row.State == StateAckedReceipt || terminal(row.State) {
		return nil
	}
	if !pushable(row.State) {
		return ErrInvalidTransition
	}
	agent, connected := d.router.Get(row.DeviceID)
	if !connected || agent == nil {
		return nil
	}
	if agent.Epoch <= 0 {
		return ErrInvalidInput
	}
	// A reconnect should not wait for the previous stream's retry delay. A
	// future PENDING delivery remains scheduled and is never pulled forward.
	if row.AvailableAt.After(d.now()) && !(row.State == StatePushed && agent.Epoch > row.PushEpoch) {
		return nil
	}

	var manifest pmv1.Manifest
	if err := protojson.Unmarshal(row.Manifest, &manifest); err != nil || !validManifest(&manifest) {
		return fmt.Errorf("%w: stored manifest", ErrInvalidInput)
	}
	if manifest.ManifestId != row.ManifestID {
		return ErrWrongManifest
	}
	changed, err := d.state.MarkPushed(ctx, deliveryID, row.DeviceID, agent.Epoch)
	if errors.Is(err, ErrStaleEpoch) {
		return nil
	}
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	message := &pmv1.ServerMessage{
		Id: ulid.Make().String(),
		Payload: &pmv1.ServerMessage_ManifestDelivery{ManifestDelivery: &pmv1.ManifestDelivery{
			DeliveryId: deliveryID, Manifest: &manifest,
		}},
	}
	if err := d.router.SendAtEpoch(row.DeviceID, agent.Epoch, message); err != nil {
		if errors.Is(err, connection.ErrAgentNotConnected) || errors.Is(err, connection.ErrStaleConnection) {
			return nil
		}
		return fmt.Errorf("send manifest delivery: %w", err)
	}
	return nil
}
