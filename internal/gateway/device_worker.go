package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/hibiken/asynq"

	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// DeviceWorkerManager manages per-device Asynq server instances.
// Each connected device gets its own Asynq server processing queue device:<deviceID>
// with concurrency 1 to ensure ordered execution.
type DeviceWorkerManager struct {
	valkeyAddr     string
	valkeyPassword string
	valkeyDB       int
	handlerFactory func(deviceID string) *asynq.ServeMux
	logger         *slog.Logger

	mu      sync.Mutex
	workers map[string]*asynq.Server
}

// NewDeviceWorkerManager creates a new device worker manager.
func NewDeviceWorkerManager(
	valkeyAddr, valkeyPassword string,
	valkeyDB int,
	handlerFactory func(deviceID string) *asynq.ServeMux,
	logger *slog.Logger,
) *DeviceWorkerManager {
	return &DeviceWorkerManager{
		valkeyAddr:     valkeyAddr,
		valkeyPassword: valkeyPassword,
		valkeyDB:       valkeyDB,
		handlerFactory: handlerFactory,
		logger:         logger,
		workers:        make(map[string]*asynq.Server),
	}
}

// StartWorker starts an Asynq server for the given device, processing its device queue.
func (m *DeviceWorkerManager) StartWorker(deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.workers[deviceID]; exists {
		m.logger.Debug("worker already running", "device_id", deviceID)
		return nil
	}

	queue := taskqueue.DeviceQueue(deviceID)
	devLogger := m.logger.With("device_id", deviceID)
	srv := asynq.NewServer(
		asynq.RedisClientOpt{
			Addr:     m.valkeyAddr,
			Password: m.valkeyPassword,
			DB:       m.valkeyDB,
		},
		asynq.Config{
			Concurrency: 1,
			Queues:      map[string]int{queue: 1},
			Logger:      newAsynqLogger(devLogger),
			ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
				retried, _ := asynq.GetRetryCount(ctx)
				maxRetry, _ := asynq.GetMaxRetry(ctx)
				devLogger.Error("task handler failed",
					"task_type", task.Type(),
					"error", err,
					"retry", retried,
					"max_retry", maxRetry,
				)
			}),
		},
	)

	mux := m.handlerFactory(deviceID)
	if err := srv.Start(mux); err != nil {
		return fmt.Errorf("start worker for device %s: %w", deviceID, err)
	}

	m.workers[deviceID] = srv
	m.logger.Debug("device worker started", "device_id", deviceID, "queue", queue)
	return nil
}

// StopWorker stops the Asynq server for the given device.
func (m *DeviceWorkerManager) StopWorker(deviceID string) {
	m.mu.Lock()
	srv, exists := m.workers[deviceID]
	if exists {
		delete(m.workers, deviceID)
	}
	m.mu.Unlock()

	if exists {
		srv.Shutdown()
		m.logger.Debug("device worker stopped", "device_id", deviceID)
	}
}

// StopAll stops all device workers gracefully.
func (m *DeviceWorkerManager) StopAll() {
	m.mu.Lock()
	workers := make(map[string]*asynq.Server, len(m.workers))
	for k, v := range m.workers {
		workers[k] = v
	}
	m.workers = make(map[string]*asynq.Server)
	m.mu.Unlock()

	for deviceID, srv := range workers {
		srv.Shutdown()
		m.logger.Debug("device worker stopped", "device_id", deviceID)
	}
}

// asynqLogger adapts slog.Logger to the asynq.Logger interface.
type asynqLogger struct {
	logger *slog.Logger
}

func newAsynqLogger(l *slog.Logger) *asynqLogger {
	return &asynqLogger{logger: l}
}

func (l *asynqLogger) Debug(args ...any) { l.logger.Debug(fmt.Sprint(args...)) }
func (l *asynqLogger) Info(args ...any)  { l.logger.Info(fmt.Sprint(args...)) }
func (l *asynqLogger) Warn(args ...any)  { l.logger.Warn(fmt.Sprint(args...)) }
func (l *asynqLogger) Error(args ...any) { l.logger.Error(fmt.Sprint(args...)) }
func (l *asynqLogger) Fatal(args ...any) { l.logger.Error(fmt.Sprint(args...)) }
