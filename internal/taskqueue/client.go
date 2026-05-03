package taskqueue

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hibiken/asynq"
)

// Enqueuer is the subset of Client that handlers need for
// enqueueing tasks. Making the API-handler fields depend on the
// interface rather than *Client lets tests inject a no-op or
// recording double (see api.NoOpEnqueuer, api_test scope) without
// spinning up a real Valkey — and lets production paths like
// DispatchAction refuse a request when the enqueuer is nil,
// instead of silently swallowing dispatches.
type Enqueuer interface {
	EnqueueToDevice(deviceID, taskType string, payload any, opts ...asynq.Option) error
	EnqueueToControl(taskType string, payload any) error
	EnqueueToSearch(taskType string, payload any) error
	// DeleteScheduledDeviceTask removes a scheduled or pending task
	// from a device's queue by its asynq TaskID. Used by
	// CancelExecution to prune deferred dispatches before they fire.
	// Best-effort: returns nil if the task is not found (already
	// fired, already cancelled, or never existed) so the cancel path
	// stays idempotent.
	DeleteScheduledDeviceTask(deviceID, taskID string) error
}

// Client wraps asynq.Client for enqueuing tasks to device and control queues.
type Client struct {
	client    *asynq.Client
	inspector *asynq.Inspector
}

// Compile-time check that *Client satisfies Enqueuer. A drift here
// means production code stopped matching the handler contract.
var _ Enqueuer = (*Client)(nil)

// NewClient creates a new task queue client connected to Valkey.
func NewClient(addr, password string, db int) *Client {
	opts := asynq.RedisClientOpt{
		Addr:     addr,
		Password: password,
		DB:       db,
	}
	return &Client{
		client:    asynq.NewClient(opts),
		inspector: asynq.NewInspector(opts),
	}
}

// EnqueueToDevice enqueues a task to a device-specific queue.
// The gateway's per-device Asynq server processes these tasks.
// Additional asynq.Option values (MaxRetry, Deadline, etc.) can be passed.
func (c *Client) EnqueueToDevice(deviceID, taskType string, payload any, opts ...asynq.Option) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	task := asynq.NewTask(taskType, data)
	enqueueOpts := append([]asynq.Option{asynq.Queue(DeviceQueue(deviceID))}, opts...)
	_, err = c.client.Enqueue(task, enqueueOpts...)
	if err != nil {
		return fmt.Errorf("enqueue to device %s: %w", deviceID, err)
	}
	return nil
}

// EnqueueToControl enqueues a task to the control inbox queue.
// The control server's Asynq server processes these tasks.
//
// Terminal audit chunks route to their own serial queue
// (ControlTerminalAuditQueue) instead of the main inbox so an
// independent Concurrency=1 worker applies them in order. See
// ControlTerminalAuditQueue for the rationale — the per-chunk
// AppendTerminalSessionChunk query is not safe to run under the
// main inbox's 10-worker pool.
func (c *Client) EnqueueToControl(taskType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	queue := ControlInboxQueue
	if taskType == TypeTerminalAuditChunk {
		queue = ControlTerminalAuditQueue
	}

	task := asynq.NewTask(taskType, data)
	_, err = c.client.Enqueue(task, asynq.Queue(queue))
	if err != nil {
		return fmt.Errorf("enqueue to control: %w", err)
	}
	return nil
}

// EnqueueToSearch enqueues a task to the search index update queue.
func (c *Client) EnqueueToSearch(taskType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	task := asynq.NewTask(taskType, data)
	_, err = c.client.Enqueue(task, asynq.Queue(SearchQueue))
	if err != nil {
		return fmt.Errorf("enqueue to search: %w", err)
	}
	return nil
}

// DeleteScheduledDeviceTask removes a scheduled or pending task from
// a device's queue by its asynq TaskID. Used by CancelExecution to
// prune deferred dispatches before they fire. Best-effort: returns
// nil if the task is not found in either the scheduled or pending
// list (already fired, already cancelled, never existed) so the
// cancel path stays idempotent.
//
// asynq.Inspector.DeleteTask returns asynq.ErrTaskNotFound when the
// task isn't in the specified queue+state; we swallow that and let
// the caller observe the projection's actual status to decide what
// happened.
func (c *Client) DeleteScheduledDeviceTask(deviceID, taskID string) error {
	queue := DeviceQueue(deviceID)
	err := c.inspector.DeleteTask(queue, taskID)
	if err == nil {
		return nil
	}
	if errors.Is(err, asynq.ErrTaskNotFound) || errors.Is(err, asynq.ErrQueueNotFound) {
		return nil
	}
	return fmt.Errorf("delete task %s in %s: %w", taskID, queue, err)
}

// Close closes the underlying Asynq client connection.
func (c *Client) Close() error {
	if err := c.inspector.Close(); err != nil {
		// Inspector close errors are non-fatal — the underlying
		// connection is shared with the client which we still close
		// below. Log via the returned error from client.Close so the
		// caller sees the more authoritative failure.
		_ = err
	}
	return c.client.Close()
}
