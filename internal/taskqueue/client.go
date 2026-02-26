package taskqueue

import (
	"encoding/json"
	"fmt"

	"github.com/hibiken/asynq"
)

// Client wraps asynq.Client for enqueuing tasks to device and control queues.
type Client struct {
	client *asynq.Client
}

// NewClient creates a new task queue client connected to Valkey.
func NewClient(addr, password string, db int) *Client {
	client := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &Client{client: client}
}

// EnqueueToDevice enqueues a task to a device-specific queue.
// The gateway's per-device Asynq server processes these tasks.
func (c *Client) EnqueueToDevice(deviceID, taskType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	task := asynq.NewTask(taskType, data)
	_, err = c.client.Enqueue(task, asynq.Queue(DeviceQueue(deviceID)))
	if err != nil {
		return fmt.Errorf("enqueue to device %s: %w", deviceID, err)
	}
	return nil
}

// EnqueueToControl enqueues a task to the control inbox queue.
// The control server's Asynq server processes these tasks.
func (c *Client) EnqueueToControl(taskType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	task := asynq.NewTask(taskType, data)
	_, err = c.client.Enqueue(task, asynq.Queue(ControlInboxQueue))
	if err != nil {
		return fmt.Errorf("enqueue to control: %w", err)
	}
	return nil
}

// Close closes the underlying Asynq client connection.
func (c *Client) Close() error {
	return c.client.Close()
}
