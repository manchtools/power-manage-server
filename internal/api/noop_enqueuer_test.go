package api

import "github.com/hibiken/asynq"

// This file's `_test.go` suffix means NoOpEnqueuer compiles ONLY
// during `go test`. Production builds do not link it, so a handler
// that accidentally reached for `api.NoOpEnqueuer{}` outside test
// code would fail to build — the same footgun-closing trick as
// NoOpSigner.
//
// Tests that exercise dispatch paths (DispatchAction,
// DispatchInstantAction, device_handler revoke, osquery dispatch,
// logs dispatch) construct their handler, then call
// `h.SetTaskQueueClient(api.NoOpEnqueuer{})` before triggering the
// RPC. Without this, the fail-closed precondition check now rejects
// dispatches with CodeFailedPrecondition — the exact behaviour
// production wants when Valkey is unconfigured, but not what the
// tests are verifying.

// NoOpEnqueuer is a recording no-op taskqueue.Enqueuer for tests.
// Every method succeeds without enqueueing anything. Tests that
// need to assert the dispatch was attempted inspect the recorded
// calls directly.
type NoOpEnqueuer struct {
	// DeviceCalls records each EnqueueToDevice invocation so tests
	// can assert the dispatch reached this boundary. Not protected
	// by a mutex: tests do not run dispatch concurrently in the
	// same handler under current fixtures.
	DeviceCalls []NoOpEnqueuerCall
}

// NoOpEnqueuerCall captures the arguments of one EnqueueToDevice.
type NoOpEnqueuerCall struct {
	DeviceID string
	TaskType string
	Payload  any
}

// EnqueueToDevice records and succeeds.
func (n *NoOpEnqueuer) EnqueueToDevice(deviceID, taskType string, payload any, _ ...asynq.Option) error {
	n.DeviceCalls = append(n.DeviceCalls, NoOpEnqueuerCall{
		DeviceID: deviceID,
		TaskType: taskType,
		Payload:  payload,
	})
	return nil
}

// EnqueueToControl is a no-op.
func (*NoOpEnqueuer) EnqueueToControl(_ string, _ any) error { return nil }

// EnqueueToSearch is a no-op.
func (*NoOpEnqueuer) EnqueueToSearch(_ string, _ any) error { return nil }
