// Package taskqueue provides Asynq-based task queue types and helpers
// for communication between the control server and gateway via Valkey.
package taskqueue

// Task type constants for control → gateway communication (device queues).
const (
	// TypeActionDispatch dispatches an action execution to a device's agent.
	TypeActionDispatch = "action:dispatch"

	// TypeOSQueryDispatch dispatches an on-demand OSQuery to a device's agent.
	TypeOSQueryDispatch = "osquery:dispatch"

	// TypeInventoryRequest requests fresh inventory collection from a device.
	TypeInventoryRequest = "inventory:request"

	// TypeRevokeLuksDeviceKey instructs an agent to revoke the device-bound LUKS key.
	TypeRevokeLuksDeviceKey = "luks:revoke_device_key"
)

// Task type constants for gateway → control communication (control:inbox queue).
const (
	// TypeDeviceHello is sent when an agent first connects.
	TypeDeviceHello = "device:hello"

	// TypeDeviceHeartbeat is sent periodically by connected agents.
	TypeDeviceHeartbeat = "device:heartbeat"

	// TypeExecutionResult reports an action execution result.
	TypeExecutionResult = "execution:result"

	// TypeExecutionOutputChunk streams output from a running execution.
	TypeExecutionOutputChunk = "execution:output_chunk"

	// TypeOSQueryResult reports the result of an on-demand OSQuery.
	TypeOSQueryResult = "osquery:result"

	// TypeInventoryUpdate sends device inventory data.
	TypeInventoryUpdate = "inventory:update"

	// TypeSecurityAlert reports a security event from an agent.
	TypeSecurityAlert = "security:alert"

	// TypeRevokeLuksDeviceKeyResult reports the result of a LUKS key revocation.
	TypeRevokeLuksDeviceKeyResult = "luks:revoke_device_key_result"
)

// ControlInboxQueue is the Asynq queue name for gateway → control messages.
const ControlInboxQueue = "control:inbox"

// DeviceQueue returns the Asynq queue name for a specific device.
// Tasks enqueued to this queue are processed by the per-device Asynq server
// running on the gateway that has the agent connected.
func DeviceQueue(deviceID string) string {
	return "device:" + deviceID
}
