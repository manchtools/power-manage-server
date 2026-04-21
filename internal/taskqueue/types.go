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

	// TypeLogQueryDispatch dispatches a journalctl log query to a device's agent.
	TypeLogQueryDispatch = "log:dispatch"
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

	// TypeLogQueryResult reports the result of a journalctl log query.
	TypeLogQueryResult = "log:result"

	// TypeTerminalAuditChunk carries a stdin chunk from a terminal
	// session for audit persistence. Enqueued by the gateway's
	// WebSocket bridge and consumed by the control's inbox worker.
	// Only stdin is audited (stdout is high-volume and derivable).
	TypeTerminalAuditChunk = "terminal:audit_chunk"
)

// ControlInboxQueue is the Asynq queue name for gateway → control messages.
const ControlInboxQueue = "control:inbox"

// ControlTerminalAuditQueue is a dedicated Asynq queue for terminal
// stdin audit chunks. The control server runs a second Asynq worker
// against this queue with Concurrency=1 so chunks for the same session
// are applied to the terminal_sessions.input column strictly in order
// — the AppendTerminalSessionChunk query guards against task
// redelivery (dup sequences) but NOT against two workers committing
// different sequences concurrently, which would drop the later
// committer's bytes. Isolating the task type on a serial queue keeps
// the inbox's 10-worker pool available for everything else while the
// audit path stays lossless.
const ControlTerminalAuditQueue = "control:terminal_audit"

// Task type constants for search index updates (search queue).
const (
	// TypeSearchReindex updates a single entity in the search index.
	TypeSearchReindex = "search:reindex"

	// TypeSearchMemberChange updates membership relationships in the search index.
	TypeSearchMemberChange = "search:member_change"

	// TypeSearchRemove removes an entity from the search index.
	TypeSearchRemove = "search:remove"
)

// SearchQueue is the Asynq queue name for search index update tasks.
const SearchQueue = "search"

// DeviceQueue returns the Asynq queue name for a specific device.
// Tasks enqueued to this queue are processed by the per-device Asynq server
// running on the gateway that has the agent connected.
func DeviceQueue(deviceID string) string {
	return "device:" + deviceID
}
