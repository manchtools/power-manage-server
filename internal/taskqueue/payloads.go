package taskqueue

import "encoding/json"

// === Control → Gateway payloads (device queues) ===

// ActionDispatchPayload is the payload for TypeActionDispatch tasks.
type ActionDispatchPayload struct {
	ExecutionID     string          `json:"execution_id"`
	ActionType      int32           `json:"action_type"`
	DesiredState    int32           `json:"desired_state"`
	Params          json.RawMessage `json:"params"`
	TimeoutSeconds  int32           `json:"timeout_seconds"`
	Signature       []byte          `json:"signature,omitempty"`
	ParamsCanonical []byte          `json:"params_canonical,omitempty"`
}

// OSQueryDispatchPayload is the payload for TypeOSQueryDispatch tasks.
type OSQueryDispatchPayload struct {
	QueryID string   `json:"query_id"`
	Table   string   `json:"table"`
	Columns []string `json:"columns,omitempty"`
	Limit   int32    `json:"limit,omitempty"`
	RawSQL  string   `json:"raw_sql,omitempty"`
}

// InventoryRequestPayload is the payload for TypeInventoryRequest tasks.
// Currently empty — the agent just needs the signal.
type InventoryRequestPayload struct{}

// RevokeLuksDeviceKeyPayload is the payload for TypeRevokeLuksDeviceKey tasks.
type RevokeLuksDeviceKeyPayload struct {
	ActionID string `json:"action_id"`
}

// === Gateway → Control payloads (control:inbox queue) ===

// DeviceHelloPayload is the payload for TypeDeviceHello tasks.
type DeviceHelloPayload struct {
	DeviceID     string `json:"device_id"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
}

// DeviceHeartbeatPayload is the payload for TypeDeviceHeartbeat tasks.
type DeviceHeartbeatPayload struct {
	DeviceID       string  `json:"device_id"`
	AgentVersion   string  `json:"agent_version,omitempty"`
	UptimeSeconds  int64   `json:"uptime_seconds,omitempty"`
	CpuPercent     float32 `json:"cpu_percent,omitempty"`
	MemoryPercent  float32 `json:"memory_percent,omitempty"`
	DiskPercent    float32 `json:"disk_percent,omitempty"`
}

// ExecutionResultPayload is the payload for TypeExecutionResult tasks.
// Contains the protojson-encoded ActionResult plus the device ID.
type ExecutionResultPayload struct {
	DeviceID    string `json:"device_id"`
	// ActionResultJSON is the protojson-serialized pm.ActionResult.
	ActionResultJSON []byte `json:"action_result_json"`
}

// ExecutionOutputChunkPayload is the payload for TypeExecutionOutputChunk tasks.
type ExecutionOutputChunkPayload struct {
	DeviceID    string `json:"device_id"`
	ExecutionID string `json:"execution_id"`
	Stream      string `json:"stream"` // "stdout" or "stderr"
	Data        string `json:"data"`
	Sequence    int64  `json:"sequence"`
}

// OSQueryResultPayload is the payload for TypeOSQueryResult tasks.
type OSQueryResultPayload struct {
	DeviceID string `json:"device_id"`
	QueryID  string `json:"query_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
	RowsJSON []byte `json:"rows_json"` // JSON-encoded []map[string]string
}

// InventoryUpdatePayload is the payload for TypeInventoryUpdate tasks.
type InventoryUpdatePayload struct {
	DeviceID string           `json:"device_id"`
	Tables   []InventoryTable `json:"tables"`
}

// InventoryTable is a single inventory table in an update.
type InventoryTable struct {
	TableName string `json:"table_name"`
	RowsJSON  []byte `json:"rows_json"` // JSON-encoded []map[string]string
}

// SecurityAlertPayload is the payload for TypeSecurityAlert tasks.
type SecurityAlertPayload struct {
	DeviceID  string            `json:"device_id"`
	AlertType string            `json:"alert_type"`
	Message   string            `json:"message"`
	Details   map[string]string `json:"details,omitempty"`
}

// RevokeLuksDeviceKeyResultPayload is the payload for TypeRevokeLuksDeviceKeyResult tasks.
type RevokeLuksDeviceKeyResultPayload struct {
	DeviceID string `json:"device_id"`
	ActionID string `json:"action_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

// === Search index payloads (search queue) ===

// SearchReindexPayload is the payload for TypeSearchReindex tasks.
// Data is pre-populated by the API handler to avoid re-reading from PG.
type SearchReindexPayload struct {
	Scope string            `json:"scope"` // "action", "action_set", or "definition"
	ID    string            `json:"id"`
	Data  *SearchEntityData `json:"data,omitempty"`
}

// SearchMemberChangePayload is the payload for TypeSearchMemberChange tasks.
type SearchMemberChangePayload struct {
	ParentScope string `json:"parent_scope"` // "action_set" or "definition"
	ParentID    string `json:"parent_id"`
	ChildScope  string `json:"child_scope"` // "action" or "action_set"
	ChildID     string `json:"child_id"`
	ChildName   string `json:"child_name"` // pre-resolved by handler
	Action      string `json:"action"`     // "add" or "remove"
}

// SearchRemovePayload is the payload for TypeSearchRemove tasks.
type SearchRemovePayload struct {
	Scope      string   `json:"scope"`
	ID         string   `json:"id"`
	CascadeIDs []string `json:"cascade_ids,omitempty"`
}

// SearchEntityData carries pre-populated entity data in search payloads.
type SearchEntityData struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	MemberCount  int32  `json:"member_count,omitempty"`
	Type         int32  `json:"type,omitempty"`
	IsCompliance bool   `json:"is_compliance,omitempty"`
}
