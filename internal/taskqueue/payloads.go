package taskqueue

import pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"

// === Control → Gateway payloads (device queues) ===

// ActionDispatchPayload is the payload for TypeActionDispatch tasks.
//
// Clean break (action-signing rewrite): the payload now carries only the
// signed SignedActionEnvelope bytes and the CA signature over them. The
// action type, desired state, timeout, schedule, target device, and typed
// params all live INSIDE the signed envelope, so the gateway no longer
// reconstructs a typed Action or re-serialises params — it forwards
// EnvelopeBytes + Signature verbatim and the agent verifies+unmarshals the
// same bytes. This closes the gap where a compromised gateway/Valkey could
// rewrite the executed action (desired_state, params, type, device) under a
// signature that covered only (id, type, paramsJSON).
//
// ExecutionID is kept OUTSIDE the signed bytes purely for gateway logging /
// task correlation; it is also bound inside the envelope as ActionId, which
// is the authoritative copy the agent trusts.
type ActionDispatchPayload struct {
	ExecutionID string `json:"execution_id"`
	// EnvelopeBytes is the deterministic wire encoding of the signed
	// SignedActionEnvelope (verify.MarshalEnvelope). Transported verbatim
	// to the agent as ActionDispatch.envelope — the exact bytes the
	// signature covers.
	EnvelopeBytes []byte `json:"envelope_bytes"`
	// Signature is the CA signature over EnvelopeBytes.
	Signature []byte `json:"signature"`
}

// OSQueryDispatchPayload is the payload for TypeOSQueryDispatch tasks.
//
// Signature is the CA signature over the canonical bytes of ToProto() under
// verify.OSQuerySignatureDomain (WS4). The control server computes it; the
// gateway copies it onto the wire OSQuery verbatim and NEVER originates it.
type OSQueryDispatchPayload struct {
	QueryID   string   `json:"query_id"`
	Table     string   `json:"table"`
	Columns   []string `json:"columns,omitempty"`
	Limit     int32    `json:"limit,omitempty"`
	RawSQL    string   `json:"raw_sql,omitempty"`
	Signature []byte   `json:"signature,omitempty"`
}

// ToProto builds the wire OSQuery from the payload (signature excluded). It is
// the SINGLE construction site shared by the control server (which signs
// ToProto()'s canonical bytes) and the gateway (which sends ToProto() with the
// carried signature attached) — so the bytes the agent verifies are
// byte-for-byte the bytes the server signed, with no field-mapping drift.
func (p OSQueryDispatchPayload) ToProto() *pm.OSQuery {
	return &pm.OSQuery{
		QueryId: p.QueryID,
		Table:   p.Table,
		Columns: p.Columns,
		Limit:   p.Limit,
		RawSql:  p.RawSQL,
	}
}

// InventoryRequestPayload is the payload for TypeInventoryRequest tasks.
//
// query_id makes a server-originated collection request bindable; Signature is
// the CA signature over ToProto()'s canonical bytes under
// verify.InventorySignatureDomain (WS4).
type InventoryRequestPayload struct {
	QueryID   string `json:"query_id"`
	Signature []byte `json:"signature,omitempty"`
}

// ToProto builds the wire RequestInventory (signature excluded). Shared
// construction site for sign (control) and send (gateway) — see
// OSQueryDispatchPayload.ToProto.
func (p InventoryRequestPayload) ToProto() *pm.RequestInventory {
	return &pm.RequestInventory{QueryId: p.QueryID}
}

// RevokeLuksDeviceKeyPayload is the payload for TypeRevokeLuksDeviceKey tasks.
//
// Signature is the CA signature over ToProto()'s canonical bytes under
// verify.LuksRevokeSignatureDomain (WS4) — binding action_id so a compromised
// gateway cannot forge or replay the destructive slot-7 wipe.
type RevokeLuksDeviceKeyPayload struct {
	ActionID  string `json:"action_id"`
	Signature []byte `json:"signature,omitempty"`
}

// ToProto builds the wire RevokeLuksDeviceKey (signature excluded). Shared
// construction site for sign (control) and send (gateway).
func (p RevokeLuksDeviceKeyPayload) ToProto() *pm.RevokeLuksDeviceKey {
	return &pm.RevokeLuksDeviceKey{ActionId: p.ActionID}
}

// LogQueryDispatchPayload is the payload for TypeLogQueryDispatch tasks.
//
// Signature is the CA signature over ToProto()'s canonical bytes under
// verify.LogQuerySignatureDomain (WS4).
type LogQueryDispatchPayload struct {
	QueryID   string `json:"query_id"`
	Lines     int32  `json:"lines,omitempty"`
	Unit      string `json:"unit,omitempty"`
	Since     string `json:"since,omitempty"`
	Until     string `json:"until,omitempty"`
	Priority  string `json:"priority,omitempty"`
	Grep      string `json:"grep,omitempty"`
	Kernel    bool   `json:"kernel,omitempty"`
	Signature []byte `json:"signature,omitempty"`
}

// ToProto builds the wire LogQuery (signature excluded). Shared construction
// site for sign (control) and send (gateway). NOTE: it must set EXACTLY the
// fields the gateway sends — Source is intentionally omitted here and at the
// gateway, so the canonical bytes match on both sides.
func (p LogQueryDispatchPayload) ToProto() *pm.LogQuery {
	return &pm.LogQuery{
		QueryId:  p.QueryID,
		Lines:    p.Lines,
		Unit:     p.Unit,
		Since:    p.Since,
		Until:    p.Until,
		Priority: p.Priority,
		Grep:     p.Grep,
		Kernel:   p.Kernel,
	}
}

// === Gateway → Control payloads (control:inbox queue) ===

// DeviceHelloPayload is the payload for TypeDeviceHello tasks.
//
// The proto Hello message also carries arch (field 5), but it is deliberately
// NOT forwarded here: the control terminus (handleDeviceHello) only emits a
// DeviceHeartbeat (agent_version + hostname), and os_arch is sourced from the
// inventory/osquery pipeline — nothing consumes a hello-time arch. Per audit
// N008 (see DeviceHeartbeatPayload) we don't transport bytes with no consumer.
// If a future feature wants arch known at connect time (before the first
// inventory), add it here AND give it a projector that writes os_arch, rather
// than carrying an unread field. TestDeviceHelloPayload_WireContract pins the
// exact wire shape so this stays a conscious choice, not silent twin drift.
type DeviceHelloPayload struct {
	DeviceID     string `json:"device_id"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
	// GatewayID self-asserts which gateway relayed this device-origin
	// task. The control:inbox worker cross-references it against the
	// device→gateway routing binding (registry.CheckDeviceGatewayBinding)
	// to confine a device-origin event to the gateway the device is
	// actually live on — the peer-class gateway mTLS cert carries no
	// per-gateway identity, so this is the only binding signal.
	GatewayID string `json:"gateway_id"`
}

// DeviceHeartbeatPayload is the payload for TypeDeviceHeartbeat tasks.
//
// Audit N008: prior versions of this struct also carried
// UptimeSeconds, CpuPercent, MemoryPercent, DiskPercent, but the
// inbox-worker terminus only ever wrote them into the event store —
// nothing read them. There is no device_metrics_projection.
// Dropped from the wire to stop transporting bytes that have no
// consumer; agent handlers stopped reading them off the proto
// Heartbeat at the same time. If a future feature wants live
// metrics, design a dedicated DeviceMetricsPayload + projection
// rather than reanimating these.
type DeviceHeartbeatPayload struct {
	DeviceID     string `json:"device_id"`
	AgentVersion string `json:"agent_version,omitempty"`
	// GatewayID — see DeviceHelloPayload.GatewayID.
	GatewayID string `json:"gateway_id"`
}

// ExecutionResultPayload is the payload for TypeExecutionResult tasks.
// Contains the protojson-encoded ActionResult plus the device ID.
type ExecutionResultPayload struct {
	DeviceID string `json:"device_id"`
	// ActionResultJSON is the protojson-serialized pm.ActionResult.
	ActionResultJSON []byte `json:"action_result_json"`
	// GatewayID — see DeviceHelloPayload.GatewayID.
	GatewayID string `json:"gateway_id"`
}

// ExecutionOutputChunkPayload is the payload for TypeExecutionOutputChunk tasks.
type ExecutionOutputChunkPayload struct {
	DeviceID    string `json:"device_id"`
	ExecutionID string `json:"execution_id"`
	Stream      string `json:"stream"` // "stdout" or "stderr"
	Data        string `json:"data"`
	Sequence    int64  `json:"sequence"`
	// GatewayID — see DeviceHelloPayload.GatewayID.
	GatewayID string `json:"gateway_id"`
}

// OSQueryResultPayload is the payload for TypeOSQueryResult tasks.
type OSQueryResultPayload struct {
	DeviceID string `json:"device_id"`
	QueryID  string `json:"query_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
	RowsJSON []byte `json:"rows_json"` // JSON-encoded []map[string]string
	// GatewayID — see DeviceHelloPayload.GatewayID.
	GatewayID string `json:"gateway_id"`
}

// InventoryUpdatePayload is the payload for TypeInventoryUpdate tasks.
type InventoryUpdatePayload struct {
	DeviceID string           `json:"device_id"`
	Tables   []InventoryTable `json:"tables"`
	// GatewayID — see DeviceHelloPayload.GatewayID.
	GatewayID string `json:"gateway_id"`
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
	// GatewayID — see DeviceHelloPayload.GatewayID.
	GatewayID string `json:"gateway_id"`
}

// RevokeLuksDeviceKeyResultPayload is the payload for TypeRevokeLuksDeviceKeyResult tasks.
type RevokeLuksDeviceKeyResultPayload struct {
	DeviceID string `json:"device_id"`
	ActionID string `json:"action_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
	// GatewayID — see DeviceHelloPayload.GatewayID.
	GatewayID string `json:"gateway_id"`
}

// LogQueryResultPayload is the payload for TypeLogQueryResult tasks.
type LogQueryResultPayload struct {
	DeviceID string `json:"device_id"`
	QueryID  string `json:"query_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
	Logs     string `json:"logs"`
	// GatewayID — see DeviceHelloPayload.GatewayID.
	GatewayID string `json:"gateway_id"`
}

// TerminalAuditChunkPayload carries a stdin chunk from a terminal
// session so the control server's inbox worker can persist it as an
// audit event. Only stdin is audited — stdout is high-volume and
// derivable from input replay.
type TerminalAuditChunkPayload struct {
	SessionID string `json:"session_id"`
	DeviceID  string `json:"device_id"`
	UserID    string `json:"user_id"`
	Data      []byte `json:"data"`
	Sequence  int64  `json:"sequence"`
	// GatewayID — see DeviceHelloPayload.GatewayID. Bound against the
	// DeviceID the audit chunk claims, so a confused/compromised gateway
	// cannot relay terminal-stdin audit bytes for a device that is live
	// on a different gateway.
	GatewayID string `json:"gateway_id"`
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
	Name           string `json:"name"`
	Description    string `json:"description"`
	MemberCount    int32  `json:"member_count,omitempty"`
	Type           int32  `json:"type,omitempty"`
	IsCompliance   bool   `json:"is_compliance,omitempty"`
	ActionNames    string `json:"action_names,omitempty"`
	HasActionNames bool   `json:"has_action_names,omitempty"`

	// Common timestamps
	CreatedAt int64 `json:"created_at,omitempty"`
	UpdatedAt int64 `json:"updated_at,omitempty"`

	// Execution fields
	ActionName     string `json:"action_name,omitempty"`
	DeviceHostname string `json:"device_hostname,omitempty"`
	Status         string `json:"status,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
	DurationMs     int64  `json:"duration_ms,omitempty"`
	Changed        bool   `json:"changed,omitempty"`
	DesiredState   int32  `json:"desired_state,omitempty"`
	ActionID       string `json:"action_id,omitempty"`

	// Device fields
	Hostname         string `json:"hostname,omitempty"`
	AgentVersion     string `json:"agent_version,omitempty"`
	Labels           string `json:"labels,omitempty"`
	ComplianceStatus int32  `json:"compliance_status,omitempty"`
	LastSeenAt       int64  `json:"last_seen_at,omitempty"`
	RegisteredAt     int64  `json:"registered_at,omitempty"`
	OSName           string `json:"os_name,omitempty"`
	OSVersion        string `json:"os_version,omitempty"`
	OSArch           string `json:"os_arch,omitempty"`
	Kernel           string `json:"kernel,omitempty"`

	// User fields
	Email         string `json:"email,omitempty"`
	DisplayName   string `json:"display_name,omitempty"`
	LinuxUsername string `json:"linux_username,omitempty"`
	Disabled      string `json:"disabled,omitempty"`
	Role          string `json:"role,omitempty"`          // #325 TAG filter
	LastLoginAt   int64  `json:"last_login_at,omitempty"` // #325 sortable

	// Device group / User group fields
	IsDynamic string `json:"is_dynamic,omitempty"`

	// #325 filter additions
	Assigned     string `json:"assigned,omitempty"`       // action/action_set/definition: "true"/"false" — directly assigned (TAG)
	RuleCount    int32  `json:"rule_count,omitempty"`     // compliance policy rule count (NUMERIC, sortable)
	HasRuleCount bool   `json:"has_rule_count,omitempty"` // signals RuleCount computed (so 0 is written for the empty-rules filter)

	// Audit event fields
	EventType  string `json:"event_type,omitempty"`
	StreamType string `json:"stream_type,omitempty"`
	ActorType  string `json:"actor_type,omitempty"`
	ActorID    string `json:"actor_id,omitempty"`
	OccurredAt int64  `json:"occurred_at,omitempty"`
	StreamID   string `json:"stream_id,omitempty"`
}
