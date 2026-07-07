package payloads

// DeviceGroupCreated is the wire shape for DeviceGroupCreated.
// Mirrors the historical map[string]any{} key set verbatim — the
// projector decoder accepts both the original payload and any future
// payload encoded via this struct because the JSON keys are identical.
type DeviceGroupCreated struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	IsDynamic    bool   `json:"is_dynamic"`
	DynamicQuery string `json:"dynamic_query"`
}

// DeviceGroupRenamed is the wire shape for DeviceGroupRenamed.
type DeviceGroupRenamed struct {
	Name string `json:"name"`
}

// DeviceGroupDescriptionUpdated is the wire shape for
// DeviceGroupDescriptionUpdated.
type DeviceGroupDescriptionUpdated struct {
	Description string `json:"description"`
}

// DeviceGroupMemberAdded / DeviceGroupMemberRemoved share the
// device_id-only shape — the StreamID carries the group identity, and
// the projector reads device_id off the payload.
type DeviceGroupMemberAdded struct {
	DeviceID string `json:"device_id"`
}

type DeviceGroupMemberRemoved struct {
	DeviceID string `json:"device_id"`
}

// DeviceGroupMembersReevaluated is the wire shape for the dynamic-group
// membership delta the evaluator emits (#7 spec 14). StreamID carries the group
// id; the payload carries the device ids added and removed by this evaluation.
// Audited + consumed by api/SearchListener to reindex the affected devices.
type DeviceGroupMembersReevaluated struct {
	AddedDeviceIDs   []string `json:"added_device_ids,omitempty"`
	RemovedDeviceIDs []string `json:"removed_device_ids,omitempty"`
}

// DeviceGroupQueryUpdated toggles a static group to dynamic (or back).
type DeviceGroupQueryUpdated struct {
	IsDynamic    bool   `json:"is_dynamic"`
	DynamicQuery string `json:"dynamic_query"`
}

// DeviceGroupSyncIntervalSet is the wire shape for the per-group sync
// interval override (zero means "use server default").
type DeviceGroupSyncIntervalSet struct {
	SyncIntervalMinutes int32 `json:"sync_interval_minutes"`
}

// DeviceGroupInventoryIntervalSet is the wire shape for the per-group
// inventory-collection interval (spec 22; zero means "no group
// contribution" to the device's resolved interval).
type DeviceGroupInventoryIntervalSet struct {
	InventoryIntervalMinutes int32 `json:"inventory_interval_minutes"`
}

// DeviceGroupMaintenanceWindowSet is the wire shape for the
// MaintenanceWindowSet event. The maintenance_window value mirrors
// the JSONB shape produced by maintenanceWindowToMap on the handler
// side.
type DeviceGroupMaintenanceWindowSet struct {
	MaintenanceWindow map[string]any `json:"maintenance_window"`
}
