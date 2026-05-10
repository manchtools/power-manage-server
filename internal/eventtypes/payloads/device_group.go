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

// DeviceGroupMaintenanceWindowSet is the wire shape for the
// MaintenanceWindowSet event. The maintenance_window value mirrors
// the JSONB shape produced by maintenanceWindowToMap on the handler
// side.
type DeviceGroupMaintenanceWindowSet struct {
	MaintenanceWindow map[string]any `json:"maintenance_window"`
}
