package api

import (
	"encoding/json"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/maintenance"
)

// maintenanceWindowToMap turns a proto MaintenanceWindow into the
// JSONB shape stored on group projections. nil and empty windows
// produce an empty map so the projector's COALESCE keeps the column
// at its '{}' default — that way "clear the window" round-trips
// through replay without leaving a residual schedule.
func maintenanceWindowToMap(w *pmv1.MaintenanceWindow) map[string]any {
	if w == nil || len(w.GetSchedule()) == 0 {
		return map[string]any{}
	}
	entries := make([]map[string]any, 0, len(w.GetSchedule()))
	for _, e := range w.GetSchedule() {
		entries = append(entries, map[string]any{
			"days":  e.GetDays(),
			"allow": e.GetAllow(),
		})
	}
	return map[string]any{"schedule": entries}
}

// maintenanceWindowFromJSON deserializes a JSONB column back into a
// proto MaintenanceWindow. Empty/missing payloads return nil so the
// caller can decide whether to surface "no window" vs. "empty
// window" — both mean "no constraint" but the wire form prefers nil
// to keep responses lean.
func maintenanceWindowFromJSON(data []byte) *pmv1.MaintenanceWindow {
	if len(data) == 0 {
		return nil
	}
	var raw struct {
		Schedule []struct {
			Days  []string `json:"days"`
			Allow string   `json:"allow"`
		} `json:"schedule"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	if len(raw.Schedule) == 0 {
		return nil
	}
	w := &pmv1.MaintenanceWindow{
		Schedule: make([]*pmv1.MaintenanceWindowEntry, 0, len(raw.Schedule)),
	}
	for _, e := range raw.Schedule {
		w.Schedule = append(w.Schedule, &pmv1.MaintenanceWindowEntry{
			Days:  e.Days,
			Allow: e.Allow,
		})
	}
	return w
}

// resolveMaintenanceWindowUnion turns a slice of JSONB rows from
// store.ListMaintenanceWindowsForDevice into the union the agent
// will evaluate. Returns nil when the result is unconstrained — the
// wire shape skips an empty MaintenanceWindow on the response.
func resolveMaintenanceWindowUnion(rows [][]byte) *pmv1.MaintenanceWindow {
	if len(rows) == 0 {
		return nil
	}
	windows := make([]*pmv1.MaintenanceWindow, 0, len(rows))
	for _, r := range rows {
		w := maintenanceWindowFromJSON(r)
		if w == nil {
			// JSONB row with empty schedule contributes no constraint
			// in the union; skip rather than collapsing to "always
			// allowed" (the SQL pre-filter already drops empty rows).
			continue
		}
		windows = append(windows, w)
	}
	if len(windows) == 0 {
		return nil
	}
	out := maintenance.Union(windows...)
	if out == nil || len(out.GetSchedule()) == 0 {
		return nil
	}
	return out
}
