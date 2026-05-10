// Package api file action_schedule.go — schedule encode / decode
// helpers extracted from the action_handler.go god file (audit F005).
//
// scheduleToMap is the emit-side helper used by Create / Update RPCs;
// scheduleFromJSON is the read-side helper used by actionToProto when
// rehydrating an action from its projection row. Both intentionally
// stay in the api package — the schedule shape is part of the
// projection-to-proto translation contract, not a generic encoder.
package api

import (
	"encoding/json"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// scheduleToMap converts an ActionSchedule proto to a map for event storage.
func scheduleToMap(s *pm.ActionSchedule) map[string]any {
	m := map[string]any{}
	if s.Cron != "" {
		m["cron"] = s.Cron
	}
	if s.IntervalHours > 0 {
		m["interval_hours"] = s.IntervalHours
	}
	if s.RunOnAssign {
		m["run_on_assign"] = true
	}
	if s.SkipIfUnchanged {
		m["skip_if_unchanged"] = true
	}
	return m
}

// scheduleFromJSON deserializes a schedule JSONB column into an ActionSchedule proto.
func scheduleFromJSON(data []byte) *pm.ActionSchedule {
	var raw struct {
		Cron            string `json:"cron"`
		IntervalHours   int32  `json:"interval_hours"`
		RunOnAssign     bool   `json:"run_on_assign"`
		SkipIfUnchanged bool   `json:"skip_if_unchanged"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	// Empty object means no schedule configured
	if raw.Cron == "" && raw.IntervalHours == 0 && !raw.RunOnAssign && !raw.SkipIfUnchanged {
		return nil
	}
	return &pm.ActionSchedule{
		Cron:            raw.Cron,
		IntervalHours:   raw.IntervalHours,
		RunOnAssign:     raw.RunOnAssign,
		SkipIfUnchanged: raw.SkipIfUnchanged,
	}
}
