package actionparams

import (
	"encoding/json"
	"log/slog"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// ScheduleToMap converts an ActionSchedule proto into the map shape
// used for JSONB event payloads. Empty-valued fields are omitted so
// the projector's ON CONFLICT / COALESCE behaviour treats them as
// "preserve" rather than "set to zero".
//
// Used by the action / action_set / definition handlers when emitting
// XxxCreated / XxxUpdated events. Centralised here so the serialised
// shape stays identical across handlers — drift would surface as
// silently-different schedule semantics depending on which entity
// the schedule was attached to.
func ScheduleToMap(s *pm.ActionSchedule) map[string]any {
	m := map[string]any{}
	if s == nil {
		return m
	}
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

// ScheduleFromJSON deserialises a schedule JSONB column back into an
// ActionSchedule proto. Returns nil for malformed JSON or for the
// empty-object case (so callers can leave the proto field unset
// instead of carrying an all-zeros placeholder).
func ScheduleFromJSON(data []byte) *pm.ActionSchedule {
	var raw struct {
		Cron            string `json:"cron"`
		IntervalHours   int32  `json:"interval_hours"`
		RunOnAssign     bool   `json:"run_on_assign"`
		SkipIfUnchanged bool   `json:"skip_if_unchanged"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		// Truly-empty input is a normal "no schedule configured"
		// signal — stay silent. Non-empty bytes that fail to parse
		// indicate event-store corruption or a schema drift the
		// projector should surface, so emit a structured log so
		// operators can grep for it.
		if len(data) > 0 {
			slog.Warn("actionparams: schedule JSON malformed; treating as no schedule",
				"bytes", len(data), "error", err)
		}
		return nil
	}
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
