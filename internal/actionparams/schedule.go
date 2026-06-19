package actionparams

import (
	"bytes"
	"encoding/json"
	"log/slog"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"google.golang.org/protobuf/proto"
)

// ScheduleToRaw serialises an ActionSchedule proto into the json.RawMessage
// form stored in JSONB event payloads, via the shared protojson marshalOptions
// (EmitUnpopulated). It returns nil — so the emitter omits the `schedule` key —
// in two cases:
//
//   - a nil schedule, and
//   - an all-default schedule (every field at its zero value), detected
//     generically with proto.Equal against the zero message rather than by
//     re-enumerating the field set.
//
// Omitting an empty schedule is load-bearing: the action / action_set /
// definition projectors replace a MISSING schedule key with the drift-prevention
// default `{"interval_hours": 8}` (migration 006 column default). A client that
// sends a required-but-empty schedule must still land on that default, exactly
// as the old len-gated ScheduleToMap arranged.
//
// For any NON-empty schedule, EmitUnpopulated keeps an explicitly-set zero
// value (e.g. interval_hours:0 alongside run_on_assign:true — "run once on
// assign, never on a drift interval") observable on the wire instead of being
// silently dropped and re-defaulted — the pm-tty createHome bug class. And the
// field set is now declared exactly once (the proto), not three times.
func ScheduleToRaw(s *pm.ActionSchedule) (json.RawMessage, error) {
	if s == nil || proto.Equal(s, &pm.ActionSchedule{}) {
		return nil, nil
	}
	b, err := marshalOptions.Marshal(s)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// ScheduleFromJSON deserialises a schedule JSONB column back into an
// ActionSchedule proto via protojson. A populated object decodes to a non-nil
// proto (even when every field is its zero value — presence is the schedule's
// existence, distinct from absence). Empty input, `{}`, or `null` decode to nil
// (no schedule configured) so callers leave the proto field unset rather than
// carrying an all-zeros placeholder.
//
// protojson (DiscardUnknown) accepts BOTH the camelCase names ScheduleToRaw now
// emits and the snake_case names the legacy ScheduleToMap wrote, so existing
// event-store bytes still rehydrate after the switch.
func ScheduleFromJSON(data []byte) *pm.ActionSchedule {
	// Probe for object presence first: an empty object carries no schedule,
	// while a populated object is a schedule even if all fields are zero. This
	// is what distinguishes "explicitly set" from "unset" — protojson alone
	// can't, since both decode to the same all-zero proto.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		// Truly-empty / whitespace-only input is a normal "no schedule" signal —
		// stay silent. Non-empty bytes that fail to parse indicate event-store
		// corruption or schema drift the projector should surface.
		if len(bytes.TrimSpace(data)) > 0 {
			slog.Warn("actionparams: schedule JSON malformed; treating as no schedule",
				"bytes", len(data), "error", err)
		}
		return nil
	}
	if len(probe) == 0 {
		// `{}`, `null` (decodes to nil map), or absent → no schedule.
		return nil
	}
	var s pm.ActionSchedule
	if err := unmarshalOpts.Unmarshal(data, &s); err != nil {
		slog.Warn("actionparams: schedule JSON failed protojson decode; treating as no schedule",
			"bytes", len(data), "error", err)
		return nil
	}
	return &s
}
