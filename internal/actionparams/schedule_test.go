package actionparams_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
)

// TestScheduleRoundTrip_PreservesExplicitFalse pins WS1b #4: ActionSchedule is
// serialised via protojson (EmitUnpopulated), so an explicitly-set zero-valued
// field is observable on the wire instead of being dropped — the exact gap that
// let the pm-tty createHome bug fabricate a home the server never asked for.
// The old ScheduleToMap omitted zero values, collapsing "explicitly false" into
// "unset" and, for an all-zero schedule, into "no schedule at all".
func TestScheduleRoundTrip_PreservesExplicitFalse(t *testing.T) {
	// A present schedule whose run_on_assign / skip_if_unchanged are their zero
	// value EXPLICITLY must serialise with those keys present.
	s := &pm.ActionSchedule{Cron: "0 0 * * *", RunOnAssign: false, SkipIfUnchanged: false}
	raw, err := actionparams.ScheduleToRaw(s)
	require.NoError(t, err)
	require.NotNil(t, raw)

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	assert.Contains(t, m, "runOnAssign", "explicit run_on_assign=false must be present on the wire, not dropped")
	assert.Contains(t, m, "skipIfUnchanged", "explicit skip_if_unchanged=false must be present on the wire")

	// Lossless round-trip back to the proto.
	got := actionparams.ScheduleFromJSON(raw)
	require.NotNil(t, got)
	assert.True(t, proto.Equal(s, got), "schedule must round-trip losslessly via protojson")
}

// TestScheduleFromJSON_DistinguishesPresentFromEmpty pins that a present
// schedule object decodes to a non-nil proto (even when all fields are zero),
// while {} / nil / null decode to nil (no schedule) — the presence distinction
// the empty-map shape destroyed.
func TestScheduleFromJSON_DistinguishesPresentFromEmpty(t *testing.T) {
	// Empty / absent → no schedule.
	assert.Nil(t, actionparams.ScheduleFromJSON(nil), "nil bytes → no schedule")
	assert.Nil(t, actionparams.ScheduleFromJSON([]byte("")), "empty bytes → no schedule")
	assert.Nil(t, actionparams.ScheduleFromJSON([]byte("{}")), "{} → no schedule")
	assert.Nil(t, actionparams.ScheduleFromJSON([]byte("  {}  ")), "whitespaced {} → no schedule")
	assert.Nil(t, actionparams.ScheduleFromJSON([]byte("null")), "null → no schedule")

	// A populated object → non-nil proto.
	got := actionparams.ScheduleFromJSON([]byte(`{"runOnAssign":true}`))
	require.NotNil(t, got)
	assert.True(t, got.RunOnAssign)

	// Malformed (non-empty) → nil, swallowed (logged), never a panic.
	assert.Nil(t, actionparams.ScheduleFromJSON([]byte("{not json")))
}

// TestScheduleToRaw_NilOrEmptyIsAbsent pins that BOTH a nil schedule and an
// all-default schedule serialise to a nil RawMessage, so the emitter omits the
// `schedule` key and the projector applies the {interval_hours:8} drift default.
// This is the load-bearing contract the old len-gated ScheduleToMap arranged —
// a required-but-empty schedule must still land on the safe default, not be
// stored as an explicit all-zero (interval_hours:0 ⇒ no drift checks at all).
func TestScheduleToRaw_NilOrEmptyIsAbsent(t *testing.T) {
	rawNil, err := actionparams.ScheduleToRaw(nil)
	require.NoError(t, err)
	assert.Nil(t, rawNil, "nil schedule must serialise to nil so the event omits the schedule key")

	rawEmpty, err := actionparams.ScheduleToRaw(&pm.ActionSchedule{})
	require.NoError(t, err)
	assert.Nil(t, rawEmpty, "an all-default schedule must serialise to nil so the projector applies the interval_hours:8 default")

	// A schedule with ANY non-default field is NOT empty and serialises.
	rawOnFlag, err := actionparams.ScheduleToRaw(&pm.ActionSchedule{RunOnAssign: true})
	require.NoError(t, err)
	require.NotNil(t, rawOnFlag, "a schedule with run_on_assign set must serialise")
	got := actionparams.ScheduleFromJSON(rawOnFlag)
	require.NotNil(t, got)
	assert.True(t, got.RunOnAssign)
	assert.Equal(t, int32(0), got.IntervalHours, "explicit interval_hours:0 is preserved alongside run_on_assign:true")
}

// TestScheduleFromJSON_ReadsLegacySnakeCase pins backward-compatibility with
// event bytes written by the old map-shaped ScheduleToMap (snake_case keys),
// so existing event-store data still rehydrates after the protojson switch.
func TestScheduleFromJSON_ReadsLegacySnakeCase(t *testing.T) {
	got := actionparams.ScheduleFromJSON([]byte(`{"cron":"0 0 * * *","interval_hours":6,"run_on_assign":true}`))
	require.NotNil(t, got)
	assert.Equal(t, "0 0 * * *", got.Cron)
	assert.Equal(t, int32(6), got.IntervalHours)
	assert.True(t, got.RunOnAssign)
}
