package api

import (
	"encoding/json"
	"testing"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

func TestMaintenanceWindowToMap_NilOrEmpty(t *testing.T) {
	if got := maintenanceWindowToMap(nil); len(got) != 0 {
		t.Fatalf("nil window should produce empty map, got %v", got)
	}
	if got := maintenanceWindowToMap(&pmv1.MaintenanceWindow{}); len(got) != 0 {
		t.Fatalf("empty window should produce empty map, got %v", got)
	}
}

func TestMaintenanceWindowRoundTrip(t *testing.T) {
	in := &pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
		{Days: []string{"mon", "tue"}, Allow: "22:00-06:00"},
		{Days: []string{"sat", "sun"}, Allow: "00:00-23:59"},
	}}
	asMap := maintenanceWindowToMap(in)
	raw, err := json.Marshal(asMap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := maintenanceWindowFromJSON(raw)
	if out == nil {
		t.Fatalf("expected non-nil round-trip, got nil")
	}
	if len(out.Schedule) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out.Schedule))
	}
	if out.Schedule[0].Allow != "22:00-06:00" || out.Schedule[1].Allow != "00:00-23:59" {
		t.Fatalf("ranges round-tripped wrong: %+v", out.Schedule)
	}
	if len(out.Schedule[0].Days) != 2 || out.Schedule[0].Days[0] != "mon" {
		t.Fatalf("days round-tripped wrong: %+v", out.Schedule[0].Days)
	}
}

func TestMaintenanceWindowFromJSON_EmptyAndMalformed(t *testing.T) {
	if got := maintenanceWindowFromJSON(nil); got != nil {
		t.Fatalf("nil bytes should yield nil, got %v", got)
	}
	if got := maintenanceWindowFromJSON([]byte("{}")); got != nil {
		t.Fatalf("empty object should yield nil, got %v", got)
	}
	if got := maintenanceWindowFromJSON([]byte(`{"schedule":[]}`)); got != nil {
		t.Fatalf("empty schedule should yield nil, got %v", got)
	}
	if got := maintenanceWindowFromJSON([]byte("not json")); got != nil {
		t.Fatalf("malformed json should yield nil, got %v", got)
	}
}

func TestResolveMaintenanceWindowUnion(t *testing.T) {
	// Empty input → nil (no constraint).
	if got := resolveMaintenanceWindowUnion(nil); got != nil {
		t.Fatalf("nil rows should resolve to nil window, got %v", got)
	}

	// Two non-empty windows merge by concatenation.
	w1 := []byte(`{"schedule":[{"days":["mon"],"allow":"22:00-06:00"}]}`)
	w2 := []byte(`{"schedule":[{"days":["sat"],"allow":"00:00-23:59"}]}`)
	got := resolveMaintenanceWindowUnion([][]byte{w1, w2})
	if got == nil {
		t.Fatalf("expected non-nil union, got nil")
	}
	if len(got.Schedule) != 2 {
		t.Fatalf("expected 2 union entries, got %d", len(got.Schedule))
	}

	// One row is empty schedule — should be skipped, not collapse the
	// union to "always allowed". The SQL pre-filter normally keeps
	// these out, but Resolve must be defensive in case a future
	// caller bypasses the filter.
	wEmpty := []byte(`{}`)
	got = resolveMaintenanceWindowUnion([][]byte{w1, wEmpty})
	if got == nil {
		t.Fatalf("non-empty + empty must keep the constraint, got nil")
	}
	if len(got.Schedule) != 1 {
		t.Fatalf("empty row should be skipped, expected 1 entry, got %d", len(got.Schedule))
	}

	// All rows empty → nil.
	if got := resolveMaintenanceWindowUnion([][]byte{wEmpty, wEmpty}); got != nil {
		t.Fatalf("all-empty rows should resolve to nil, got %v", got)
	}
}
