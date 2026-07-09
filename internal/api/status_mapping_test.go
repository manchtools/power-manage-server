package api

import (
	"testing"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// TestExecutionStatusMapping_RoundTripsEveryEnumValue is self-discovering
// over the proto enum registry: every ExecutionStatus the SDK defines
// (except UNSPECIFIED) must map to a non-empty projection string and back
// to itself. A new enum value added in the SDK without a statusToString /
// stringToStatus case fails here instead of silently mapping to "" —
// which would corrupt the ListExecutions status filter and GetExecution
// responses.
func TestExecutionStatusMapping_RoundTripsEveryEnumValue(t *testing.T) {
	checked := 0
	for num, name := range pm.ExecutionStatus_name {
		s := pm.ExecutionStatus(num)
		if s == pm.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED {
			continue
		}
		checked++
		str := statusToString(s)
		if str == "" {
			t.Errorf("statusToString(%s) = \"\" — add a case for the new enum value", name)
			continue
		}
		if got := stringToStatus(str); got != s {
			t.Errorf("stringToStatus(statusToString(%s)) = %s, want %s", name, got, s)
		}
	}
	// Matches-zero guard: if the registry iteration ever finds nothing,
	// the test is broken, not the code.
	if checked == 0 {
		t.Fatal("enum registry iteration found no ExecutionStatus values — test harness broken")
	}
}
