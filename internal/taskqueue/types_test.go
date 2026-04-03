package taskqueue

import "testing"

func TestDeviceQueue(t *testing.T) {
	tests := []struct {
		deviceID string
		want     string
	}{
		{"abc123", "device:abc123"},
		{"", "device:"},
		{"01JQXYZ", "device:01JQXYZ"},
		{"device-with-dashes", "device:device-with-dashes"},
	}

	for _, tt := range tests {
		got := DeviceQueue(tt.deviceID)
		if got != tt.want {
			t.Errorf("DeviceQueue(%q) = %q, want %q", tt.deviceID, got, tt.want)
		}
	}
}

func TestControlInboxQueueConstant(t *testing.T) {
	if ControlInboxQueue == "" {
		t.Fatal("ControlInboxQueue must not be empty")
	}
	if ControlInboxQueue != "control:inbox" {
		t.Fatalf("ControlInboxQueue = %q, want %q", ControlInboxQueue, "control:inbox")
	}
}

func TestSearchQueueConstant(t *testing.T) {
	if SearchQueue == "" {
		t.Fatal("SearchQueue must not be empty")
	}
	if SearchQueue != "search" {
		t.Fatalf("SearchQueue = %q, want %q", SearchQueue, "search")
	}
}

func TestTaskTypeConstants_NonEmpty(t *testing.T) {
	types := []struct {
		name  string
		value string
	}{
		{"TypeActionDispatch", TypeActionDispatch},
		{"TypeOSQueryDispatch", TypeOSQueryDispatch},
		{"TypeInventoryRequest", TypeInventoryRequest},
		{"TypeRevokeLuksDeviceKey", TypeRevokeLuksDeviceKey},
		{"TypeLogQueryDispatch", TypeLogQueryDispatch},
		{"TypeTriggerUpdate", TypeTriggerUpdate},
		{"TypeDeviceHello", TypeDeviceHello},
		{"TypeDeviceHeartbeat", TypeDeviceHeartbeat},
		{"TypeExecutionResult", TypeExecutionResult},
		{"TypeExecutionOutputChunk", TypeExecutionOutputChunk},
		{"TypeOSQueryResult", TypeOSQueryResult},
		{"TypeInventoryUpdate", TypeInventoryUpdate},
		{"TypeSecurityAlert", TypeSecurityAlert},
		{"TypeRevokeLuksDeviceKeyResult", TypeRevokeLuksDeviceKeyResult},
		{"TypeLogQueryResult", TypeLogQueryResult},
		{"TypeSearchReindex", TypeSearchReindex},
		{"TypeSearchMemberChange", TypeSearchMemberChange},
		{"TypeSearchRemove", TypeSearchRemove},
	}

	for _, tt := range types {
		if tt.value == "" {
			t.Errorf("%s must not be empty", tt.name)
		}
	}
}

func TestTaskTypeConstants_Unique(t *testing.T) {
	types := map[string]string{
		"TypeActionDispatch":             TypeActionDispatch,
		"TypeOSQueryDispatch":            TypeOSQueryDispatch,
		"TypeInventoryRequest":           TypeInventoryRequest,
		"TypeRevokeLuksDeviceKey":        TypeRevokeLuksDeviceKey,
		"TypeLogQueryDispatch":           TypeLogQueryDispatch,
		"TypeTriggerUpdate":              TypeTriggerUpdate,
		"TypeDeviceHello":                TypeDeviceHello,
		"TypeDeviceHeartbeat":            TypeDeviceHeartbeat,
		"TypeExecutionResult":            TypeExecutionResult,
		"TypeExecutionOutputChunk":       TypeExecutionOutputChunk,
		"TypeOSQueryResult":              TypeOSQueryResult,
		"TypeInventoryUpdate":            TypeInventoryUpdate,
		"TypeSecurityAlert":              TypeSecurityAlert,
		"TypeRevokeLuksDeviceKeyResult":  TypeRevokeLuksDeviceKeyResult,
		"TypeLogQueryResult":             TypeLogQueryResult,
		"TypeSearchReindex":              TypeSearchReindex,
		"TypeSearchMemberChange":         TypeSearchMemberChange,
		"TypeSearchRemove":               TypeSearchRemove,
	}

	seen := make(map[string]string) // value -> name
	for name, value := range types {
		if existing, ok := seen[value]; ok {
			t.Errorf("duplicate task type value %q: %s and %s", value, existing, name)
		}
		seen[value] = name
	}
}
