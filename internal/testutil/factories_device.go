package testutil

// Device + device-group fixtures. Membership + assignment helpers
// also live here since they share the device stream.

import (
	"context"
	"testing"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/store"
)

// CreateTestDevice creates a device via events and returns the device ID.
func CreateTestDevice(t *testing.T, st *store.Store, hostname string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   id,
		EventType:  string(eventtypes.DeviceRegistered),
		Data: map[string]any{
			"hostname":      hostname,
			"agent_version": "1.0.0",
		},
		ActorType: "system",
		ActorID:   "test",
	})
	if err != nil {
		t.Fatalf("create test device: %v", err)
	}

	return id
}

// CreateTestDeviceGroup creates a device group via events and returns the group ID.
func CreateTestDeviceGroup(t *testing.T, st *store.Store, actorID, name string) string {
	t.Helper()
	ctx := context.Background()
	id := NewID()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   id,
		EventType:  string(eventtypes.DeviceGroupCreated),
		Data: map[string]any{
			"name":       name,
			"is_dynamic": false,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("create test device group: %v", err)
	}

	return id
}

// AssignDeviceToUser assigns a device to a user via events.
func AssignDeviceToUser(t *testing.T, st *store.Store, actorID, deviceID, userID string) {
	t.Helper()
	ctx := context.Background()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device",
		StreamID:   deviceID,
		EventType:  string(eventtypes.DeviceAssigned),
		Data: map[string]any{
			"user_id": userID,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("assign device to user: %v", err)
	}
}

// AddDeviceToTestGroup adds a device to a device group via events.
func AddDeviceToTestGroup(t *testing.T, st *store.Store, actorID, groupID, deviceID string) {
	t.Helper()
	ctx := context.Background()

	err := st.AppendEvent(ctx, store.Event{
		StreamType: "device_group",
		StreamID:   groupID,
		EventType:  string(eventtypes.DeviceGroupMemberAdded),
		Data: map[string]any{
			"device_id": deviceID,
		},
		ActorType: "user",
		ActorID:   actorID,
	})
	if err != nil {
		t.Fatalf("add device to test group: %v", err)
	}
}
