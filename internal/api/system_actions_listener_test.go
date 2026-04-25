package api

import (
	"encoding/json"
	"testing"

	"github.com/manchtools/power-manage/server/internal/store"
)

// TestAffectedFromEvent covers the rc11 #77 derived-projection
// classifier. Each case asserts the (op, userIDs) pair AffectedFromEvent
// returns for a representative event of each handled type. Adding a
// new permission-shaping event type to the system requires extending
// AffectedFromEvent; adding the case here is the test that locks in
// the contract.
//
// Coverage rules of thumb:
//   - Per-user events emit SyncOpSyncUser with one user ID.
//   - Fan-out events emit SyncOpSyncAll with no user IDs.
//   - UserDeleted is handled in the originating handler (load-before-emit
//     ordering), so the listener returns SyncOpNone — see the comment
//     on the UserDeleted case in AffectedFromEvent.
//   - Unknown event types return SyncOpNone.
func TestAffectedFromEvent(t *testing.T) {
	cases := []struct {
		name       string
		event      store.PersistedEvent
		wantOp     SyncOp
		wantUsers  []string
	}{
		// Per-user events keyed by stream_id.
		{
			name: "UserCreated → sync user (stream_id)",
			event: store.PersistedEvent{
				StreamType: "user",
				StreamID:   "user-1",
				EventType:  "UserCreated",
			},
			wantOp:    SyncOpSyncUser,
			wantUsers: []string{"user-1"},
		},
		{
			name: "UserDisabled → sync user",
			event: store.PersistedEvent{
				StreamType: "user",
				StreamID:   "user-2",
				EventType:  "UserDisabled",
			},
			wantOp:    SyncOpSyncUser,
			wantUsers: []string{"user-2"},
		},
		{
			name: "UserLinuxUsernameChanged → sync user",
			event: store.PersistedEvent{
				StreamType: "user",
				StreamID:   "user-3",
				EventType:  "UserLinuxUsernameChanged",
			},
			wantOp:    SyncOpSyncUser,
			wantUsers: []string{"user-3"},
		},
		{
			name: "UserSshKeyAdded → sync user",
			event: store.PersistedEvent{
				StreamType: "user",
				StreamID:   "user-4",
				EventType:  "UserSshKeyAdded",
			},
			wantOp:    SyncOpSyncUser,
			wantUsers: []string{"user-4"},
		},

		// Per-user events keyed by event.data.user_id.
		{
			name: "UserRoleAssigned → sync user (from data.user_id)",
			event: store.PersistedEvent{
				StreamType: "user_role",
				StreamID:   "user-5:role-x",
				EventType:  "UserRoleAssigned",
				Data:       mustMarshalJSON(t, map[string]any{"user_id": "user-5", "role_id": "role-x"}),
			},
			wantOp:    SyncOpSyncUser,
			wantUsers: []string{"user-5"},
		},
		{
			name: "UserRoleRevoked → sync user",
			event: store.PersistedEvent{
				StreamType: "user_role",
				StreamID:   "user-6:role-y",
				EventType:  "UserRoleRevoked",
				Data:       mustMarshalJSON(t, map[string]any{"user_id": "user-6", "role_id": "role-y"}),
			},
			wantOp:    SyncOpSyncUser,
			wantUsers: []string{"user-6"},
		},
		{
			name: "UserGroupMemberAdded → sync user (from data.user_id)",
			event: store.PersistedEvent{
				StreamType: "user_group",
				StreamID:   "group-1",
				EventType:  "UserGroupMemberAdded",
				Data:       mustMarshalJSON(t, map[string]any{"user_id": "user-7", "group_id": "group-1"}),
			},
			wantOp:    SyncOpSyncUser,
			wantUsers: []string{"user-7"},
		},

		// Fan-out events — sync everyone.
		{
			name: "RoleUpdated → sync all (every holder may have changed permissions)",
			event: store.PersistedEvent{
				StreamType: "role",
				StreamID:   "role-x",
				EventType:  "RoleUpdated",
			},
			wantOp:    SyncOpSyncAll,
			wantUsers: nil,
		},
		{
			name: "RoleDeleted → sync all",
			event: store.PersistedEvent{
				StreamType: "role",
				StreamID:   "role-x",
				EventType:  "RoleDeleted",
			},
			wantOp:    SyncOpSyncAll,
			wantUsers: nil,
		},
		{
			name: "UserGroupRoleAssigned → sync all (every group member affected)",
			event: store.PersistedEvent{
				StreamType: "user_group",
				StreamID:   "group-1",
				EventType:  "UserGroupRoleAssigned",
			},
			wantOp:    SyncOpSyncAll,
			wantUsers: nil,
		},
		{
			name: "UserGroupDeleted → sync all",
			event: store.PersistedEvent{
				StreamType: "user_group",
				StreamID:   "group-1",
				EventType:  "UserGroupDeleted",
			},
			wantOp:    SyncOpSyncAll,
			wantUsers: nil,
		},
		{
			name: "ServerSettingUpdated → sync all (provisioning/SSH global flip affects everyone)",
			event: store.PersistedEvent{
				StreamType: "server_settings",
				StreamID:   "global",
				EventType:  "ServerSettingUpdated",
			},
			wantOp:    SyncOpSyncAll,
			wantUsers: nil,
		},

		// Deliberate no-ops.
		{
			name: "UserDeleted → SyncOpNone (handler-side cleanup; see classifier comment)",
			event: store.PersistedEvent{
				StreamType: "user",
				StreamID:   "user-99",
				EventType:  "UserDeleted",
			},
			wantOp:    SyncOpNone,
			wantUsers: nil,
		},
		{
			name: "Unknown event type → SyncOpNone",
			event: store.PersistedEvent{
				StreamType: "device",
				StreamID:   "device-1",
				EventType:  "DeviceRegistered",
			},
			wantOp:    SyncOpNone,
			wantUsers: nil,
		},
		{
			name: "UserRoleAssigned with missing user_id in data → SyncOpNone (defensive)",
			event: store.PersistedEvent{
				StreamType: "user_role",
				StreamID:   "user-x:role-y",
				EventType:  "UserRoleAssigned",
				Data:       mustMarshalJSON(t, map[string]any{"role_id": "role-y"}),
			},
			wantOp:    SyncOpNone,
			wantUsers: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotOp, gotUsers := AffectedFromEvent(tc.event)
			if gotOp != tc.wantOp {
				t.Errorf("op = %v, want %v", gotOp, tc.wantOp)
			}
			if !equalStringSlices(gotUsers, tc.wantUsers) {
				t.Errorf("users = %v, want %v", gotUsers, tc.wantUsers)
			}
		})
	}
}

func mustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
