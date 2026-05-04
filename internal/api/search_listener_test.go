package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
)

// TestAffectedSearchOps is a table-driven exercise of the classifier
// for every event type Phase 1 of #81 covers. A future event type
// added in a handler must show up here with an explicit case (or an
// explicit "no-op" entry) so missed coverage is caught at review
// time rather than as silently-stale search results in production.
func TestAffectedSearchOps(t *testing.T) {
	cases := []struct {
		name      string
		event     store.PersistedEvent
		want      []api.SearchAffected
	}{
		// User scope — reindex on field-changing events
		{
			"UserCreated reindexes user",
			store.PersistedEvent{EventType: "UserCreated", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUser, ID: "USR1"}},
		},
		{
			"UserEmailChanged reindexes user",
			store.PersistedEvent{EventType: "UserEmailChanged", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUser, ID: "USR1"}},
		},
		{
			"UserDisabled reindexes user (the disabled flag is in the search payload)",
			store.PersistedEvent{EventType: "UserDisabled", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUser, ID: "USR1"}},
		},
		{
			"UserProfileUpdated reindexes user (display name lives in the profile payload)",
			store.PersistedEvent{EventType: "UserProfileUpdated", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUser, ID: "USR1"}},
		},
		{
			"UserLinuxUsernameChanged reindexes user",
			store.PersistedEvent{EventType: "UserLinuxUsernameChanged", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUser, ID: "USR1"}},
		},
		{
			"UserDeleted removes user from index",
			store.PersistedEvent{EventType: "UserDeleted", StreamID: "USR1", StreamType: "user"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeUser, ID: "USR1"}},
		},

		// User events that should NOT touch search — proves the
		// classifier doesn't over-trigger.
		{
			"UserPasswordChanged is search-irrelevant",
			store.PersistedEvent{EventType: "UserPasswordChanged", StreamID: "USR1", StreamType: "user"},
			nil,
		},
		{
			"UserSshKeyAdded is search-irrelevant",
			store.PersistedEvent{EventType: "UserSshKeyAdded", StreamID: "USR1", StreamType: "user"},
			nil,
		},
		{
			"UserLoggedIn is search-irrelevant",
			store.PersistedEvent{EventType: "UserLoggedIn", StreamID: "USR1", StreamType: "user"},
			nil,
		},

		// Device scope — reindex on field-changing events
		{
			"DeviceRegistered reindexes device",
			store.PersistedEvent{EventType: "DeviceRegistered", StreamID: "DEV1", StreamType: "device"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDevice, ID: "DEV1"}},
		},
		{
			"DeviceLabelSet reindexes device (labels are searchable)",
			store.PersistedEvent{EventType: "DeviceLabelSet", StreamID: "DEV1", StreamType: "device"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDevice, ID: "DEV1"}},
		},
		{
			"DeviceLabelRemoved reindexes device",
			store.PersistedEvent{EventType: "DeviceLabelRemoved", StreamID: "DEV1", StreamType: "device"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDevice, ID: "DEV1"}},
		},
		{
			"DeviceSyncIntervalSet reindexes device",
			store.PersistedEvent{EventType: "DeviceSyncIntervalSet", StreamID: "DEV1", StreamType: "device"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDevice, ID: "DEV1"}},
		},
		{
			"DeviceDeleted removes device from index",
			store.PersistedEvent{EventType: "DeviceDeleted", StreamID: "DEV1", StreamType: "device"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeDevice, ID: "DEV1"}},
		},

		// Device events that should NOT touch search.
		{
			"DeviceCertRenewed is search-irrelevant",
			store.PersistedEvent{EventType: "DeviceCertRenewed", StreamID: "DEV1", StreamType: "device"},
			nil,
		},
		{
			"DeviceAssigned is search-irrelevant (search payload has no assignee field)",
			store.PersistedEvent{EventType: "DeviceAssigned", StreamID: "DEV1", StreamType: "device"},
			nil,
		},

		// DeviceGroup scope (added in Phase 2 alongside execution).
		{
			"DeviceGroupCreated reindexes device group",
			store.PersistedEvent{EventType: "DeviceGroupCreated", StreamID: "DGRP1", StreamType: "device_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDeviceGroup, ID: "DGRP1"}},
		},
		{
			"DeviceGroupRenamed reindexes device group",
			store.PersistedEvent{EventType: "DeviceGroupRenamed", StreamID: "DGRP1", StreamType: "device_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDeviceGroup, ID: "DGRP1"}},
		},
		{
			"DeviceGroupMemberAdded reindexes device group (member_count changed)",
			store.PersistedEvent{EventType: "DeviceGroupMemberAdded", StreamID: "DGRP1", StreamType: "device_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDeviceGroup, ID: "DGRP1"}},
		},
		{
			"DeviceGroupMaintenanceWindowSet reindexes device group",
			store.PersistedEvent{EventType: "DeviceGroupMaintenanceWindowSet", StreamID: "DGRP1", StreamType: "device_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDeviceGroup, ID: "DGRP1"}},
		},
		{
			"DeviceGroupDeleted removes device group",
			store.PersistedEvent{EventType: "DeviceGroupDeleted", StreamID: "DGRP1", StreamType: "device_group"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeDeviceGroup, ID: "DGRP1"}},
		},
		{
			// DeviceGroupAssigned/Unassigned live on a relationship
			// table, not the device_group projection itself.
			"DeviceGroupAssigned is search-irrelevant",
			store.PersistedEvent{EventType: "DeviceGroupAssigned", StreamID: "DGRP1", StreamType: "device_group"},
			nil,
		},

		// Execution scope — every lifecycle event reindexes
		// because status / duration / action linkage all change.
		// Cover Created + Dispatched + Started + Completed in addition
		// to the four already listed; ExecutionCreated is the
		// most-common path (immediate dispatch) and a regression there
		// would silently break the search index for all new dispatches.
		{
			"ExecutionCreated reindexes execution",
			store.PersistedEvent{EventType: "ExecutionCreated", StreamID: "EXEC1", StreamType: "execution"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeExecution, ID: "EXEC1"}},
		},
		{
			"ExecutionDispatched reindexes execution",
			store.PersistedEvent{EventType: "ExecutionDispatched", StreamID: "EXEC1", StreamType: "execution"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeExecution, ID: "EXEC1"}},
		},
		{
			"ExecutionStarted reindexes execution",
			store.PersistedEvent{EventType: "ExecutionStarted", StreamID: "EXEC1", StreamType: "execution"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeExecution, ID: "EXEC1"}},
		},
		{
			"ExecutionCompleted reindexes execution",
			store.PersistedEvent{EventType: "ExecutionCompleted", StreamID: "EXEC1", StreamType: "execution"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeExecution, ID: "EXEC1"}},
		},
		{
			"ExecutionScheduled reindexes execution",
			store.PersistedEvent{EventType: "ExecutionScheduled", StreamID: "EXEC1", StreamType: "execution"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeExecution, ID: "EXEC1"}},
		},
		{
			"ExecutionCancelled reindexes execution",
			store.PersistedEvent{EventType: "ExecutionCancelled", StreamID: "EXEC1", StreamType: "execution"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeExecution, ID: "EXEC1"}},
		},
		{
			"ExecutionFailed reindexes execution",
			store.PersistedEvent{EventType: "ExecutionFailed", StreamID: "EXEC1", StreamType: "execution"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeExecution, ID: "EXEC1"}},
		},
		{
			"ExecutionTimedOut reindexes execution",
			store.PersistedEvent{EventType: "ExecutionTimedOut", StreamID: "EXEC1", StreamType: "execution"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeExecution, ID: "EXEC1"}},
		},

		// UserGroup scope (added in Phase 2b).
		{
			"UserGroupCreated reindexes user group",
			store.PersistedEvent{EventType: "UserGroupCreated", StreamID: "UGRP1", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},
		{
			"UserGroupUpdated reindexes user group",
			store.PersistedEvent{EventType: "UserGroupUpdated", StreamID: "UGRP1", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},
		{
			"UserGroupMemberAdded reindexes user group (member_count changed)",
			store.PersistedEvent{EventType: "UserGroupMemberAdded", StreamID: "UGRP1", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},
		{
			"UserGroupRoleAssigned reindexes user group (roles list changed)",
			store.PersistedEvent{EventType: "UserGroupRoleAssigned", StreamID: "UGRP1", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},
		{
			"UserGroupMaintenanceWindowSet reindexes user group",
			store.PersistedEvent{EventType: "UserGroupMaintenanceWindowSet", StreamID: "UGRP1", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},
		{
			"UserGroupDeleted removes user group",
			store.PersistedEvent{EventType: "UserGroupDeleted", StreamID: "UGRP1", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},

		// Out-of-scope: event types from handlers not yet ported
		// classify as nil today. When subsequent Phase 2 PRs add a
		// scope they MUST move from nil to a populated slice in the
		// same PR that removes the handler-side enqueue.
		{
			"ActionSetCreated is Phase-2 scope (returns nil today)",
			store.PersistedEvent{EventType: "ActionSetCreated", StreamID: "AS1", StreamType: "action_set"},
			nil,
		},

		// Unknown event type
		{
			"unknown event classifies as no-op",
			store.PersistedEvent{EventType: "SomeNewEventTypeWeHaveNotSeenBefore", StreamID: "X", StreamType: "future"},
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := api.AffectedSearchOps(tc.event)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestSearchListener_NilDepsAreSafe — boot-time guard. If the search
// index isn't configured (single-instance dev without Valkey), the
// listener factory must hand back a no-op closure rather than
// crashing AppendEvent on every write.
func TestSearchListener_NilDepsAreSafe(t *testing.T) {
	listener := api.SearchListener(nil, nil, nil)
	if listener == nil {
		t.Fatal("SearchListener should never return nil — factory contract")
	}
	// Calling the no-op listener must not panic, even with junk data.
	listener(nil, store.PersistedEvent{EventType: "UserCreated", StreamID: "X"})
}
