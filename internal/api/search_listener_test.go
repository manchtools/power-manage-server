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
		name  string
		event store.PersistedEvent
		want  []api.SearchAffected
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
		// Group-stream events use the group ID directly as StreamID.
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
			"UserGroupQueryUpdated reindexes user group",
			store.PersistedEvent{EventType: "UserGroupQueryUpdated", StreamID: "UGRP1", StreamType: "user_group"},
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

		// Member + role events use a COMPOSITE StreamID
		// "<group_id>:<user_id>" (members) or
		// "<group_id>:role:<role_id>" (roles). The classifier MUST
		// extract the group_id prefix — passing the composite would
		// make loadSearchEntityData fail to find the row and the
		// reindex would silently drop. CodeRabbit catch on PR #112.
		{
			"UserGroupMemberAdded extracts group_id from composite StreamID",
			store.PersistedEvent{EventType: "UserGroupMemberAdded", StreamID: "UGRP1:USR42", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},
		{
			"UserGroupMemberRemoved extracts group_id",
			store.PersistedEvent{EventType: "UserGroupMemberRemoved", StreamID: "UGRP1:USR42", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},
		{
			"UserGroupRoleAssigned extracts group_id from <group>:role:<role> composite",
			store.PersistedEvent{EventType: "UserGroupRoleAssigned", StreamID: "UGRP1:role:ROLE42", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},
		{
			"UserGroupRoleRevoked extracts group_id",
			store.PersistedEvent{EventType: "UserGroupRoleRevoked", StreamID: "UGRP1:role:ROLE42", StreamType: "user_group"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeUserGroup, ID: "UGRP1"}},
		},
		{
			"UserGroupMemberAdded with empty StreamID returns no-op (defensive)",
			store.PersistedEvent{EventType: "UserGroupMemberAdded", StreamID: "", StreamType: "user_group"},
			nil,
		},

		// ActionSet scope (added in Phase 2c). Every classified
		// event has a row — the "every event gets an explicit case"
		// contract documented at the top of the table.
		{
			"ActionSetCreated reindexes set",
			store.PersistedEvent{EventType: "ActionSetCreated", StreamID: "AS1", StreamType: "action_set"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeActionSet, ID: "AS1"}},
		},
		{
			"ActionSetRenamed reindexes set",
			store.PersistedEvent{EventType: "ActionSetRenamed", StreamID: "AS1", StreamType: "action_set"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeActionSet, ID: "AS1"}},
		},
		{
			"ActionSetDescriptionUpdated reindexes set",
			store.PersistedEvent{EventType: "ActionSetDescriptionUpdated", StreamID: "AS1", StreamType: "action_set"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeActionSet, ID: "AS1"}},
		},
		{
			"ActionSetScheduleUpdated reindexes set",
			store.PersistedEvent{EventType: "ActionSetScheduleUpdated", StreamID: "AS1", StreamType: "action_set"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeActionSet, ID: "AS1"}},
		},
		{
			"ActionSetMemberAdded reindexes set (member_count changed)",
			store.PersistedEvent{EventType: "ActionSetMemberAdded", StreamID: "AS1", StreamType: "action_set"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeActionSet, ID: "AS1"}},
		},
		{
			"ActionSetMemberRemoved reindexes set",
			store.PersistedEvent{EventType: "ActionSetMemberRemoved", StreamID: "AS1", StreamType: "action_set"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeActionSet, ID: "AS1"}},
		},
		{
			"ActionSetMemberReordered reindexes set (member-list ordering visible in search)",
			store.PersistedEvent{EventType: "ActionSetMemberReordered", StreamID: "AS1", StreamType: "action_set"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeActionSet, ID: "AS1"}},
		},
		{
			"ActionSetDeleted removes set (cascade IDs resolved at dispatch time)",
			store.PersistedEvent{EventType: "ActionSetDeleted", StreamID: "AS1", StreamType: "action_set"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeActionSet, ID: "AS1"}},
		},

		// Definition scope (added in Phase 2c — same shape as ActionSet).
		{
			"DefinitionCreated reindexes definition",
			store.PersistedEvent{EventType: "DefinitionCreated", StreamID: "DEF1", StreamType: "definition"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDefinition, ID: "DEF1"}},
		},
		{
			"DefinitionRenamed reindexes definition",
			store.PersistedEvent{EventType: "DefinitionRenamed", StreamID: "DEF1", StreamType: "definition"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDefinition, ID: "DEF1"}},
		},
		{
			"DefinitionDescriptionUpdated reindexes definition",
			store.PersistedEvent{EventType: "DefinitionDescriptionUpdated", StreamID: "DEF1", StreamType: "definition"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDefinition, ID: "DEF1"}},
		},
		{
			"DefinitionScheduleUpdated reindexes definition",
			store.PersistedEvent{EventType: "DefinitionScheduleUpdated", StreamID: "DEF1", StreamType: "definition"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDefinition, ID: "DEF1"}},
		},
		{
			"DefinitionMemberAdded reindexes definition",
			store.PersistedEvent{EventType: "DefinitionMemberAdded", StreamID: "DEF1", StreamType: "definition"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDefinition, ID: "DEF1"}},
		},
		{
			"DefinitionMemberRemoved reindexes definition",
			store.PersistedEvent{EventType: "DefinitionMemberRemoved", StreamID: "DEF1", StreamType: "definition"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDefinition, ID: "DEF1"}},
		},
		{
			"DefinitionMemberReordered reindexes definition",
			store.PersistedEvent{EventType: "DefinitionMemberReordered", StreamID: "DEF1", StreamType: "definition"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeDefinition, ID: "DEF1"}},
		},
		{
			"DefinitionDeleted removes definition",
			store.PersistedEvent{EventType: "DefinitionDeleted", StreamID: "DEF1", StreamType: "definition"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeDefinition, ID: "DEF1"}},
		},

		// Action scope (added in Phase 2d). Every classified event
		// has an explicit row.
		{
			"ActionCreated reindexes action",
			store.PersistedEvent{EventType: "ActionCreated", StreamID: "ACT1", StreamType: "action"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeAction, ID: "ACT1"}},
		},
		{
			"ActionRenamed reindexes action",
			store.PersistedEvent{EventType: "ActionRenamed", StreamID: "ACT1", StreamType: "action"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeAction, ID: "ACT1"}},
		},
		{
			"ActionDescriptionUpdated reindexes action",
			store.PersistedEvent{EventType: "ActionDescriptionUpdated", StreamID: "ACT1", StreamType: "action"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeAction, ID: "ACT1"}},
		},
		{
			"ActionParamsUpdated reindexes action (isCompliance derived from params can flip)",
			store.PersistedEvent{EventType: "ActionParamsUpdated", StreamID: "ACT1", StreamType: "action"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeAction, ID: "ACT1"}},
		},
		{
			"ActionDeleted removes action (cascade IDs to parent action_sets resolved at dispatch time)",
			store.PersistedEvent{EventType: "ActionDeleted", StreamID: "ACT1", StreamType: "action"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeAction, ID: "ACT1"}},
		},

		// CompliancePolicy scope (added in Phase 2e). Every classified
		// event has an explicit row.
		{
			"CompliancePolicyCreated reindexes policy",
			store.PersistedEvent{EventType: "CompliancePolicyCreated", StreamID: "CP1", StreamType: "compliance_policy"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeCompliancePolicy, ID: "CP1"}},
		},
		{
			"CompliancePolicyRenamed reindexes policy",
			store.PersistedEvent{EventType: "CompliancePolicyRenamed", StreamID: "CP1", StreamType: "compliance_policy"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeCompliancePolicy, ID: "CP1"}},
		},
		{
			"CompliancePolicyDescriptionUpdated reindexes policy",
			store.PersistedEvent{EventType: "CompliancePolicyDescriptionUpdated", StreamID: "CP1", StreamType: "compliance_policy"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeCompliancePolicy, ID: "CP1"}},
		},
		{
			"CompliancePolicyRuleAdded reindexes policy (rules contribute denormalised action_names)",
			store.PersistedEvent{EventType: "CompliancePolicyRuleAdded", StreamID: "CP1", StreamType: "compliance_policy"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeCompliancePolicy, ID: "CP1"}},
		},
		{
			"CompliancePolicyRuleRemoved reindexes policy",
			store.PersistedEvent{EventType: "CompliancePolicyRuleRemoved", StreamID: "CP1", StreamType: "compliance_policy"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeCompliancePolicy, ID: "CP1"}},
		},
		{
			"CompliancePolicyRuleUpdated reindexes policy",
			store.PersistedEvent{EventType: "CompliancePolicyRuleUpdated", StreamID: "CP1", StreamType: "compliance_policy"},
			[]api.SearchAffected{{Op: api.SearchOpReindex, Scope: search.ScopeCompliancePolicy, ID: "CP1"}},
		},
		{
			"CompliancePolicyDeleted removes policy",
			store.PersistedEvent{EventType: "CompliancePolicyDeleted", StreamID: "CP1", StreamType: "compliance_policy"},
			[]api.SearchAffected{{Op: api.SearchOpRemove, Scope: search.ScopeCompliancePolicy, ID: "CP1"}},
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
