// Package eventtypes is the single source of truth for event-type
// string identifiers stored in the events table. Constants here catch
// typos at compile time that would otherwise silently mis-dispatch
// (a bare `case "UserCrated":` matches no event, projects nothing,
// and never errors). Every emit site and every listener switch in the
// server should reference a constant from this package instead of a
// bare string literal.
//
// The constants intentionally retain the exact wire-string values the
// server has always written into events.event_type — the events table
// schema does not change, the JSON-encoded event_type column stays a
// plain string, and historical events stay readable.
package eventtypes

// EventType is the typed wrapper for an event-type identifier. Stored
// as the bare string in the events table; the type alias only
// constrains where a string literal can be passed at the Go layer.
// Convert with string(eventtypes.X) at the boundary with store.Event,
// where the field is intentionally still a plain string (matching the
// JSONB column).
type EventType string

const (
	// action stream
	ActionCreated            EventType = "ActionCreated"
	ActionRenamed            EventType = "ActionRenamed"
	ActionDescriptionUpdated EventType = "ActionDescriptionUpdated"
	ActionParamsUpdated      EventType = "ActionParamsUpdated"
	ActionDeleted            EventType = "ActionDeleted"

	// definition stream
	DefinitionCreated            EventType = "DefinitionCreated"
	DefinitionRenamed            EventType = "DefinitionRenamed"
	DefinitionDescriptionUpdated EventType = "DefinitionDescriptionUpdated"
	DefinitionScheduleUpdated    EventType = "DefinitionScheduleUpdated"
	DefinitionDeleted            EventType = "DefinitionDeleted"
	DefinitionMemberAdded        EventType = "DefinitionMemberAdded"
	DefinitionMemberRemoved      EventType = "DefinitionMemberRemoved"
	DefinitionMemberReordered    EventType = "DefinitionMemberReordered"

	// action_set stream
	ActionSetCreated            EventType = "ActionSetCreated"
	ActionSetRenamed            EventType = "ActionSetRenamed"
	ActionSetDescriptionUpdated EventType = "ActionSetDescriptionUpdated"
	ActionSetScheduleUpdated    EventType = "ActionSetScheduleUpdated"
	ActionSetDeleted            EventType = "ActionSetDeleted"
	ActionSetMemberAdded        EventType = "ActionSetMemberAdded"
	ActionSetMemberRemoved      EventType = "ActionSetMemberRemoved"
	ActionSetMemberReordered    EventType = "ActionSetMemberReordered"

	// assignment stream
	AssignmentCreated          EventType = "AssignmentCreated"
	AssignmentDeleted          EventType = "AssignmentDeleted"
	AssignmentModeChanged      EventType = "AssignmentModeChanged"
	AssignmentSortOrderChanged EventType = "AssignmentSortOrderChanged"

	// compliance stream
	ComplianceResultUpdated EventType = "ComplianceResultUpdated"
	ComplianceResultRemoved EventType = "ComplianceResultRemoved"

	// compliance_policy stream
	CompliancePolicyCreated            EventType = "CompliancePolicyCreated"
	CompliancePolicyRenamed            EventType = "CompliancePolicyRenamed"
	CompliancePolicyDescriptionUpdated EventType = "CompliancePolicyDescriptionUpdated"
	CompliancePolicyDeleted            EventType = "CompliancePolicyDeleted"
	CompliancePolicyRuleAdded          EventType = "CompliancePolicyRuleAdded"
	CompliancePolicyRuleRemoved        EventType = "CompliancePolicyRuleRemoved"
	CompliancePolicyRuleUpdated        EventType = "CompliancePolicyRuleUpdated"

	// device stream
	DeviceRegistered      EventType = "DeviceRegistered"
	DeviceSeen            EventType = "DeviceSeen"
	DeviceHeartbeat       EventType = "DeviceHeartbeat"
	DeviceCertRenewed     EventType = "DeviceCertRenewed"
	DeviceLabelsUpdated   EventType = "DeviceLabelsUpdated"
	DeviceLabelSet        EventType = "DeviceLabelSet"
	DeviceLabelRemoved    EventType = "DeviceLabelRemoved"
	DeviceDeleted         EventType = "DeviceDeleted"
	DeviceAssigned        EventType = "DeviceAssigned"
	DeviceUnassigned      EventType = "DeviceUnassigned"
	DeviceGroupAssigned   EventType = "DeviceGroupAssigned"
	DeviceGroupUnassigned EventType = "DeviceGroupUnassigned"
	DeviceSyncIntervalSet EventType = "DeviceSyncIntervalSet"

	// device_group stream
	DeviceGroupCreated              EventType = "DeviceGroupCreated"
	DeviceGroupRenamed              EventType = "DeviceGroupRenamed"
	DeviceGroupDescriptionUpdated   EventType = "DeviceGroupDescriptionUpdated"
	DeviceGroupQueryUpdated         EventType = "DeviceGroupQueryUpdated"
	DeviceGroupSyncIntervalSet      EventType = "DeviceGroupSyncIntervalSet"
	DeviceGroupMaintenanceWindowSet EventType = "DeviceGroupMaintenanceWindowSet"
	DeviceGroupMemberAdded          EventType = "DeviceGroupMemberAdded"
	DeviceGroupMemberRemoved        EventType = "DeviceGroupMemberRemoved"
	// DeviceGroupMembersReevaluated records a DYNAMIC group's membership delta
	// produced by the in-process evaluator (#7 spec 14). The evaluator materializes
	// dynamic membership imperatively (and a rebuild re-evaluates), so this is not a
	// projected source — it exists for the audit trail and to drive the search
	// index reindex of the affected devices via api/SearchListener.
	DeviceGroupMembersReevaluated EventType = "DeviceGroupMembersReevaluated"
	DeviceGroupDeleted            EventType = "DeviceGroupDeleted"
	// Legacy device-group membership aliases — emitted by older versions
	// before the *MemberAdded / *MemberRemoved naming. The device_group
	// listener still recognises them so historical events replay
	// correctly during a rebuild.
	DeviceAddedToGroup     EventType = "DeviceAddedToGroup"
	DeviceRemovedFromGroup EventType = "DeviceRemovedFromGroup"

	// execution stream
	ExecutionCreated    EventType = "ExecutionCreated"
	ExecutionScheduled  EventType = "ExecutionScheduled"
	ExecutionDispatched EventType = "ExecutionDispatched"
	ExecutionStarted    EventType = "ExecutionStarted"
	ExecutionCompleted  EventType = "ExecutionCompleted"
	ExecutionFailed     EventType = "ExecutionFailed"
	ExecutionTimedOut   EventType = "ExecutionTimedOut"
	ExecutionSkipped    EventType = "ExecutionSkipped"
	ExecutionCancelled  EventType = "ExecutionCancelled"
	// OutputChunk is emitted on the execution stream for streaming
	// terminal/output payloads (LoadOutputChunks reads them back).
	OutputChunk EventType = "OutputChunk"

	// identity_provider stream
	IdentityProviderCreated          EventType = "IdentityProviderCreated"
	IdentityProviderUpdated          EventType = "IdentityProviderUpdated"
	IdentityProviderDeleted          EventType = "IdentityProviderDeleted"
	IdentityProviderSCIMEnabled      EventType = "IdentityProviderSCIMEnabled"
	IdentityProviderSCIMDisabled     EventType = "IdentityProviderSCIMDisabled"
	IdentityProviderSCIMTokenRotated EventType = "IdentityProviderSCIMTokenRotated"
	IdentityLinked                   EventType = "IdentityLinked"
	IdentityLinkLoginUpdated         EventType = "IdentityLinkLoginUpdated"
	IdentityUnlinked                 EventType = "IdentityUnlinked"

	// lps_password stream
	LpsPasswordRotated EventType = "LpsPasswordRotated"

	// luks_key stream
	LuksKeyRotated                    EventType = "LuksKeyRotated"
	LuksDeviceKeyRevocationRequested  EventType = "LuksDeviceKeyRevocationRequested"
	LuksDeviceKeyRevocationDispatched EventType = "LuksDeviceKeyRevocationDispatched"
	LuksDeviceKeyRevoked              EventType = "LuksDeviceKeyRevoked"
	LuksDeviceKeyRevocationFailed     EventType = "LuksDeviceKeyRevocationFailed"

	// role stream
	RoleCreated EventType = "RoleCreated"
	RoleUpdated EventType = "RoleUpdated"
	RoleDeleted EventType = "RoleDeleted"

	// scim_group_mapping stream
	SCIMGroupMapped         EventType = "SCIMGroupMapped"
	SCIMGroupUnmapped       EventType = "SCIMGroupUnmapped"
	SCIMGroupMappingUpdated EventType = "SCIMGroupMappingUpdated"

	// security_alert stream
	SecurityAlert             EventType = "SecurityAlert"
	SecurityAlertAcknowledged EventType = "SecurityAlertAcknowledged"

	// server_settings stream
	ServerSettingUpdated EventType = "ServerSettingUpdated"

	// terminal_session stream
	TerminalSessionStarted    EventType = "TerminalSessionStarted"
	TerminalSessionStopped    EventType = "TerminalSessionStopped"
	TerminalSessionTerminated EventType = "TerminalSessionTerminated"

	// terminal_admin stream — emitted by the global TerminalAdmin
	// reconciler when a pm-tty-* operator is removed from the LIMITED
	// or FULL action's users[] (server #70). Carries the human
	// user_id, the pm-tty-<username> string that was dropped, the
	// affected action_id, and the access_level so audit consumers can
	// distinguish Limited vs Full revocations without re-reading the
	// action's params.
	TerminalAdminMembershipRevoked EventType = "TerminalAdminMembershipRevoked"

	// token stream
	TokenCreated  EventType = "TokenCreated"
	TokenRenamed  EventType = "TokenRenamed"
	TokenUsed     EventType = "TokenUsed"
	TokenDisabled EventType = "TokenDisabled"
	TokenEnabled  EventType = "TokenEnabled"
	TokenDeleted  EventType = "TokenDeleted"

	// totp stream
	TOTPSetupInitiated         EventType = "TOTPSetupInitiated"
	TOTPVerified               EventType = "TOTPVerified"
	TOTPDisabled               EventType = "TOTPDisabled"
	TOTPBackupCodeUsed         EventType = "TOTPBackupCodeUsed"
	TOTPBackupCodesRegenerated EventType = "TOTPBackupCodesRegenerated"

	// user stream
	UserCreatedWithRoles            EventType = "UserCreatedWithRoles"
	UserProfileUpdated              EventType = "UserProfileUpdated"
	UserEmailChanged                EventType = "UserEmailChanged"
	UserPasswordChanged             EventType = "UserPasswordChanged"
	UserRoleChanged                 EventType = "UserRoleChanged"
	UserSessionInvalidated          EventType = "UserSessionInvalidated"
	UserDisabled                    EventType = "UserDisabled"
	UserEnabled                     EventType = "UserEnabled"
	UserLoggedIn                    EventType = "UserLoggedIn"
	UserDeleted                     EventType = "UserDeleted"
	UserSshKeyAdded                 EventType = "UserSshKeyAdded"
	UserSshKeyRemoved               EventType = "UserSshKeyRemoved"
	UserSshSettingsUpdated          EventType = "UserSshSettingsUpdated"
	UserLinuxUsernameChanged        EventType = "UserLinuxUsernameChanged"
	UserSystemActionLinked          EventType = "UserSystemActionLinked"
	UserProvisioningSettingsUpdated EventType = "UserProvisioningSettingsUpdated"

	// user_role stream
	UserRoleAssigned EventType = "UserRoleAssigned"
	UserRoleRevoked  EventType = "UserRoleRevoked"

	// user_group stream
	UserGroupCreated              EventType = "UserGroupCreated"
	UserGroupUpdated              EventType = "UserGroupUpdated"
	UserGroupQueryUpdated         EventType = "UserGroupQueryUpdated"
	UserGroupMaintenanceWindowSet EventType = "UserGroupMaintenanceWindowSet"
	UserGroupDeleted              EventType = "UserGroupDeleted"
	UserGroupMemberAdded          EventType = "UserGroupMemberAdded"
	UserGroupMemberRemoved        EventType = "UserGroupMemberRemoved"
	UserGroupRoleAssigned         EventType = "UserGroupRoleAssigned"
	UserGroupRoleRevoked          EventType = "UserGroupRoleRevoked"
	UserGroupMembersRebuilt       EventType = "UserGroupMembersRebuilt"
	// UserGroupMembersReevaluated is the user-group sibling of
	// DeviceGroupMembersReevaluated — a dynamic user-group membership delta from
	// the evaluator (#7 spec 14), audited + drives the search reindex of affected
	// users; not a projected source.
	UserGroupMembersReevaluated EventType = "UserGroupMembersReevaluated"

	// user_selection stream
	UserSelectionChanged EventType = "UserSelectionChanged"
)

// All returns every defined event type. Useful for tests that want to
// enumerate over the full set (e.g. uniqueness checks, future parity
// checks against listener switch coverage).
func All() []EventType {
	return []EventType{
		ActionCreated, ActionRenamed, ActionDescriptionUpdated, ActionParamsUpdated, ActionDeleted,
		DefinitionCreated, DefinitionRenamed, DefinitionDescriptionUpdated, DefinitionScheduleUpdated, DefinitionDeleted,
		DefinitionMemberAdded, DefinitionMemberRemoved, DefinitionMemberReordered,
		ActionSetCreated, ActionSetRenamed, ActionSetDescriptionUpdated, ActionSetScheduleUpdated,
		ActionSetDeleted, ActionSetMemberAdded, ActionSetMemberRemoved, ActionSetMemberReordered,
		AssignmentCreated, AssignmentDeleted, AssignmentModeChanged, AssignmentSortOrderChanged,
		ComplianceResultUpdated, ComplianceResultRemoved,
		CompliancePolicyCreated, CompliancePolicyRenamed, CompliancePolicyDescriptionUpdated, CompliancePolicyDeleted,
		CompliancePolicyRuleAdded, CompliancePolicyRuleRemoved, CompliancePolicyRuleUpdated,
		DeviceRegistered, DeviceSeen, DeviceHeartbeat, DeviceCertRenewed, DeviceLabelsUpdated,
		DeviceLabelSet, DeviceLabelRemoved, DeviceDeleted, DeviceAssigned, DeviceUnassigned,
		DeviceGroupAssigned, DeviceGroupUnassigned, DeviceSyncIntervalSet,
		DeviceGroupCreated, DeviceGroupRenamed, DeviceGroupDescriptionUpdated, DeviceGroupQueryUpdated,
		DeviceGroupSyncIntervalSet, DeviceGroupMaintenanceWindowSet, DeviceGroupMemberAdded,
		DeviceGroupMemberRemoved, DeviceGroupMembersReevaluated, DeviceGroupDeleted, DeviceAddedToGroup, DeviceRemovedFromGroup,
		ExecutionCreated, ExecutionScheduled, ExecutionDispatched, ExecutionStarted, ExecutionCompleted,
		ExecutionFailed, ExecutionTimedOut, ExecutionSkipped, ExecutionCancelled, OutputChunk,
		IdentityProviderCreated, IdentityProviderUpdated, IdentityProviderDeleted, IdentityProviderSCIMEnabled,
		IdentityProviderSCIMDisabled, IdentityProviderSCIMTokenRotated, IdentityLinked,
		IdentityLinkLoginUpdated, IdentityUnlinked,
		LpsPasswordRotated,
		LuksKeyRotated, LuksDeviceKeyRevocationRequested, LuksDeviceKeyRevocationDispatched,
		LuksDeviceKeyRevoked, LuksDeviceKeyRevocationFailed,
		RoleCreated, RoleUpdated, RoleDeleted,
		SCIMGroupMapped, SCIMGroupUnmapped, SCIMGroupMappingUpdated,
		SecurityAlert, SecurityAlertAcknowledged,
		ServerSettingUpdated,
		TerminalSessionStarted, TerminalSessionStopped, TerminalSessionTerminated,
		TerminalAdminMembershipRevoked,
		TokenCreated, TokenRenamed, TokenUsed, TokenDisabled, TokenEnabled, TokenDeleted,
		TOTPSetupInitiated, TOTPVerified, TOTPDisabled, TOTPBackupCodeUsed, TOTPBackupCodesRegenerated,
		UserCreatedWithRoles, UserProfileUpdated, UserEmailChanged, UserPasswordChanged, UserRoleChanged,
		UserSessionInvalidated, UserDisabled, UserEnabled, UserLoggedIn, UserDeleted,
		UserSshKeyAdded, UserSshKeyRemoved, UserSshSettingsUpdated, UserLinuxUsernameChanged,
		UserSystemActionLinked, UserProvisioningSettingsUpdated,
		UserRoleAssigned, UserRoleRevoked,
		UserGroupCreated, UserGroupUpdated, UserGroupQueryUpdated, UserGroupMaintenanceWindowSet,
		UserGroupDeleted, UserGroupMemberAdded, UserGroupMemberRemoved, UserGroupRoleAssigned,
		UserGroupRoleRevoked, UserGroupMembersRebuilt, UserGroupMembersReevaluated,
		UserSelectionChanged,
	}
}
