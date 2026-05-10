package projectors

import (
	"log/slog"

	"github.com/manchtools/power-manage/server/internal/store"
)

// WireAll registers every Go-side projector listener against the
// store's post-commit listener pipeline. Single source of truth for
// projector wiring so production boot (cmd/control/main.go) and
// tests (internal/testutil.SetupPostgres) get identical projector
// coverage. A new projector port adds itself here once and both
// sides pick it up.
//
// Listeners fire synchronously inside Store.AppendEvent — by the
// time AppendEvent returns to the handler, every listener's writes
// have landed. So read-your-writes works the same as the deleted
// PL/pgSQL triggers from the caller's perspective; the only
// behavioural delta is that the listener writes are not atomic with
// the event commit (separate autocommit per listener call). That
// matters only when multiple consecutive events would corrupt state
// on partial-failure mid-listener; the periodic indexer reconciler
// is the safety net for any drift.
//
// Refs tracker #107.
func WireAll(st *store.Store, logger *slog.Logger) {
	if st == nil {
		return
	}
	st.RegisterEventListener(SecurityAlertListener(
		st,
		loggerFor(logger, "security_alert_projector"),
	))
	st.RegisterEventListener(TotpListener(
		st,
		loggerFor(logger, "totp_projector"),
	))
	st.RegisterEventListener(LpsPasswordListener(
		st,
		loggerFor(logger, "lps_password_projector"),
	))
	st.RegisterEventListener(LuksKeyListener(
		st,
		loggerFor(logger, "luks_key_projector"),
	))
	st.RegisterEventListener(ServerSettingsListener(
		st,
		loggerFor(logger, "server_settings_projector"),
	))
	st.RegisterEventListener(RoleListener(
		st,
		loggerFor(logger, "role_projector"),
	))
	st.RegisterEventListener(UserRoleListener(
		st,
		loggerFor(logger, "user_role_projector"),
	))
	st.RegisterEventListener(TokenListener(
		st,
		loggerFor(logger, "token_projector"),
	))
	st.RegisterEventListener(IdentityProviderListener(
		st,
		loggerFor(logger, "identity_provider_projector"),
	))
	st.RegisterEventListener(SCIMGroupMappingListener(
		st,
		loggerFor(logger, "scim_group_mapping_projector"),
	))
	st.RegisterEventListener(UserSelectionListener(
		st,
		loggerFor(logger, "user_selection_projector"),
	))
	st.RegisterEventListener(ActionSetListener(
		st,
		loggerFor(logger, "action_set_projector"),
	))
	st.RegisterEventListener(AssignmentListener(
		st,
		loggerFor(logger, "assignment_projector"),
	))
	st.RegisterEventListener(UserGroupListener(
		st,
		loggerFor(logger, "user_group_projector"),
	))
	st.RegisterEventListener(DeviceGroupListener(
		st,
		loggerFor(logger, "device_group_projector"),
	))
	st.RegisterEventListener(CompliancePolicyListener(
		st,
		loggerFor(logger, "compliance_policy_projector"),
	))
	st.RegisterEventListener(ComplianceListener(
		st,
		loggerFor(logger, "compliance_projector"),
	))
	st.RegisterEventListener(ActionListener(
		st,
		loggerFor(logger, "action_projector"),
	))
	st.RegisterEventListener(ExecutionListener(
		st,
		loggerFor(logger, "execution_projector"),
	))
	st.RegisterEventListener(DeviceListener(
		st,
		loggerFor(logger, "device_projector"),
	))
	st.RegisterEventListener(UserListener(
		st,
		loggerFor(logger, "user_projector"),
	))
	// All 11 ports of tracker #107 are now wired here, plus every
	// Phase 2 port under tracker #136 (action_set, assignment,
	// user_group, device_group, compliance_policy, compliance,
	// action+definition, execution, device, user). With UserListener
	// landed, every domain projector lives in Go — the cleanup
	// migration can drop project_event() and the dispatcher trigger.
	// One ActionListener handles both the action and definition stream
	// types because DefinitionCreated dispatches across two
	// projections — synthesise an actions_projection row (when
	// payload carries `action_type`) OR insert a definitions_projection
	// row (otherwise) — and splitting would race the two branches.

	// Rebuild appliers (manchtools/power-manage-server#125). Only
	// the ported projectors that own a rebuildTarget in
	// store.AllRebuildTargets need this wiring — RebuildAll
	// dispatches everything else through the legacy PL/pgSQL
	// Function. Of the 11 #107 ports, three own rebuild targets:
	// roles, tokens, user_selections. The Phase 2 ports add four
	// more (action_sets, assignments, user_groups, device_groups).
	st.RegisterRebuildApply("roles", ApplyRole)
	st.RegisterRebuildApply("tokens", ApplyToken)
	st.RegisterRebuildApply("user_selections", ApplyUserSelection)
	st.RegisterRebuildApply("action_sets", ApplyActionSet)
	st.RegisterRebuildApply("assignments", ApplyAssignment)
	st.RegisterRebuildApply("user_groups", ApplyUserGroup)
	st.RegisterRebuildApply("device_groups", ApplyDeviceGroup)
	// scim_group_mappings rebuild — runs AFTER user_groups (target
	// order in AllRebuildTargets) so the FK reference to
	// user_groups_projection is restored before the upserts. Plugs
	// the gap where user_groups' TRUNCATE CASCADE wiped the SCIM
	// mappings but never replayed them. See manchtools/power-manage-
	// server#175.
	st.RegisterRebuildApply("scim_group_mappings", ApplySCIMGroupMapping)
	// One Apply body, two rebuild targets: the "actions" target
	// rebuilds actions_projection from BOTH action and definition
	// streams (the synthesised-action path). The "definitions"
	// target rebuilds definitions_projection from definition events
	// only. The per-event StreamType gate inside ApplyAction makes
	// the dual registration safe.
	st.RegisterRebuildApply("actions", ApplyAction)
	st.RegisterRebuildApply("definitions", ApplyDefinition)
	st.RegisterRebuildApply("executions", ApplyExecution)
	st.RegisterRebuildApply("devices", ApplyDevice)
	st.RegisterRebuildApply("users", ApplyUser)
}

// loggerFor returns a sub-logger tagged with the projector
// component name, or a discard logger when the parent is nil so
// tests that pass nil don't panic.
func loggerFor(parent *slog.Logger, component string) *slog.Logger {
	if parent == nil {
		return slog.Default()
	}
	return parent.With("component", component)
}
