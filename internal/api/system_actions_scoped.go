package api

import (
	"context"
	"fmt"
	"strings"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

// Per-scope TerminalAdmin actions (#7). The global reconciler in
// system_actions.go handles the two `:global` actions; this file adds the
// per-device-group actions `system:terminal-admin-{limited,full}:<dgID>`,
// sharing the same cohort computation and reconcile body.

// cohortKey identifies one (access level, scope) sudo cohort. Scope is
// "" for the global action, or a device_group id for a per-scope action.
type cohortKey struct {
	Level pm.AdminAccessLevel
	Scope string
}

// Per-scope action name prefixes. A per-scope name is the prefix + the
// device-group id (a ULID — colon-free, so the suffix is unambiguous).
const (
	scopedTerminalAdminPrefixLimited = "system:terminal-admin-limited:"
	scopedTerminalAdminPrefixFull    = "system:terminal-admin-full:"
)

// terminalAdminScopeKey reduces a scoped grant to its cohort scope:
//   - unscoped/global grant       → ("", true)   → the :global action
//   - device_group-scoped grant   → (groupID, true) → the per-scope action
//   - user_group-scoped / unknown → ("", false)  → ignored (TerminalAdmin
//     is a device-target permission; a user_group scope grants no device
//     reach).
func terminalAdminScopeKey(g store.ScopedGrant) (scope string, ok bool) {
	switch g.ScopeKind {
	case "":
		return "", true
	case auth.ScopeKindDeviceGroup:
		return g.ScopeID, true
	default:
		return "", false
	}
}

// scopedTerminalAdminActionName builds the per-scope action name for a
// (level, device-group) pair.
func scopedTerminalAdminActionName(level pm.AdminAccessLevel, deviceGroupID string) string {
	if level == pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL {
		return scopedTerminalAdminPrefixFull + deviceGroupID
	}
	return scopedTerminalAdminPrefixLimited + deviceGroupID
}

// levelFromScopedActionName parses the access level back out of a
// per-scope action name. ok=false for the :global actions or any name
// that isn't a per-scope terminal-admin action.
func levelFromScopedActionName(name string) (pm.AdminAccessLevel, bool) {
	switch {
	case name == GlobalTerminalAdminLimitedActionName || name == GlobalTerminalAdminFullActionName:
		return 0, false
	case strings.HasPrefix(name, scopedTerminalAdminPrefixFull):
		return pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL, true
	case strings.HasPrefix(name, scopedTerminalAdminPrefixLimited):
		return pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED, true
	default:
		return 0, false
	}
}

// ReconcileScopedTerminalAdminActions recomputes users[] for every
// per-device-group TerminalAdmin action. For each (level, device-group)
// cohort that has ≥1 holder it lazily creates the action (idempotent,
// signed once on create) and reconciles its membership; for any
// pre-existing per-scope action whose cohort is now empty it reconciles
// the membership to [] (the row is LEFT in place — an empty AdminPolicy
// is inert and the agent SKIPs it; deleting would churn the action id
// across grant flapping).
//
// GAP-A (over-revocation safety): each (level × scope) is exactly one
// action with its own users[] derived from exactly the grants of that
// level at that scope, so revoking Limited:dgX recomputes only
// system:terminal-admin-limited:<dgX> and cannot touch
// system:terminal-admin-full:<dgY>.
func (m *SystemActionManager) ReconcileScopedTerminalAdminActions(ctx context.Context) error {
	users, err := m.store.Repos().User.ListAllNonDeleted(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	cohorts := m.computeTerminalAdminCohorts(ctx, users)

	wanted := map[string]struct{}{}
	for k, cohort := range cohorts {
		if k.Scope == "" {
			continue // global actions are owned by the global reconciler
		}
		name := scopedTerminalAdminActionName(k.Level, k.Scope)
		wanted[name] = struct{}{}
		if err := m.bootstrapTerminalAdminAction(ctx, name, k.Level); err != nil {
			return fmt.Errorf("bootstrap %s: %w", name, err)
		}
		if err := m.reconcileOneTerminalAdmin(ctx, name, k.Level, cohort); err != nil {
			return fmt.Errorf("reconcile %s: %w", name, err)
		}
	}

	// Empty the cohort of any per-scope action that no longer has holders.
	existing, err := m.store.Queries().ListScopedTerminalAdminActionNames(ctx)
	if err != nil {
		return fmt.Errorf("list scoped terminal-admin action names: %w", err)
	}
	for _, name := range existing {
		if _, ok := wanted[name]; ok {
			continue
		}
		level, ok := levelFromScopedActionName(name)
		if !ok {
			continue // defensive — query already excludes non-per-scope names
		}
		if err := m.reconcileOneTerminalAdmin(ctx, name, level, nil); err != nil {
			return fmt.Errorf("clear empty scope %s: %w", name, err)
		}
	}
	return nil
}
