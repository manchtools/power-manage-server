package resolution

import (
	"context"
	"log/slog"

	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// Querier defines the queries needed for action resolution.
type Querier interface {
	ListResolvedActionsForDevice(ctx context.Context, targetID string) ([]db.ListResolvedActionsForDeviceRow, error)
	ListDeviceLayerExcludedActionIDs(ctx context.Context, targetID string) ([]string, error)
	ListUserLayerResolvedActionsForDevice(ctx context.Context, id string) ([]db.ListUserLayerResolvedActionsForDeviceRow, error)
	ListSystemTtyActionsForPermissionHolders(ctx context.Context) ([]db.ListSystemTtyActionsForPermissionHoldersRow, error)
}

// ResolveActionsForDevice queries device-layer assignments, user-layer
// assignments, and the permission-derived TTY action source, merges them
// with cross-layer exclusion rules, and returns the final action list.
//
// Cross-layer exclusion rules:
//   - Device EXCLUDED → blocks the action for assignment-derived layers
//   - User EXCLUDED → only removes from user layer, device layer unaffected
//   - Same action in both layers → device layer wins (no duplicates)
//
// The permission-derived TTY layer (every user with StartTerminal needs
// their pm-tty-<username> account on every device) deliberately bypasses
// device-layer EXCLUDED — terminal access is the system's escape hatch
// and must never be turned off by an operator-side exclusion. User
// deletion drives cleanup through a different path (the system action
// itself is removed, agents drop the account on the next sync).
func ResolveActionsForDevice(ctx context.Context, q Querier, deviceID string) ([]db.ListResolvedActionsForDeviceRow, error) {
	// 1. Get device-layer resolved actions (existing query, unchanged)
	deviceActions, err := q.ListResolvedActionsForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// 2. Get user-layer resolved actions (returns empty if device has no owner)
	userActions, err := q.ListUserLayerResolvedActionsForDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// 3. Permission-derived TTY actions — independent of device assignment.
	//
	// Scale note: this query returns one row per (user with
	// StartTerminal × linked TTY action), and every device receives
	// every row, so the per-device payload grows linearly with the
	// terminal-capable operator population. That's the documented
	// contract — every such user needs their pm-tty-<username>
	// account on every device — but worth keeping in mind once the
	// StartTerminal cohort gets large enough that ProxySyncActions
	// starts feeling the extra rows. Mitigation rides on the bulk
	// hoist below.
	//
	// TODO(bulk-resolve): the query takes no deviceID and returns the
	// same global set on every call, so a future bulk caller that
	// resolves many devices in one pass should hoist this fetch out
	// of the per-device loop and pass the slice down (e.g. add a
	// ResolveActionsForDevices helper used by ProxySyncActions). The
	// single live caller today is the per-agent ProxySyncActions
	// handler, where each call is already a one-off — no in-process
	// cache needed at current scale.
	//
	// Failure mode: this layer is purely additive — it only appends
	// rows, never removes them. A transient DB hiccup on this single
	// query path should not be allowed to abort the whole resolve and
	// break ProxySyncActions for every device, including devices with
	// no TTY-related state. Log and continue with an empty TTY slice;
	// the next agent sync after the DB recovers reconciles things,
	// and pm-tty accounts that already exist on devices stay put in
	// the meantime.
	ttyActions, err := q.ListSystemTtyActionsForPermissionHolders(ctx)
	if err != nil {
		slog.WarnContext(ctx, "permission-derived TTY action source failed; continuing without it",
			"device_id", deviceID, "error", err)
		ttyActions = nil
	}

	// 4. Device-layer excluded action IDs are needed only to filter the
	//    user-layer; the TTY layer is exclusion-exempt by design.
	var excludedSet map[string]bool
	if len(userActions) > 0 {
		excludedIDs, err := q.ListDeviceLayerExcludedActionIDs(ctx, deviceID)
		if err != nil {
			return nil, err
		}
		excludedSet = make(map[string]bool, len(excludedIDs))
		for _, id := range excludedIDs {
			excludedSet[id] = true
		}
	}

	deviceActionSet := make(map[string]bool, len(deviceActions))
	for _, a := range deviceActions {
		deviceActionSet[a.ID] = true
	}

	// 5. Merge user-layer actions: drop device-excluded and dedupe
	//    against the device layer.
	//
	// The direct struct conversion is sound because the sqlc-generated
	// row types share the same field layout (currently 14 fields). It
	// also makes the previous Schedule-drop bug structurally impossible
	// to repeat — if the layouts ever diverge, the conversion fails to
	// compile and forces the merge to be re-evaluated explicitly.
	for _, ua := range userActions {
		if excludedSet[ua.ID] || deviceActionSet[ua.ID] {
			continue
		}
		deviceActions = append(deviceActions, db.ListResolvedActionsForDeviceRow(ua))
		deviceActionSet[ua.ID] = true
	}

	// 6. Merge permission-derived TTY actions: dedupe against everything
	//    already in the result, but never honor device-layer exclusion.
	for _, ta := range ttyActions {
		if deviceActionSet[ta.ID] {
			continue
		}
		deviceActions = append(deviceActions, db.ListResolvedActionsForDeviceRow(ta))
		deviceActionSet[ta.ID] = true
	}

	return deviceActions, nil
}
