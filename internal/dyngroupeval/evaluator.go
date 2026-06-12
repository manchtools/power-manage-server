// Package dyngroupeval implements the in-process replacement for the
// PL/pgSQL functions evaluate_dynamic_group and evaluate_dynamic_user_group
// (migration 004). It walks every device or user, evaluates the group's
// dynamic_query against each using internal/dynamicquery, then reconciles
// device_group_members_projection / user_group_members_projection with
// the result.
//
// Shape vs. internal/compliance (audit N034). dyngroupeval is invoked
// as a top-level operation from API handlers and the control inbox
// worker, so its public API takes a *store.Store and opens its own
// transactions internally — there is no *InTx variant. compliance, by
// contrast, runs inside the projector listener WithTx blocks, so its
// public API takes a *store.Queries the caller already obtained. The
// difference is intentional, not naming drift: matching the API would
// force dyngroupeval callers to manage a tx they don't otherwise need.
//
// Part of Wave C of the storage-abstraction roadmap (tracker
// manchtools/power-manage-server#242).
package dyngroupeval

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/manchtools/power-manage/server/internal/dynamicquery"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// Evaluator is the in-process group-membership recalculator. Construct
// once per server boot (alongside the handlers / inbox worker) and call
// EvaluateDeviceGroup / EvaluateUserGroup per group.
type Evaluator struct {
	now    func() time.Time // clock seam; defaults to time.Now, overridden in tests
	store  *store.Store
	logger *slog.Logger
}

// New returns an Evaluator bound to the given Store. Logger is used for
// diagnostic output during eval — pass the same logger the surrounding
// handler / worker uses.
func New(s *store.Store, lg *slog.Logger) *Evaluator {
	return &Evaluator{store: s, logger: lg, now: time.Now}
}

// EvaluateDeviceGroup re-computes the membership of the dynamic device
// group identified by groupID. Mirrors the PL/pgSQL evaluate_dynamic_group:
// no-op for missing / soft-deleted / non-dynamic groups (and clears the
// stale queue entry in that case).
func (e *Evaluator) EvaluateDeviceGroup(ctx context.Context, groupID string) error {
	evalStart := e.now()
	q := e.store.Queries()

	group, err := e.store.Repos().DeviceGroup.Get(ctx, groupID)
	if err != nil {
		if store.IsNotFound(err) {
			return q.DeleteDynamicDeviceGroupEvaluationQueueRow(ctx, groupID)
		}
		return fmt.Errorf("dyngroupeval: load group %s: %w", groupID, err)
	}
	if !group.IsDynamic {
		return q.DeleteDynamicDeviceGroupEvaluationQueueRow(ctx, groupID)
	}

	expr, err := dynamicquery.Parse(derefString(group.DynamicQuery))
	if err != nil {
		// Don't drop the queue entry on parse error — a fix to the
		// query (UpdateDeviceGroupQuery event) will re-queue and the
		// next pass will succeed. Skip writes here.
		return fmt.Errorf("dyngroupeval: parse group %s query: %w", groupID, err)
	}

	currentMembers, err := q.ListDeviceGroupMemberIDs(ctx, groupID)
	if err != nil {
		return fmt.Errorf("dyngroupeval: list current members for %s: %w", groupID, err)
	}
	currentSet := toSet(currentMembers)

	deviceIDs, err := q.ListDevicesForDynamicEvaluation(ctx)
	if err != nil {
		return fmt.Errorf("dyngroupeval: list devices: %w", err)
	}
	labelsByDevice, err := e.loadAllDeviceLabels(ctx)
	if err != nil {
		return err
	}

	needsGroups := referencesGroupField(expr)
	newSet := make(map[string]bool, len(currentMembers))
	for _, id := range deviceIDs {
		dctx := e.attachGroupMembership(ctx, e.buildDeviceContext(ctx, id, labelsByDevice[id]), needsGroups)
		if dynamicquery.EvaluateDevice(expr, dctx) {
			newSet[id] = true
		}
	}

	for id := range newSet {
		if !currentSet[id] {
			added := evalStart
			if err := q.InsertDeviceGroupMember(ctx, db.InsertDeviceGroupMemberParams{
				GroupID:           groupID,
				DeviceID:          id,
				AddedAt:           &added,
				ProjectionVersion: 0,
			}); err != nil {
				return fmt.Errorf("dyngroupeval: add device %s to group %s: %w", id, groupID, err)
			}
		}
	}
	for id := range currentSet {
		if !newSet[id] {
			if err := q.DeleteDeviceGroupMember(ctx, db.DeleteDeviceGroupMemberParams{
				GroupID:  groupID,
				DeviceID: id,
			}); err != nil {
				return fmt.Errorf("dyngroupeval: remove device %s from group %s: %w", id, groupID, err)
			}
		}
	}

	if err := q.RecountDeviceGroupMembers(ctx, groupID); err != nil {
		return fmt.Errorf("dyngroupeval: recount %s: %w", groupID, err)
	}

	return q.DeleteDynamicDeviceGroupQueueBefore(ctx, db.DeleteDynamicDeviceGroupQueueBeforeParams{
		GroupID:  groupID,
		BeforeTs: evalStart,
	})
}

// EvaluateUserGroup re-computes the membership of the dynamic user
// group identified by groupID. Mirrors evaluate_dynamic_user_group.
func (e *Evaluator) EvaluateUserGroup(ctx context.Context, groupID string) error {
	evalStart := e.now()
	q := e.store.Queries()

	group, err := e.store.Repos().UserGroup.Get(ctx, groupID)
	if err != nil {
		if store.IsNotFound(err) {
			return q.DeleteDynamicUserGroupEvaluationQueueRow(ctx, groupID)
		}
		return fmt.Errorf("dyngroupeval: load user group %s: %w", groupID, err)
	}
	if !group.IsDynamic {
		return q.DeleteDynamicUserGroupEvaluationQueueRow(ctx, groupID)
	}

	expr, err := dynamicquery.Parse(derefString(group.DynamicQuery))
	if err != nil {
		return fmt.Errorf("dyngroupeval: parse user group %s query: %w", groupID, err)
	}

	currentMembers, err := q.ListUserGroupMemberIDs(ctx, groupID)
	if err != nil {
		return fmt.Errorf("dyngroupeval: list user-group current members for %s: %w", groupID, err)
	}
	currentSet := toSet(currentMembers)

	users, err := q.ListUsersForDynamicEvaluation(ctx)
	if err != nil {
		return fmt.Errorf("dyngroupeval: list users: %w", err)
	}

	newSet := make(map[string]bool, len(currentMembers))
	for _, u := range users {
		uctx := dynamicquery.UserContext{
			Email:             u.Email,
			Disabled:          u.Disabled,
			TotpEnabled:       u.TotpEnabled,
			HasPassword:       u.HasPassword,
			DisplayName:       u.DisplayName,
			PreferredUsername: u.PreferredUsername,
			Locale:            u.Locale,
		}
		if dynamicquery.EvaluateUser(expr, uctx) {
			newSet[u.ID] = true
		}
	}

	for id := range newSet {
		if !currentSet[id] {
			if err := q.InsertUserGroupMember(ctx, db.InsertUserGroupMemberParams{
				GroupID:           groupID,
				UserID:            id,
				AddedAt:           evalStart,
				AddedBy:           "system",
				ProjectionVersion: 0,
			}); err != nil {
				return fmt.Errorf("dyngroupeval: add user %s to group %s: %w", id, groupID, err)
			}
		}
	}
	for id := range currentSet {
		if !newSet[id] {
			if err := q.DeleteUserGroupMember(ctx, db.DeleteUserGroupMemberParams{
				GroupID: groupID,
				UserID:  id,
			}); err != nil {
				return fmt.Errorf("dyngroupeval: remove user %s from group %s: %w", id, groupID, err)
			}
		}
	}

	if err := q.RecountUserGroupMembers(ctx, groupID); err != nil {
		return fmt.Errorf("dyngroupeval: recount user group %s: %w", groupID, err)
	}

	return q.DeleteDynamicUserGroupQueueBefore(ctx, db.DeleteDynamicUserGroupQueueBeforeParams{
		GroupID:  groupID,
		BeforeTs: evalStart,
	})
}

// DrainResult is the per-batch summary the drain loop returns. Count
// is the number of groups evaluated; More is true when the queue still
// has rows after this batch (the caller should iterate again).
type DrainResult struct {
	Count int32
	More  bool
}

// device-group drain batch size matches the PL/pgSQL evaluate_queued_dynamic_groups
// constant (audit F035 / #168 wave). User-group drain uses 100 — historical
// asymmetry the PL/pgSQL function had; keep the parity until tuning data
// suggests otherwise.
const (
	deviceQueueBatchLimit = 1000
	userQueueBatchLimit   = 100
)

// DrainDeviceGroupQueue evaluates the next batch of device-group queue
// entries and returns (count, more). Per-group failures are logged and
// skipped — one bad group should not block evaluation of the rest of
// the batch.
//
// Replaces the PL/pgSQL evaluate_queued_dynamic_groups call. Callers
// loop until More is false (see cmd/control/drainDynamicQueue).
func (e *Evaluator) DrainDeviceGroupQueue(ctx context.Context) (DrainResult, error) {
	q := e.store.Queries()
	ids, err := q.ListDynamicDeviceGroupQueueBatch(ctx, deviceQueueBatchLimit)
	if err != nil {
		return DrainResult{}, fmt.Errorf("dyngroupeval: list device-group queue batch: %w", err)
	}
	var count int32
	for _, id := range ids {
		if err := e.EvaluateDeviceGroup(ctx, id); err != nil {
			e.logger.Warn("dyngroupeval: failed to evaluate queued device group; skipping",
				"group_id", id, "error", err)
			continue
		}
		count++
	}
	more, err := q.HasDynamicDeviceGroupQueueEntries(ctx)
	if err != nil {
		return DrainResult{}, fmt.Errorf("dyngroupeval: probe device-group queue: %w", err)
	}
	return DrainResult{Count: count, More: more}, nil
}

// DrainUserGroupQueue is the user-group sibling of DrainDeviceGroupQueue.
func (e *Evaluator) DrainUserGroupQueue(ctx context.Context) (DrainResult, error) {
	q := e.store.Queries()
	ids, err := q.ListDynamicUserGroupQueueBatch(ctx, userQueueBatchLimit)
	if err != nil {
		return DrainResult{}, fmt.Errorf("dyngroupeval: list user-group queue batch: %w", err)
	}
	var count int32
	for _, id := range ids {
		if err := e.EvaluateUserGroup(ctx, id); err != nil {
			e.logger.Warn("dyngroupeval: failed to evaluate queued user group; skipping",
				"group_id", id, "error", err)
			continue
		}
		count++
	}
	more, err := q.HasDynamicUserGroupQueueEntries(ctx)
	if err != nil {
		return DrainResult{}, fmt.Errorf("dyngroupeval: probe user-group queue: %w", err)
	}
	return DrainResult{Count: count, More: more}, nil
}

// CountMatchingDevices returns the number of non-deleted devices that
// match the given query. Used by the ValidateDynamicQuery RPC's preview
// count. Parse failure is surfaced as an error so the caller can
// report it; PL/pgSQL CountMatchingDevicesForQuery used to count only
// the matching subset and silently ignore unparseable atoms.
func (e *Evaluator) CountMatchingDevices(ctx context.Context, query string) (int64, error) {
	expr, err := dynamicquery.Parse(query)
	if err != nil {
		return 0, fmt.Errorf("dyngroupeval: parse: %w", err)
	}
	deviceIDs, err := e.store.Queries().ListDevicesForDynamicEvaluation(ctx)
	if err != nil {
		return 0, fmt.Errorf("dyngroupeval: list devices: %w", err)
	}
	labelsByDevice, err := e.loadAllDeviceLabels(ctx)
	if err != nil {
		return 0, err
	}
	needsGroups := referencesGroupField(expr)
	var count int64
	for _, id := range deviceIDs {
		dctx := e.attachGroupMembership(ctx, e.buildDeviceContext(ctx, id, labelsByDevice[id]), needsGroups)
		if dynamicquery.EvaluateDevice(expr, dctx) {
			count++
		}
	}
	return count, nil
}

// loadAllDeviceLabels pulls every (device_id, key, value) row in one
// query and groups by device_id. The map's nil-entry semantics let
// the callers index by device_id without needing a presence check;
// missing entries simply yield nil maps which the evaluator treats as
// "no labels."
func (e *Evaluator) loadAllDeviceLabels(ctx context.Context) (map[string]map[string]string, error) {
	rows, err := e.store.Queries().ListAllDeviceLabels(ctx)
	if err != nil {
		return nil, fmt.Errorf("dyngroupeval: list all device labels: %w", err)
	}
	out := make(map[string]map[string]string)
	for _, r := range rows {
		m, ok := out[r.DeviceID]
		if !ok {
			m = map[string]string{}
			out[r.DeviceID] = m
		}
		m[r.Key] = r.Value
	}
	return out, nil
}

// CountMatchingUsers returns the number of non-deleted users that
// match the given query.
func (e *Evaluator) CountMatchingUsers(ctx context.Context, query string) (int64, error) {
	expr, err := dynamicquery.Parse(query)
	if err != nil {
		return 0, fmt.Errorf("dyngroupeval: parse: %w", err)
	}
	users, err := e.store.Queries().ListUsersForDynamicEvaluation(ctx)
	if err != nil {
		return 0, fmt.Errorf("dyngroupeval: list users: %w", err)
	}
	var count int64
	for _, u := range users {
		uctx := dynamicquery.UserContext{
			Email:             u.Email,
			Disabled:          u.Disabled,
			TotpEnabled:       u.TotpEnabled,
			HasPassword:       u.HasPassword,
			DisplayName:       u.DisplayName,
			PreferredUsername: u.PreferredUsername,
			Locale:            u.Locale,
		}
		if dynamicquery.EvaluateUser(expr, uctx) {
			count++
		}
	}
	return count, nil
}

// buildDeviceContext returns a DeviceContext with pre-loaded labels
// and a lazy-loading Inventory closure. Wave E.4 dropped the labels
// JSONB column — callers now pass the already-grouped map[string]string
// from a single ListAllDeviceLabels round-trip.
func (e *Evaluator) buildDeviceContext(ctx context.Context, deviceID string, labels map[string]string) dynamicquery.DeviceContext {
	var (
		inventoryLoaded bool
		inventoryByCol  map[string]string
	)

	return dynamicquery.DeviceContext{
		DeviceID: deviceID,
		Labels:   labels,
		Inventory: func(field string) (string, bool) {
			if !inventoryLoaded {
				inventoryByCol = e.loadInventoryFields(ctx, deviceID)
				inventoryLoaded = true
			}
			v, ok := inventoryByCol[strings.ToLower(field)]
			return v, ok
		},
		// GroupNames is populated by attachGroupMembership only when
		// the query AST actually references device.group. The
		// closure-style lookup isn't reachable through DeviceContext
		// (it's a plain slice), so eager pre-load is the cheapest
		// option that keeps the public interface flat.
	}
}

// derefString safely dereferences a *string, returning "" when nil.
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// attachGroupMembership eagerly loads group memberships if the AST
// references the device.group field. Avoids the round-trip when the
// query only touches labels / inventory.
//
// Returns the DeviceContext with GroupNames populated (or nil if not
// needed).
func (e *Evaluator) attachGroupMembership(ctx context.Context, dctx dynamicquery.DeviceContext, needsGroups bool) dynamicquery.DeviceContext {
	if !needsGroups {
		return dctx
	}
	names, err := e.store.Queries().ListGroupNamesForDevice(ctx, dctx.DeviceID)
	if err != nil {
		e.logger.Warn("dyngroupeval: failed to load device group names; predicate will evaluate as empty membership",
			"device_id", dctx.DeviceID, "error", err)
		return dctx
	}
	dctx.GroupNames = names
	return dctx
}

// referencesGroupField walks the AST and reports whether any atom uses
// device.group. The helper lets the per-device loop skip the
// ListGroupNamesForDevice round-trip when the query doesn't need it.
func referencesGroupField(expr dynamicquery.Expr) bool {
	switch n := expr.(type) {
	case *dynamicquery.And:
		return referencesGroupField(n.L) || referencesGroupField(n.R)
	case *dynamicquery.Or:
		return referencesGroupField(n.L) || referencesGroupField(n.R)
	case *dynamicquery.Not:
		return referencesGroupField(n.X)
	case *dynamicquery.Atom:
		return strings.EqualFold(n.Field, "device.group")
	}
	return false
}

// loadInventoryFields fetches the per-device inventory rows and flattens
// them into a {field_name: value} map keyed by the same field names the
// PL/pgSQL resolve_inventory_field exposed. Built once per device on
// first inventory reference.
func (e *Evaluator) loadInventoryFields(ctx context.Context, deviceID string) map[string]string {
	rows, err := e.store.Queries().GetDeviceInventory(ctx, deviceID)
	if err != nil {
		e.logger.Warn("dyngroupeval: failed to load inventory; device.* fields will evaluate as absent",
			"device_id", deviceID, "error", err)
		return map[string]string{}
	}
	byTable := make(map[string]map[string]string, len(rows))
	for _, r := range rows {
		var arr []map[string]any
		if err := json.Unmarshal(r.Rows, &arr); err != nil {
			// Corrupt inventory blob — surface it instead of silently
			// dropping the row. The device.* predicate that referenced
			// this table will evaluate as absent.
			e.logger.Warn("dyngroupeval: skipping corrupt inventory row",
				"device_id", deviceID, "table", r.TableName, "error", err)
			continue
		}
		if len(arr) == 0 {
			continue
		}
		colVals := make(map[string]string)
		for k, v := range arr[0] {
			colVals[strings.ToLower(k)] = anyToString(v)
		}
		byTable[r.TableName] = colVals
	}
	// Hostname lookup: PL/pgSQL preferred devices_projection.hostname
	// over inventory. Pre-load it so the inventory map carries the
	// authoritative value.
	host, err := e.deviceHostname(ctx, deviceID)
	if err == nil && host != "" {
		ensureTable(byTable, "system_info")["hostname"] = host
	}

	return flattenInventory(byTable)
}

// deviceHostname returns devices_projection.hostname for a given device,
// or "" + error when not found.
func (e *Evaluator) deviceHostname(ctx context.Context, deviceID string) (string, error) {
	d, err := e.store.Queries().GetDeviceByID(ctx, db.GetDeviceByIDParams{ID: deviceID})
	if err != nil {
		return "", err
	}
	return d.Hostname, nil
}

func ensureTable(m map[string]map[string]string, table string) map[string]string {
	if _, ok := m[table]; !ok {
		m[table] = map[string]string{}
	}
	return m[table]
}

// flattenInventory maps the PL/pgSQL `device.<field>` names to their
// (table, column) — mirrors resolve_inventory_field's CASE arms.
func flattenInventory(byTable map[string]map[string]string) map[string]string {
	out := make(map[string]string, 16)
	osv := byTable["os_version"]
	if osv != nil {
		set(out, "os", osv["name"])
		set(out, "os_version", osv["version"])
		set(out, "os_major", osv["major"])
		set(out, "os_minor", osv["minor"])
		set(out, "os_arch", osv["arch"])
		set(out, "os_platform", osv["platform"])
		set(out, "os_platform_like", osv["platform_like"])
	}
	sysi := byTable["system_info"]
	if sysi != nil {
		set(out, "hostname", sysi["hostname"])
		set(out, "cpu_type", sysi["cpu_type"])
		set(out, "cpu_brand", sysi["cpu_brand"])
		set(out, "cpu_cores", sysi["cpu_physical_cores"])
		set(out, "cpu_logical_cores", sysi["cpu_logical_cores"])
		set(out, "memory_total", sysi["physical_memory"])
	}
	if kern := byTable["kernel_info"]; kern != nil {
		set(out, "kernel", kern["version"])
	}
	return out
}

func set(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func anyToString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers come through as float64; trim trailing zeros
		// for integer-valued numbers so equals "32" matches a
		// memory_total of 32 (which deserialized as 32.0).
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	}
	return fmt.Sprint(v)
}

func toSet(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}
