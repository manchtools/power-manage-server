package devicegroup

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/manchtools/power-manage/server/internal/dynamicquery"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

// EvaluationResult is the committed membership delta and resulting group.
type EvaluationResult struct {
	Group   store.DeviceGroupView
	Added   int64
	Removed int64
}

// CountMatchingDevices validates a query and counts its current matches.
func (s *State) CountMatchingDevices(ctx context.Context, raw string) (int64, error) {
	expr, err := parseDeviceQuery(raw)
	if err != nil {
		return 0, err
	}
	rows, err := s.store.ListDevicesForDynamicEvaluation(ctx)
	if err != nil {
		return 0, err
	}
	matches, err := matchingDeviceIDs(expr, rows)
	return int64(len(matches)), err
}

// EvaluateDynamicGroup replaces one dynamic group's materialized membership in
// the same transaction as its audit record.
func (s *State) EvaluateDynamicGroup(ctx context.Context, op store.AuditOperation, id string) (EvaluationResult, error) {
	if ctx == nil || !validID(id) {
		return EvaluationResult{}, ErrInvalidInput
	}
	var added, removed []string
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		group, err := tx.GetDynamicDeviceGroupQueryForUpdate(ctx, id)
		if err != nil {
			return err
		}
		if !group.IsDynamic {
			return ErrStaticGroup
		}
		if group.DynamicQuery == nil {
			return ErrInvalidQuery
		}
		expr, err := parseDeviceQuery(*group.DynamicQuery)
		if err != nil {
			return err
		}
		devices, err := tx.ListDevicesForDynamicEvaluation(ctx)
		if err != nil {
			return fmt.Errorf("device group: list evaluation devices: %w", err)
		}
		wanted, err := matchingDeviceIDs(expr, devices)
		if err != nil {
			return err
		}
		current, err := tx.ListDeviceGroupMemberIDs(ctx, id)
		if err != nil {
			return fmt.Errorf("device group: list evaluation members: %w", err)
		}
		added, removed = membershipDelta(current, wanted)
		if len(removed) > 0 {
			removed, err = tx.RemoveDynamicDeviceGroupMembers(ctx, db.RemoveDynamicDeviceGroupMembersParams{
				GroupID: id, DeviceIds: removed,
			})
			if err != nil {
				return fmt.Errorf("device group: remove evaluated members: %w", err)
			}
			sort.Strings(removed)
		}
		if len(added) > 0 {
			now := s.now().UTC()
			added, err = tx.AddDynamicDeviceGroupMembers(ctx, db.AddDynamicDeviceGroupMembersParams{
				GroupID: id, DeviceIds: added, AddedAt: &now,
			})
			if err != nil {
				return fmt.Errorf("device group: add evaluated members: %w", err)
			}
			sort.Strings(added)
		}
		for _, deviceID := range removed {
			before := deviceID
			effect := groupEffect(id, "UPDATE", "members")
			effect.BeforeRef = &before
			rec.Effect(effect)
		}
		for _, deviceID := range added {
			after := deviceID
			effect := groupEffect(id, "UPDATE", "members")
			effect.AfterRef = &after
			rec.Effect(effect)
		}
		return nil
	})
	if err != nil {
		return EvaluationResult{}, translateNotFound(err)
	}
	group, err := s.store.GetDeviceGroup(ctx, id)
	if err != nil {
		return EvaluationResult{}, err
	}
	return EvaluationResult{Group: group, Added: int64(len(added)), Removed: int64(len(removed))}, nil
}

func parseDeviceQuery(raw string) (dynamicquery.Expr, error) {
	if dynamicquery.ValidateDeviceQuery(raw) != nil {
		return nil, ErrInvalidQuery
	}
	expr, err := dynamicquery.Parse(raw)
	if err != nil {
		return nil, ErrInvalidQuery
	}
	return expr, nil
}

func matchingDeviceIDs(expr dynamicquery.Expr, rows []db.ListDevicesForDynamicEvaluationRow) ([]string, error) {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ctx, err := evaluationContext(row)
		if err != nil {
			return nil, fmt.Errorf("device group: decode evaluation device %s: %w", row.ID, err)
		}
		if dynamicquery.EvaluateDevice(expr, ctx) {
			ids = append(ids, row.ID)
		}
	}
	return ids, nil
}

func evaluationContext(row db.ListDevicesForDynamicEvaluationRow) (dynamicquery.DeviceContext, error) {
	labels := map[string]string{}
	if err := json.Unmarshal(row.LabelsJson, &labels); err != nil {
		return dynamicquery.DeviceContext{}, err
	}
	values, err := inventoryValues(row.Hostname, row.InventoryJson)
	if err != nil {
		return dynamicquery.DeviceContext{}, err
	}
	return dynamicquery.DeviceContext{
		DeviceID: row.ID, Labels: labels, GroupNames: row.GroupNames,
		Inventory: func(field string) (string, bool) {
			value, ok := values[field]
			return value, ok
		},
	}, nil
}

var inventorySources = map[string][2]string{
	"os":                {"os_version", "name"},
	"os_version":        {"os_version", "version"},
	"os_major":          {"os_version", "major"},
	"os_minor":          {"os_version", "minor"},
	"os_arch":           {"os_version", "arch"},
	"os_platform":       {"os_version", "platform"},
	"os_platform_like":  {"os_version", "platform_like"},
	"cpu_type":          {"system_info", "cpu_type"},
	"cpu_brand":         {"system_info", "cpu_brand"},
	"cpu_cores":         {"system_info", "cpu_physical_cores"},
	"cpu_logical_cores": {"system_info", "cpu_logical_cores"},
	"memory_total":      {"system_info", "physical_memory"},
	"kernel":            {"kernel_info", "version"},
}

func inventoryValues(hostname string, raw []byte) (map[string]string, error) {
	encoded := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, err
	}
	tables := make(map[string]map[string]any, len(encoded))
	for name, value := range encoded {
		var rows []map[string]any
		if err := json.Unmarshal(value, &rows); err != nil {
			return nil, fmt.Errorf("inventory table %s: %w", name, err)
		}
		if len(rows) > 0 {
			tables[name] = rows[0]
		}
	}
	values := map[string]string{"hostname": hostname}
	for field, source := range inventorySources {
		if table := tables[source[0]]; table != nil {
			if value := scalarString(table[source[1]]); value != "" {
				values[field] = value
			}
		}
	}
	return values, nil
}

func scalarString(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case bool:
		return strconv.FormatBool(value)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	default:
		return ""
	}
}

func membershipDelta(current, wanted []string) (added, removed []string) {
	currentSet := make(map[string]struct{}, len(current))
	wantedSet := make(map[string]struct{}, len(wanted))
	for _, id := range current {
		currentSet[id] = struct{}{}
	}
	for _, id := range wanted {
		wantedSet[id] = struct{}{}
		if _, ok := currentSet[id]; !ok {
			added = append(added, id)
		}
	}
	for _, id := range current {
		if _, ok := wantedSet[id]; !ok {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
