// Package devicegroup owns direct device-group state.
package devicegroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/dynamicquery"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const maxBatchDevices = 256

var (
	ErrInvalidInput   = errors.New("invalid device group input")
	ErrInvalidQuery   = errors.New("invalid device group query")
	ErrDynamicGroup   = errors.New("dynamic group membership is evaluator-owned")
	ErrMemberNotFound = errors.New("device group member not found")
	errNoChange       = errors.New("device group mutation made no change")
)

// Config supplies the direct store and clock.
type Config struct {
	Store *store.Store
	Now   func() time.Time
}

// State applies device-group mutations through audited transactions.
type State struct {
	store *store.Store
	now   func() time.Time
}

// NewState constructs direct device-group state.
func NewState(cfg Config) *State {
	if cfg.Store == nil {
		panic("device group: store is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &State{store: cfg.Store, now: cfg.Now}
}

// CreateParams is the complete authored shape of a new group.
type CreateParams struct {
	Name        string
	Description string
	CreatedBy   string
	Dynamic     bool
	Query       string
}

// Create inserts one empty group.
func (s *State) Create(ctx context.Context, op store.AuditOperation, p CreateParams) (store.DeviceGroupView, error) {
	if ctx == nil || !validID(p.CreatedBy) || (op.ActorID != "" && op.ActorID != p.CreatedBy) ||
		p.Name == "" || utf8.RuneCountInString(p.Name) > 255 || utf8.RuneCountInString(p.Description) > 1024 {
		return store.DeviceGroupView{}, ErrInvalidInput
	}
	query, err := validatedQuery(p.Dynamic, p.Query)
	if err != nil {
		return store.DeviceGroupView{}, err
	}
	id, now := ulid.Make().String(), s.now().UTC()
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.InsertDeviceGroup(ctx, db.InsertDeviceGroupParams{
			ID: id, Name: p.Name, Description: p.Description, CreatedAt: &now,
			CreatedBy: p.CreatedBy, IsDynamic: p.Dynamic, DynamicQuery: query,
		}); err != nil {
			return fmt.Errorf("device group: insert: %w", err)
		}
		rec.Effect(groupEffect(id, "CREATE", "name", "description", "is_dynamic", "dynamic_query"))
		return nil
	})
	if err != nil {
		return store.DeviceGroupView{}, err
	}
	return s.store.GetDeviceGroup(ctx, id)
}

// Rename replaces a group name.
func (s *State) Rename(ctx context.Context, op store.AuditOperation, id, name string) (store.DeviceGroupView, error) {
	if ctx == nil || !validID(id) || name == "" || utf8.RuneCountInString(name) > 255 {
		return store.DeviceGroupView{}, ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.RenameDeviceGroup(ctx, db.RenameDeviceGroupParams{ID: id, NewName: name}); err != nil {
			return err
		}
		rec.Effect(groupEffect(id, "UPDATE", "name"))
		return nil
	})
	return s.readAfter(ctx, id, err)
}

// UpdateDescription replaces a group description.
func (s *State) UpdateDescription(ctx context.Context, op store.AuditOperation, id, description string) (store.DeviceGroupView, error) {
	if ctx == nil || !validID(id) || utf8.RuneCountInString(description) > 1024 {
		return store.DeviceGroupView{}, ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.UpdateDeviceGroupDescription(ctx, db.UpdateDeviceGroupDescriptionParams{
			ID: id, Description: description,
		}); err != nil {
			return err
		}
		rec.Effect(groupEffect(id, "UPDATE", "description"))
		return nil
	})
	return s.readAfter(ctx, id, err)
}

// UpdateQuery replaces the membership mode and dynamic query. Membership
// reconciliation is a separate explicit evaluation operation.
func (s *State) UpdateQuery(ctx context.Context, op store.AuditOperation, id string, dynamic bool, raw string) (store.DeviceGroupView, error) {
	if ctx == nil || !validID(id) {
		return store.DeviceGroupView{}, ErrInvalidInput
	}
	query, err := validatedQuery(dynamic, raw)
	if err != nil {
		return store.DeviceGroupView{}, err
	}
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.UpdateDeviceGroupQuery(ctx, db.UpdateDeviceGroupQueryParams{
			ID: id, IsDynamic: dynamic, DynamicQuery: query,
		}); err != nil {
			return err
		}
		rec.Effect(groupEffect(id, "UPDATE", "is_dynamic", "dynamic_query"))
		return nil
	})
	return s.readAfter(ctx, id, err)
}

// AddDevices adds each live device once to a static group.
func (s *State) AddDevices(ctx context.Context, op store.AuditOperation, groupID string, deviceIDs []string) (int64, error) {
	if ctx == nil || !validID(groupID) || len(deviceIDs) == 0 || len(deviceIDs) > maxBatchDevices {
		return 0, ErrInvalidInput
	}
	group, err := s.store.GetDeviceGroup(ctx, groupID)
	if err != nil {
		return 0, translateNotFound(err)
	}
	if group.IsDynamic {
		return 0, ErrDynamicGroup
	}
	unique := make([]string, 0, len(deviceIDs))
	seen := make(map[string]struct{}, len(deviceIDs))
	for _, id := range deviceIDs {
		if !validID(id) {
			return 0, ErrInvalidInput
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if _, err := s.store.GetDevice(ctx, id); err != nil {
			return 0, translateNotFound(err)
		}
		unique = append(unique, id)
	}
	members, err := s.store.ListDeviceGroupMembers(ctx, groupID)
	if err != nil {
		return 0, err
	}
	for _, member := range members {
		delete(seen, member.DeviceID)
	}
	if len(seen) == 0 {
		return 0, nil
	}

	now := s.now().UTC()
	var added int64
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		current, err := tx.GetDeviceGroup(ctx, groupID)
		if err != nil {
			return err
		}
		if current.IsDynamic {
			return ErrDynamicGroup
		}
		for _, id := range unique {
			if _, wanted := seen[id]; !wanted {
				continue
			}
			rows, err := tx.AddDeviceGroupMember(ctx, db.AddDeviceGroupMemberParams{
				GroupID: groupID, DeviceID: id, AddedAt: &now,
			})
			if err != nil {
				return err
			}
			if rows == 0 {
				continue
			}
			added += rows
			after := id
			effect := groupEffect(groupID, "UPDATE", "members")
			effect.AfterRef = &after
			rec.Effect(effect)
		}
		if added == 0 {
			return errNoChange
		}
		return nil
	})
	if errors.Is(err, errNoChange) {
		return 0, nil
	}
	return added, translateNotFound(err)
}

// RemoveDevice removes one live device from a static group.
func (s *State) RemoveDevice(ctx context.Context, op store.AuditOperation, groupID, deviceID string) error {
	if ctx == nil || !validID(groupID) || !validID(deviceID) {
		return ErrInvalidInput
	}
	group, err := s.store.GetDeviceGroup(ctx, groupID)
	if err != nil {
		return translateNotFound(err)
	}
	if group.IsDynamic {
		return ErrDynamicGroup
	}
	_, err = s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		rows, err := tx.RemoveDeviceGroupMember(ctx, db.RemoveDeviceGroupMemberParams{
			GroupID: groupID, DeviceID: deviceID,
		})
		if err != nil {
			return err
		}
		if rows == 0 {
			return ErrMemberNotFound
		}
		before := deviceID
		effect := groupEffect(groupID, "UPDATE", "members")
		effect.BeforeRef = &before
		rec.Effect(effect)
		return nil
	})
	return translateNotFound(err)
}

// SetSyncInterval replaces the group's sync contribution.
func (s *State) SetSyncInterval(ctx context.Context, op store.AuditOperation, id string, minutes int32) (store.DeviceGroupView, error) {
	if ctx == nil || !validID(id) || minutes < 0 || minutes > 1440 {
		return store.DeviceGroupView{}, ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.SetDeviceGroupSyncInterval(ctx, db.SetDeviceGroupSyncIntervalParams{
			ID: id, SyncIntervalMinutes: minutes,
		}); err != nil {
			return err
		}
		rec.Effect(groupEffect(id, "UPDATE", "sync_interval_minutes"))
		return nil
	})
	return s.readAfter(ctx, id, err)
}

// SetInventoryInterval replaces the group's inventory contribution.
func (s *State) SetInventoryInterval(ctx context.Context, op store.AuditOperation, id string, minutes int32) (store.DeviceGroupView, error) {
	if ctx == nil || !validID(id) || (minutes != 0 && (minutes < 120 || minutes > 10080)) {
		return store.DeviceGroupView{}, ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.SetDeviceGroupInventoryInterval(ctx, db.SetDeviceGroupInventoryIntervalParams{
			ID: id, InventoryIntervalMinutes: minutes,
		}); err != nil {
			return err
		}
		rec.Effect(groupEffect(id, "UPDATE", "inventory_interval_minutes"))
		return nil
	})
	return s.readAfter(ctx, id, err)
}

// SetMaintenanceWindow stores one validated JSON object. The RPC handler owns
// semantic MaintenanceWindow validation; this layer rejects malformed storage
// shapes as a second boundary.
func (s *State) SetMaintenanceWindow(ctx context.Context, op store.AuditOperation, id string, raw []byte) (store.DeviceGroupView, error) {
	var object map[string]any
	if ctx == nil || !validID(id) || len(raw) == 0 || json.Unmarshal(raw, &object) != nil || object == nil {
		return store.DeviceGroupView{}, ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		if _, err := tx.SetDeviceGroupMaintenanceWindow(ctx, db.SetDeviceGroupMaintenanceWindowParams{
			ID: id, MaintenanceWindow: raw,
		}); err != nil {
			return err
		}
		rec.Effect(groupEffect(id, "UPDATE", "maintenance_window"))
		return nil
	})
	return s.readAfter(ctx, id, err)
}

// Delete soft-deletes a group and removes memberships, assignments and scoped
// authority in the same transaction.
func (s *State) Delete(ctx context.Context, op store.AuditOperation, id string) error {
	if ctx == nil || !validID(id) {
		return ErrInvalidInput
	}
	_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		members, err := tx.DeleteDeviceGroupMembers(ctx, id)
		if err != nil {
			return err
		}
		assignments, err := tx.DeleteDeviceGroupAssignments(ctx, id)
		if err != nil {
			return err
		}
		scopeID := id
		userGrants, err := tx.DeleteDeviceGroupUserRoleScopes(ctx, &scopeID)
		if err != nil {
			return err
		}
		groupGrants, err := tx.DeleteDeviceGroupUserGroupRoleScopes(ctx, &scopeID)
		if err != nil {
			return err
		}
		if _, err := tx.SoftDeleteDeviceGroup(ctx, id); err != nil {
			return err
		}
		count := members + assignments + userGrants + groupGrants
		effect := groupEffect(id, "DELETE", "is_deleted", "members", "assignments", "scoped_grants")
		effect.BeforeCount = &count
		rec.Effect(effect)
		return nil
	})
	return translateNotFound(err)
}

func (s *State) readAfter(ctx context.Context, id string, mutationErr error) (store.DeviceGroupView, error) {
	if mutationErr != nil {
		return store.DeviceGroupView{}, translateNotFound(mutationErr)
	}
	return s.store.GetDeviceGroup(ctx, id)
}

func validatedQuery(dynamic bool, raw string) (*string, error) {
	if !dynamic {
		if raw != "" {
			return nil, ErrInvalidQuery
		}
		return nil, nil
	}
	if raw == "" || utf8.RuneCountInString(raw) > 4096 || dynamicquery.ValidateDeviceQuery(raw) != nil {
		return nil, ErrInvalidQuery
	}
	return &raw, nil
}

func validID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}

func translateNotFound(err error) error {
	if store.IsNotFound(err) {
		return store.ErrNotFound
	}
	return err
}

func groupEffect(id, action string, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: "device_group", ResourceID: id, Action: action,
		Outcome: store.EffectApplied, ChangedFields: fields,
	}
}
