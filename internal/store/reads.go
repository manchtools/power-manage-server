package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Reads are exported one at a time rather than by handing out the
// generated query surface. A read method cannot become a write by
// accident, and the set of things a caller can do to the database
// stays enumerable: this file plus WithAudit.

// AuditOperationRow is one stored operation row.
type AuditOperationRow = generated.AuditOperation

// AuditEffectRow is one stored effect row.
type AuditEffectRow = generated.AuditEffect

// DeviceRow is one stored device.
type DeviceRow = generated.Device

// DeliveryRow is one durable manifest delivery.
type DeliveryRow = generated.Delivery

// JobRow is one durable scheduled job.
type JobRow = generated.Job

// DeviceStatusFilter selects the server-derived online state for a device
// listing. Zero keeps both states.
type DeviceStatusFilter int32

const (
	DeviceStatusAny     DeviceStatusFilter = 0
	DeviceStatusOnline  DeviceStatusFilter = 1
	DeviceStatusOffline DeviceStatusFilter = 2
)

// DeviceListFilter contains every narrowing rule shared by ListDeviceViews
// and CountDeviceViews. OnlineSince is normally now minus five minutes.
type DeviceListFilter struct {
	AfterID         string
	Limit           int32
	Status          DeviceStatusFilter
	OnlineSince     time.Time
	Labels          map[string]string
	AssignedUserID  *string
	ScopeRestricted bool
	ScopeGroupIDs   []string
}

// DeviceView is the complete device read model exposed to handlers.
type DeviceView struct {
	DeviceRow
	Labels                           map[string]string
	AssignedUserIDs                  []string
	AssignedGroupIDs                 []string
	LastInventoryAt                  *time.Time
	ResolvedInventoryIntervalMinutes int32
}

// DeviceAssigneeView is one live user or user group assigned to a device.
type DeviceAssigneeView struct {
	ID   string
	Kind string
	Name string
}

// DefaultInventoryIntervalMinutes is the server cadence used when neither a
// device nor any live device group supplies an inventory interval.
const DefaultInventoryIntervalMinutes int32 = 1440

// UserRow is one stored user.
type UserRow = generated.User

// AuditChainTip is a stream's current chain position.
type AuditChainTip struct {
	Stream   string
	HeadHash []byte
	Height   int64
}

// GetAuditOperation returns one operation row. ErrNotFound when the
// operation is unknown or has been archived away by retention.
func (s *Store) GetAuditOperation(ctx context.Context, operationID string) (AuditOperationRow, error) {
	row, err := s.queries.GetAuditOperation(ctx, operationID)
	if err != nil {
		return AuditOperationRow{}, fmt.Errorf("audit: get operation: %w", translateNotFound(err))
	}
	return row, nil
}

// ListAuditEffects returns an operation's effects in the order they
// were recorded, including any appended long after the operation
// itself.
func (s *Store) ListAuditEffects(ctx context.Context, operationID string) ([]AuditEffectRow, error) {
	rows, err := s.queries.ListAuditEffectsForOperation(ctx, operationID)
	if err != nil {
		return nil, fmt.Errorf("audit: list effects: %w", err)
	}
	return rows, nil
}

// AuditChainTipOf returns the stream's current head without locking it.
func (s *Store) AuditChainTipOf(ctx context.Context, stream string) (AuditChainTip, error) {
	if stream == "" {
		stream = DefaultAuditStream
	}
	row, err := s.queries.GetAuditChainHead(ctx, stream)
	if err != nil {
		return AuditChainTip{}, fmt.Errorf("audit: chain head: %w", translateNotFound(err))
	}
	return AuditChainTip{Stream: row.Stream, HeadHash: row.HeadHash, Height: row.Height}, nil
}

// CountAuditOperations returns how many operation rows a stream
// currently holds.
func (s *Store) CountAuditOperations(ctx context.Context, stream string) (int64, error) {
	if stream == "" {
		stream = DefaultAuditStream
	}
	n, err := s.queries.CountAuditOperations(ctx, stream)
	if err != nil {
		return 0, fmt.Errorf("audit: count operations: %w", err)
	}
	return n, nil
}

// GetDevice returns one live device. ErrNotFound when it is unknown or
// deleted.
func (s *Store) GetDevice(ctx context.Context, id string) (DeviceRow, error) {
	row, err := s.queries.GetDevice(ctx, id)
	if err != nil {
		return DeviceRow{}, fmt.Errorf("device: get: %w", translateNotFound(err))
	}
	return row, nil
}

// CountDevices returns the number of live devices.
func (s *Store) CountDevices(ctx context.Context) (int64, error) {
	n, err := s.queries.CountDevices(ctx)
	if err != nil {
		return 0, fmt.Errorf("device: count: %w", err)
	}
	return n, nil
}

// GetDelivery returns one durable manifest delivery. ErrNotFound when the
// delivery id is unknown.
func (s *Store) GetDelivery(ctx context.Context, id string) (DeliveryRow, error) {
	row, err := s.queries.GetDelivery(ctx, id)
	if err != nil {
		return DeliveryRow{}, fmt.Errorf("delivery: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListDueDeliveries returns due, non-terminal deliveries for the
// currently connected devices, oldest first.
func (s *Store) ListDueDeliveries(ctx context.Context, deviceIDs []string, at time.Time, limit int32) ([]DeliveryRow, error) {
	rows, err := s.queries.ListDueDeliveriesForDevices(ctx, generated.ListDueDeliveriesForDevicesParams{
		DeviceIds: deviceIDs, AvailableAt: at, PageSize: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("delivery: list due for connected devices: %w", err)
	}
	return rows, nil
}

// ListDeviceDeliveries returns manifest deliveries that have not
// reached durable agent receipt, oldest first.
func (s *Store) ListDeviceDeliveries(ctx context.Context, deviceID string, limit int32) ([]DeliveryRow, error) {
	rows, err := s.queries.ListSendableDeliveriesForDevice(ctx, generated.ListSendableDeliveriesForDeviceParams{
		DeviceID: deviceID, Limit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("delivery: list sendable for device: %w", err)
	}
	return rows, nil
}

// GetJob returns one durable scheduled job. ErrNotFound when it is unknown.
func (s *Store) GetJob(ctx context.Context, id string) (JobRow, error) {
	row, err := s.queries.GetJob(ctx, id)
	if err != nil {
		return JobRow{}, fmt.Errorf("job: get: %w", translateNotFound(err))
	}
	return row, nil
}

// ListClaimableJobs returns due pending jobs and expired leases, oldest first.
func (s *Store) ListClaimableJobs(ctx context.Context, at time.Time, limit int32) ([]JobRow, error) {
	rows, err := s.queries.ListClaimableJobs(ctx, generated.ListClaimableJobsParams{DueAt: at, Limit: limit})
	if err != nil {
		return nil, fmt.Errorf("job: list claimable: %w", err)
	}
	return rows, nil
}

// GetDeviceView returns one live device with its labels and assignees.
func (s *Store) GetDeviceView(ctx context.Context, id string) (DeviceView, error) {
	row, err := s.GetDevice(ctx, id)
	if err != nil {
		return DeviceView{}, err
	}
	labels, err := s.queries.ListDeviceLabels(ctx, id)
	if err != nil {
		return DeviceView{}, fmt.Errorf("device: list labels: %w", err)
	}
	users, err := s.queries.ListDeviceAssignedUserIDs(ctx, id)
	if err != nil {
		return DeviceView{}, fmt.Errorf("device: list assigned users: %w", err)
	}
	groups, err := s.queries.ListDeviceAssignedGroupIDs(ctx, id)
	if err != nil {
		return DeviceView{}, fmt.Errorf("device: list assigned groups: %w", err)
	}
	view := DeviceView{
		DeviceRow:        row,
		Labels:           make(map[string]string, len(labels)),
		AssignedUserIDs:  users,
		AssignedGroupIDs: groups,
	}
	for _, label := range labels {
		view.Labels[label.Key] = label.Value
	}
	views := []DeviceView{view}
	if err := s.addDeviceFreshness(ctx, []string{id}, views); err != nil {
		return DeviceView{}, err
	}
	view = views[0]
	return view, nil
}

type normalizedDeviceFilter struct {
	afterID         string
	limit           int32
	status          int32
	onlineSince     time.Time
	labels          []byte
	assignedUserID  *string
	scopeRestricted bool
	scopeGroupIDs   []string
}

func (s *Store) normalizeDeviceFilter(filter DeviceListFilter) (normalizedDeviceFilter, error) {
	// Handlers request one look-ahead row to produce an exact keyset next-page
	// token. The wire page remains capped at 100 rows.
	if filter.Limit < 0 || filter.Limit > 101 {
		return normalizedDeviceFilter{}, fmt.Errorf("device: list limit must be between 0 and 101")
	}
	if filter.Status < DeviceStatusAny || filter.Status > DeviceStatusOffline {
		return normalizedDeviceFilter{}, fmt.Errorf("device: invalid status filter %d", filter.Status)
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 50
	}
	onlineSince := filter.OnlineSince
	if onlineSince.IsZero() {
		onlineSince = s.clock().Add(-5 * time.Minute)
	}
	labels := filter.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	encodedLabels, err := json.Marshal(labels)
	if err != nil {
		return normalizedDeviceFilter{}, fmt.Errorf("device: encode label filter: %w", err)
	}
	return normalizedDeviceFilter{
		afterID: filter.AfterID, limit: limit, status: int32(filter.Status),
		onlineSince: onlineSince, labels: encodedLabels,
		assignedUserID:  filter.AssignedUserID,
		scopeRestricted: filter.ScopeRestricted, scopeGroupIDs: filter.ScopeGroupIDs,
	}, nil
}

// ListDeviceViews returns a stable keyset page with labels and assignees
// loaded in three bounded batch reads.
func (s *Store) ListDeviceViews(ctx context.Context, filter DeviceListFilter) ([]DeviceView, error) {
	f, err := s.normalizeDeviceFilter(filter)
	if err != nil {
		return nil, err
	}
	rows, err := s.queries.ListDevices(ctx, generated.ListDevicesParams{
		AfterID: f.afterID, AssignedUserID: f.assignedUserID,
		ScopeRestricted: f.scopeRestricted, ScopeGroupIds: f.scopeGroupIDs,
		LabelFilter: f.labels, StatusFilter: f.status,
		OnlineSince: &f.onlineSince, RowLimit: f.limit,
	})
	if err != nil {
		return nil, fmt.Errorf("device: list: %w", err)
	}
	if len(rows) == 0 {
		return []DeviceView{}, nil
	}

	ids := make([]string, len(rows))
	views := make([]DeviceView, len(rows))
	byID := make(map[string]int, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
		byID[row.ID] = i
		views[i] = DeviceView{DeviceRow: row, Labels: map[string]string{}}
	}
	labels, err := s.queries.ListDeviceLabelsBatch(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("device: list labels: %w", err)
	}
	for _, label := range labels {
		i := byID[label.DeviceID]
		views[i].Labels[label.Key] = label.Value
	}
	users, err := s.queries.ListDeviceAssignedUserIDsBatch(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("device: list assigned users: %w", err)
	}
	for _, assignment := range users {
		i := byID[assignment.DeviceID]
		views[i].AssignedUserIDs = append(views[i].AssignedUserIDs, assignment.UserID)
	}
	groups, err := s.queries.ListDeviceAssignedGroupIDsBatch(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("device: list assigned groups: %w", err)
	}
	for _, assignment := range groups {
		i := byID[assignment.DeviceID]
		views[i].AssignedGroupIDs = append(views[i].AssignedGroupIDs, assignment.GroupID)
	}
	if err := s.addDeviceFreshness(ctx, ids, views); err != nil {
		return nil, err
	}
	return views, nil
}

func (s *Store) addDeviceFreshness(ctx context.Context, ids []string, views []DeviceView) error {
	rows, err := s.queries.ListDeviceInventoryFreshness(ctx, generated.ListDeviceInventoryFreshnessParams{
		DefaultIntervalMinutes: DefaultInventoryIntervalMinutes,
		DeviceIds:              ids,
	})
	if err != nil {
		return fmt.Errorf("device: list inventory freshness: %w", err)
	}
	byID := make(map[string]int, len(views))
	for i := range views {
		byID[views[i].ID] = i
	}
	for _, row := range rows {
		i, ok := byID[row.DeviceID]
		if !ok {
			continue
		}
		if row.LastInventoryAt.Valid {
			collectedAt := row.LastInventoryAt.Time
			views[i].LastInventoryAt = &collectedAt
		}
		views[i].ResolvedInventoryIntervalMinutes = row.ResolvedIntervalMinutes
	}
	return nil
}

// CountDeviceViews counts the same filtered set as ListDeviceViews without a
// page cursor or limit.
func (s *Store) CountDeviceViews(ctx context.Context, filter DeviceListFilter) (int64, error) {
	f, err := s.normalizeDeviceFilter(filter)
	if err != nil {
		return 0, err
	}
	n, err := s.queries.CountDeviceViews(ctx, generated.CountDeviceViewsParams{
		AssignedUserID: f.assignedUserID, ScopeRestricted: f.scopeRestricted,
		ScopeGroupIds: f.scopeGroupIDs, LabelFilter: f.labels,
		StatusFilter: f.status, OnlineSince: &f.onlineSince,
	})
	if err != nil {
		return 0, fmt.Errorf("device: count filtered: %w", err)
	}
	return n, nil
}

// ListDeviceGroupIDs returns the device groups containing a live device.
func (s *Store) ListDeviceGroupIDs(ctx context.Context, deviceID string) ([]string, error) {
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, err
	}
	ids, err := s.queries.ListDeviceGroupIDs(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device: list group ids: %w", err)
	}
	return ids, nil
}

// IsDeviceAssignedToUser reports whether a live device is assigned directly
// to a user or through one of the user's live groups.
func (s *Store) IsDeviceAssignedToUser(ctx context.Context, deviceID, userID string) (bool, error) {
	assigned, err := s.queries.IsDeviceAssignedToUser(ctx, generated.IsDeviceAssignedToUserParams{
		DeviceID: deviceID,
		UserID:   userID,
	})
	if err != nil {
		return false, fmt.Errorf("device: check user assignment: %w", err)
	}
	return assigned, nil
}

// ListDeviceAssignees returns all live user and group assignees in one read.
func (s *Store) ListDeviceAssignees(ctx context.Context, deviceID string) ([]DeviceAssigneeView, error) {
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, err
	}
	rows, err := s.queries.ListDeviceAssignees(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device: list assignees: %w", err)
	}
	out := make([]DeviceAssigneeView, len(rows))
	for i, row := range rows {
		out[i] = DeviceAssigneeView{ID: row.AssigneeID, Kind: row.AssigneeKind, Name: row.AssigneeName}
	}
	return out, nil
}

// GetUser returns one live user. ErrNotFound when unknown or deleted.
func (s *Store) GetUser(ctx context.Context, id string) (UserRow, error) {
	row, err := s.queries.GetUser(ctx, id)
	if err != nil {
		return UserRow{}, fmt.Errorf("user: get: %w", translateNotFound(err))
	}
	return row, nil
}

// CountUsers returns the number of live users.
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	n, err := s.queries.CountUsers(ctx)
	if err != nil {
		return 0, fmt.Errorf("user: count: %w", err)
	}
	return n, nil
}

// GetUserEncryptionKey returns a subject's wrapped DEK. ErrNotFound
// when the subject has no key, which for an erased subject IS the
// expected state.
func (s *Store) GetUserEncryptionKey(ctx context.Context, userID string) (generated.UserEncryptionKey, error) {
	row, err := s.queries.GetUserEncryptionKey(ctx, userID)
	if err != nil {
		return generated.UserEncryptionKey{}, fmt.Errorf("user_encryption_key: get: %w", translateNotFound(err))
	}
	return row, nil
}
