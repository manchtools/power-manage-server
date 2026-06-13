package postgres

import (
	"context"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Device implements store.DeviceRepo against devices_projection +
// device_labels (Wave E.4 normalized labels into a child table).
type Device struct {
	q *generated.Queries
}

// NewDevice returns a Device repo bound to the given sqlc handle.
func NewDevice(q *generated.Queries) *Device {
	return &Device{q: q}
}

func (d *Device) Get(ctx context.Context, key store.GetDeviceKey) (store.Device, error) {
	row, err := d.q.GetDeviceByID(ctx, generated.GetDeviceByIDParams{
		ID:           key.ID,
		FilterUserID: key.OwnerScope,
	})
	if err != nil {
		return store.Device{}, fmt.Errorf("device: get: %w", translateNotFound(err))
	}
	dev := deviceFromRow(row)
	labels, err := d.q.ListDeviceLabels(ctx, key.ID)
	if err != nil {
		return store.Device{}, fmt.Errorf("device: load labels: %w", err)
	}
	dev.Labels = labelsFromRows(labels)
	return dev, nil
}

func (d *Device) IsDeleted(ctx context.Context, id string) (bool, error) {
	deleted, err := d.q.IsDeviceDeleted(ctx, id)
	if err != nil {
		return false, fmt.Errorf("device: is deleted: %w", translateNotFound(err))
	}
	return deleted, nil
}

func (d *Device) List(ctx context.Context, filter store.ListDevicesFilter) ([]store.Device, error) {
	rows, err := d.q.ListDevices(ctx, generated.ListDevicesParams{
		Limit:           filter.Limit,
		Offset:          filter.Offset,
		FilterUserID:    filter.OwnerScope,
		ScopeRestricted: filter.Scope.Restricted,
		ScopeGroupIds:   filter.Scope.GroupIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("device: list: %w", err)
	}
	return d.deviceRowsToSlice(ctx, rows)
}

func (d *Device) ListOnline(ctx context.Context, filter store.ListDevicesFilter) ([]store.Device, error) {
	rows, err := d.q.ListDevicesOnline(ctx, generated.ListDevicesOnlineParams{
		Limit:           filter.Limit,
		Offset:          filter.Offset,
		FilterUserID:    filter.OwnerScope,
		ScopeRestricted: filter.Scope.Restricted,
		ScopeGroupIds:   filter.Scope.GroupIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("device: list online: %w", err)
	}
	return d.deviceRowsToSlice(ctx, rows)
}

func (d *Device) ListOffline(ctx context.Context, filter store.ListDevicesFilter) ([]store.Device, error) {
	rows, err := d.q.ListDevicesOffline(ctx, generated.ListDevicesOfflineParams{
		Limit:           filter.Limit,
		Offset:          filter.Offset,
		FilterUserID:    filter.OwnerScope,
		ScopeRestricted: filter.Scope.Restricted,
		ScopeGroupIds:   filter.Scope.GroupIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("device: list offline: %w", err)
	}
	return d.deviceRowsToSlice(ctx, rows)
}

func (d *Device) Count(ctx context.Context, ownerScope *string, scope store.ScopeGroupFilter) (int64, error) {
	n, err := d.q.CountDevices(ctx, generated.CountDevicesParams{
		FilterUserID:    ownerScope,
		ScopeRestricted: scope.Restricted,
		ScopeGroupIds:   scope.GroupIDs,
	})
	if err != nil {
		return 0, fmt.Errorf("device: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (d *Device) CountOnline(ctx context.Context, ownerScope *string, scope store.ScopeGroupFilter) (int64, error) {
	n, err := d.q.CountDevicesOnline(ctx, generated.CountDevicesOnlineParams{
		FilterUserID:    ownerScope,
		ScopeRestricted: scope.Restricted,
		ScopeGroupIds:   scope.GroupIDs,
	})
	if err != nil {
		return 0, fmt.Errorf("device: count online: %w", translateNotFound(err))
	}
	return n, nil
}

func (d *Device) CountOffline(ctx context.Context, ownerScope *string, scope store.ScopeGroupFilter) (int64, error) {
	n, err := d.q.CountDevicesOffline(ctx, generated.CountDevicesOfflineParams{
		FilterUserID:    ownerScope,
		ScopeRestricted: scope.Restricted,
		ScopeGroupIds:   scope.GroupIDs,
	})
	if err != nil {
		return 0, fmt.Errorf("device: count offline: %w", translateNotFound(err))
	}
	return n, nil
}

// deviceRowsToSlice translates a slice of sqlc rows to domain devices
// and batch-loads labels for all of them in a single round-trip.
func (d *Device) deviceRowsToSlice(ctx context.Context, rows []generated.DevicesProjection) ([]store.Device, error) {
	out := make([]store.Device, len(rows))
	ids := make([]string, len(rows))
	for i, r := range rows {
		out[i] = deviceFromRow(r)
		ids[i] = r.ID
	}
	if err := d.attachLabels(ctx, out, ids); err != nil {
		return nil, err
	}
	return out, nil
}

// attachLabels populates Labels across a slice of devices via a single
// ListDeviceLabelsBatch query. Devices with no labels get a nil map.
func (d *Device) attachLabels(ctx context.Context, devices []store.Device, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := d.q.ListDeviceLabelsBatch(ctx, ids)
	if err != nil {
		return fmt.Errorf("device: list labels batch: %w", err)
	}
	byDevice := make(map[string]map[string]string, len(ids))
	for _, r := range rows {
		m, ok := byDevice[r.DeviceID]
		if !ok {
			m = map[string]string{}
			byDevice[r.DeviceID] = m
		}
		m[r.Key] = r.Value
	}
	for i := range devices {
		devices[i].Labels = byDevice[devices[i].ID]
	}
	return nil
}

func labelsFromRows(rows []generated.ListDeviceLabelsRow) map[string]string {
	if len(rows) == 0 {
		return nil
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Key] = r.Value
	}
	return out
}

func (d *Device) HostnamesByIDs(ctx context.Context, ids []string) ([]store.DeviceHostname, error) {
	rows, err := d.q.GetDeviceHostnamesByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("device: hostnames by ids: %w", err)
	}
	out := make([]store.DeviceHostname, len(rows))
	for i, r := range rows {
		out[i] = store.DeviceHostname{ID: r.ID, Hostname: r.Hostname}
	}
	return out, nil
}

func (d *Device) SyncInterval(ctx context.Context, deviceID string) (int32, error) {
	mins, err := d.q.GetDeviceSyncInterval(ctx, deviceID)
	if err != nil {
		return 0, fmt.Errorf("device: sync interval: %w", translateNotFound(err))
	}
	return mins, nil
}

// deviceFromRow translates a sqlc projection row to the domain shape.
// Labels are populated separately from the device_labels child table —
// callers should follow up with attachLabels / ListDeviceLabels.
func deviceFromRow(r generated.DevicesProjection) store.Device {
	return store.Device{
		ID:                  r.ID,
		Hostname:            r.Hostname,
		AgentVersion:        r.AgentVersion,
		CertFingerprint:     r.CertFingerprint,
		CertNotAfter:        r.CertNotAfter,
		RegisteredAt:        r.RegisteredAt,
		LastSeenAt:          r.LastSeenAt,
		RegistrationTokenID: r.RegistrationTokenID,
		IsDeleted:           r.IsDeleted,
		SyncIntervalMinutes: r.SyncIntervalMinutes,
		ComplianceStatus:    r.ComplianceStatus,
		ComplianceCheckedAt: r.ComplianceCheckedAt,
		ComplianceTotal:     r.ComplianceTotal,
		CompliancePassing:   r.CompliancePassing,
	}
}
