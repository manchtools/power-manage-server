package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Device implements store.DeviceRepo against devices_projection.
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
	return deviceFromRow(row), nil
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
		Limit:        filter.Limit,
		Offset:       filter.Offset,
		FilterUserID: filter.OwnerScope,
	})
	if err != nil {
		return nil, fmt.Errorf("device: list: %w", err)
	}
	return deviceRowsToSlice(rows), nil
}

func (d *Device) ListOnline(ctx context.Context, filter store.ListDevicesFilter) ([]store.Device, error) {
	rows, err := d.q.ListDevicesOnline(ctx, generated.ListDevicesOnlineParams{
		Limit:        filter.Limit,
		Offset:       filter.Offset,
		FilterUserID: filter.OwnerScope,
	})
	if err != nil {
		return nil, fmt.Errorf("device: list online: %w", err)
	}
	return deviceRowsToSlice(rows), nil
}

func (d *Device) ListOffline(ctx context.Context, filter store.ListDevicesFilter) ([]store.Device, error) {
	rows, err := d.q.ListDevicesOffline(ctx, generated.ListDevicesOfflineParams{
		Limit:        filter.Limit,
		Offset:       filter.Offset,
		FilterUserID: filter.OwnerScope,
	})
	if err != nil {
		return nil, fmt.Errorf("device: list offline: %w", err)
	}
	return deviceRowsToSlice(rows), nil
}

func (d *Device) Count(ctx context.Context, ownerScope *string) (int64, error) {
	n, err := d.q.CountDevices(ctx, ownerScope)
	if err != nil {
		return 0, fmt.Errorf("device: count: %w", translateNotFound(err))
	}
	return n, nil
}

func (d *Device) CountOnline(ctx context.Context, ownerScope *string) (int64, error) {
	n, err := d.q.CountDevicesOnline(ctx, ownerScope)
	if err != nil {
		return 0, fmt.Errorf("device: count online: %w", translateNotFound(err))
	}
	return n, nil
}

func (d *Device) CountOffline(ctx context.Context, ownerScope *string) (int64, error) {
	n, err := d.q.CountDevicesOffline(ctx, ownerScope)
	if err != nil {
		return 0, fmt.Errorf("device: count offline: %w", translateNotFound(err))
	}
	return n, nil
}

// deviceRowsToSlice translates a slice of sqlc rows to domain
// devices. Shared by List / ListOnline / ListOffline.
func deviceRowsToSlice(rows []generated.DevicesProjection) []store.Device {
	out := make([]store.Device, len(rows))
	for i, r := range rows {
		out[i] = deviceFromRow(r)
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

// deviceFromRow translates a sqlc projection row to the domain
// shape. Shared so the field mapping lives in one place.
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
		Labels:              json.RawMessage(r.Labels),
		IsDeleted:           r.IsDeleted,
		SyncIntervalMinutes: r.SyncIntervalMinutes,
		ComplianceStatus:    r.ComplianceStatus,
		ComplianceCheckedAt: r.ComplianceCheckedAt,
		ComplianceTotal:     r.ComplianceTotal,
		CompliancePassing:   r.CompliancePassing,
	}
}
