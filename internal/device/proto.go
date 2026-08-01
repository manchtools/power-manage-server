package device

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

const onlineWindow = 5 * time.Minute

func (h *Handlers) toProto(view store.DeviceView) *pmv1.Device {
	device := &pmv1.Device{
		Id: view.ID, Hostname: view.Hostname, AgentVersion: view.AgentVersion,
		Status:                   pmv1.DeviceStatus_DEVICE_STATUS_OFFLINE,
		Labels:                   make(map[string]string, len(view.Labels)),
		AssignedUserIds:          append([]string(nil), view.AssignedUserIDs...),
		AssignedGroupIds:         append([]string(nil), view.AssignedGroupIDs...),
		SyncIntervalMinutes:      view.SyncIntervalMinutes,
		InventoryIntervalMinutes: view.InventoryIntervalMinutes,
		ComplianceStatus:         pmv1.ComplianceStatus(view.ComplianceStatus),
		ComplianceTotal:          view.ComplianceTotal, CompliancePassing: view.CompliancePassing,
	}
	for key, value := range view.Labels {
		device.Labels[key] = value
	}
	if view.RegisteredAt != nil {
		device.RegisteredAt = timestamppb.New(*view.RegisteredAt)
	}
	if view.LastSeenAt != nil {
		device.LastSeenAt = timestamppb.New(*view.LastSeenAt)
		if view.LastSeenAt.After(h.now().Add(-onlineWindow)) {
			device.Status = pmv1.DeviceStatus_DEVICE_STATUS_ONLINE
		}
	}
	if view.CertNotAfter != nil {
		device.CertExpiresAt = timestamppb.New(*view.CertNotAfter)
	}
	if view.ComplianceCheckedAt != nil {
		device.ComplianceCheckedAt = timestamppb.New(*view.ComplianceCheckedAt)
	}
	if view.LastInventoryAt != nil {
		device.LastInventoryAt = timestamppb.New(*view.LastInventoryAt)
	}
	device.InventoryOverdue = inventoryOverdue(
		view.LastInventoryAt, view.RegisteredAt, view.ResolvedInventoryIntervalMinutes, h.now(),
	)
	return device
}

func inventoryOverdue(lastInventoryAt, registeredAt *time.Time, intervalMinutes int32, now time.Time) bool {
	base := lastInventoryAt
	if base == nil {
		base = registeredAt
	}
	if base == nil {
		return true
	}
	if intervalMinutes <= 0 {
		intervalMinutes = store.DefaultInventoryIntervalMinutes
	}
	interval := time.Duration(intervalMinutes) * time.Minute
	grace := interval / 4
	if grace < time.Hour {
		grace = time.Hour
	}
	return now.Sub(*base) > interval+grace
}
