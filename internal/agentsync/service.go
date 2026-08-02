// Package agentsync builds a stream synchronization state from durable delivery
// rows.
package agentsync

import (
	"context"
	"errors"
	"fmt"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/maintenance"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/delivery"
	"github.com/manchtools/power-manage/server/internal/store"
)

const maxSyncDeliveries = int32(1024)

var (
	ErrInvalidInput = errors.New("invalid agent sync input")
	ErrNotConnected = errors.New("agent stream is not connected")
)

// Config supplies authoritative delivery state and the live epoch registry.
type Config struct {
	Store      *store.Store
	Manager    *connection.Manager
	Deliveries *delivery.Service
}

// Service implements durable stream synchronization.
type Service struct {
	store      *store.Store
	manager    *connection.Manager
	deliveries *delivery.Service
}

// New constructs the agent sync service.
func New(cfg Config) *Service {
	if cfg.Store == nil || cfg.Manager == nil || cfg.Deliveries == nil {
		panic("agentsync: store, manager, and delivery state are required")
	}
	return &Service{store: cfg.Store, manager: cfg.Manager, deliveries: cfg.Deliveries}
}

// Sync returns each still-sendable delivery and marks the response against the
// same live connection epoch used by unsolicited stream pushes.
func (s *Service) Sync(ctx context.Context, deviceID string) (*pmv1.SyncState, error) {
	if ctx == nil || !validID(deviceID) {
		return nil, ErrInvalidInput
	}
	device, err := s.store.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	agent, connected := s.manager.Get(deviceID)
	if !connected || agent == nil || agent.Epoch <= 0 || agent.Terminated() {
		return nil, ErrNotConnected
	}
	rows, err := s.store.ListDeviceDeliveries(ctx, deviceID, maxSyncDeliveries)
	if err != nil {
		return nil, err
	}
	deliveries := make([]*pmv1.ManifestDelivery, 0, len(rows))
	for _, row := range rows {
		manifest := &pmv1.Manifest{}
		if err := protojson.Unmarshal(row.Manifest, manifest); err != nil {
			return nil, fmt.Errorf("decode delivery %s manifest: %w", row.DeliveryID, err)
		}
		if manifest.ManifestId != row.ManifestID {
			return nil, delivery.ErrWrongManifest
		}
		changed, err := s.deliveries.MarkPushed(ctx, row.DeliveryID, deviceID, agent.Epoch)
		if err != nil {
			return nil, err
		}
		if !changed {
			continue
		}
		deliveries = append(deliveries, &pmv1.ManifestDelivery{
			DeliveryId: row.DeliveryID, Manifest: manifest,
		})
	}
	windows, err := s.store.ListDeviceMaintenanceWindows(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	window, err := unionMaintenanceWindows(windows)
	if err != nil {
		return nil, err
	}
	return &pmv1.SyncState{
		SyncIntervalMinutes: device.SyncIntervalMinutes,
		Deliveries:          deliveries,
		MaintenanceWindow:   window,
	}, nil
}

func unionMaintenanceWindows(rows [][]byte) (*pmv1.MaintenanceWindow, error) {
	windows := make([]*pmv1.MaintenanceWindow, 0, len(rows))
	for _, row := range rows {
		window := &pmv1.MaintenanceWindow{}
		if err := protojson.Unmarshal(row, window); err != nil {
			return nil, fmt.Errorf("decode maintenance window: %w", err)
		}
		if len(window.Schedule) != 0 {
			windows = append(windows, window)
		}
	}
	if len(windows) == 0 {
		return nil, nil
	}
	return maintenance.Union(windows...), nil
}

func validID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}
