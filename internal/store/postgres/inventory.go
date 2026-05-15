package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// Inventory implements store.InventoryRepo against device_inventory.
type Inventory struct {
	q *generated.Queries
}

// NewInventory returns an Inventory repo bound to the given sqlc handle.
func NewInventory(q *generated.Queries) *Inventory {
	return &Inventory{q: q}
}

func (i *Inventory) ListAllTables(ctx context.Context, deviceID string) ([]store.InventoryTable, error) {
	rows, err := i.q.GetDeviceInventory(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list all tables: %w", err)
	}
	out := make([]store.InventoryTable, len(rows))
	for j, r := range rows {
		out[j] = inventoryFromRow(r)
	}
	return out, nil
}

func (i *Inventory) ListTables(ctx context.Context, deviceID string, tableNames []string) ([]store.InventoryTable, error) {
	rows, err := i.q.GetDeviceInventoryByTables(ctx, generated.GetDeviceInventoryByTablesParams{
		DeviceID: deviceID,
		Column2:  tableNames,
	})
	if err != nil {
		return nil, fmt.Errorf("inventory: list tables: %w", err)
	}
	out := make([]store.InventoryTable, len(rows))
	for j, r := range rows {
		out[j] = inventoryFromRow(r)
	}
	return out, nil
}

func (i *Inventory) Upsert(ctx context.Context, p store.UpsertInventoryTable) error {
	if err := i.q.UpsertDeviceInventory(ctx, generated.UpsertDeviceInventoryParams{
		DeviceID:  p.DeviceID,
		TableName: p.TableName,
		Rows:      []byte(p.Rows),
	}); err != nil {
		return fmt.Errorf("inventory: upsert: %w", err)
	}
	return nil
}

func inventoryFromRow(r generated.DeviceInventory) store.InventoryTable {
	return store.InventoryTable{
		DeviceID:    r.DeviceID,
		TableName:   r.TableName,
		Rows:        json.RawMessage(r.Rows),
		CollectedAt: r.CollectedAt,
	}
}
