package store

import (
	"context"
	"encoding/json"
	"time"
)

// InventoryTable is one captured osquery-style table for a device.
// Rows is the raw JSON payload (osquery returns a JSON array of
// per-row objects); kept as json.RawMessage at the repo boundary so
// each backend chooses how to materialize the column without leaking
// that choice into handlers.
type InventoryTable struct {
	DeviceID    string
	TableName   string
	Rows        json.RawMessage
	CollectedAt time.Time
}

// UpsertInventoryTable carries the fields the inbox-worker writes
// when an agent uploads a fresh inventory snapshot.
type UpsertInventoryTable struct {
	DeviceID  string
	TableName string
	Rows      json.RawMessage
}

// InventoryRepo manages the per-device inventory snapshots
// (device_inventory). Reads serve the osquery-style UI exploration
// flows; the write side is driven by agent uploads landing in the
// gateway inbox worker.
type InventoryRepo interface {
	// ListAllTables returns every inventory row for the device,
	// ordered as the projection emits them. Empty slice when the
	// device has no inventory yet.
	ListAllTables(ctx context.Context, deviceID string) ([]InventoryTable, error)

	// ListTables returns only the named tables for the device.
	// Lets the UI fetch the few tables it needs without pulling the
	// full inventory snapshot.
	ListTables(ctx context.Context, deviceID string, tableNames []string) ([]InventoryTable, error)

	// Upsert overwrites the (device, table) row with fresh data
	// from an agent upload. CollectedAt is set server-side by the
	// underlying query (NOW()).
	Upsert(ctx context.Context, p UpsertInventoryTable) error
}
