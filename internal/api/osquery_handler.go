package api

import (
	"context"
	"encoding/json"
	"fmt"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// OSQueryHandler handles OSQuery dispatch, result polling, and device inventory RPCs.
type OSQueryHandler struct {
	store *store.Store
}

// NewOSQueryHandler creates a new OSQuery handler.
func NewOSQueryHandler(st *store.Store) *OSQueryHandler {
	return &OSQueryHandler{store: st}
}

// DispatchOSQuery dispatches an on-demand osquery to a connected device.
func (h *OSQueryHandler) DispatchOSQuery(ctx context.Context, req *connect.Request[pm.DispatchOSQueryRequest]) (*connect.Response[pm.DispatchOSQueryResponse], error) {
	msg := req.Msg

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, generated.GetDeviceByIDParams{
		ID: msg.DeviceId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("device not found"))
	}

	// Generate query ID
	queryID := ulid.Make().String()

	// Create pending result row
	if err := h.store.Queries().CreateOSQueryResult(ctx, generated.CreateOSQueryResultParams{
		QueryID:   queryID,
		DeviceID:  msg.DeviceId,
		TableName: msg.Table,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create query result: %w", err))
	}

	// Build notification payload
	payload := map[string]interface{}{
		"type":     "osquery_dispatch",
		"query_id": queryID,
		"table":    msg.Table,
	}
	if len(msg.Columns) > 0 {
		payload["columns"] = msg.Columns
	}
	if msg.Limit > 0 {
		payload["limit"] = msg.Limit
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to marshal notification: %w", err))
	}

	// Notify agent via pg_notify
	if err := h.store.Notify(ctx, "agent_"+msg.DeviceId, string(payloadJSON)); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to notify agent: %w", err))
	}

	return connect.NewResponse(&pm.DispatchOSQueryResponse{
		QueryId: queryID,
	}), nil
}

// GetOSQueryResult polls for the result of a dispatched osquery.
func (h *OSQueryHandler) GetOSQueryResult(ctx context.Context, req *connect.Request[pm.GetOSQueryResultRequest]) (*connect.Response[pm.GetOSQueryResultResponse], error) {
	result, err := h.store.Queries().GetOSQueryResult(ctx, req.Msg.QueryId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("query result not found"))
	}

	resp := &pm.GetOSQueryResultResponse{
		QueryId:   result.QueryID,
		Completed: result.Completed,
		Success:   result.Success,
		Error:     result.Error,
	}

	// Parse JSONB rows back to proto
	if result.Completed && result.Success {
		var rawRows []map[string]string
		if err := json.Unmarshal(result.Rows, &rawRows); err == nil {
			for _, row := range rawRows {
				resp.Rows = append(resp.Rows, &pm.OSQueryRow{Data: row})
			}
		}
	}

	return connect.NewResponse(resp), nil
}

// GetDeviceInventory returns cached inventory data for a device.
func (h *OSQueryHandler) GetDeviceInventory(ctx context.Context, req *connect.Request[pm.GetDeviceInventoryRequest]) (*connect.Response[pm.GetDeviceInventoryResponse], error) {
	msg := req.Msg

	var rows []generated.DeviceInventory
	var err error

	if len(msg.TableNames) > 0 {
		rows, err = h.store.Queries().GetDeviceInventoryByTables(ctx, generated.GetDeviceInventoryByTablesParams{
			DeviceID: msg.DeviceId,
			Column2:  msg.TableNames,
		})
	} else {
		rows, err = h.store.Queries().GetDeviceInventory(ctx, msg.DeviceId)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get inventory: %w", err))
	}

	resp := &pm.GetDeviceInventoryResponse{}
	for _, row := range rows {
		table := &pm.InventoryTableResult{
			TableName:   row.TableName,
			CollectedAt: timestamppb.New(row.CollectedAt.Time),
		}

		// Parse JSONB rows
		var rawRows []map[string]string
		if err := json.Unmarshal(row.Rows, &rawRows); err == nil {
			for _, r := range rawRows {
				table.Rows = append(table.Rows, &pm.OSQueryRow{Data: r})
			}
		}

		resp.Tables = append(resp.Tables, table)
	}

	return connect.NewResponse(resp), nil
}

// RefreshDeviceInventory requests the agent to re-collect and send inventory.
func (h *OSQueryHandler) RefreshDeviceInventory(ctx context.Context, req *connect.Request[pm.RefreshDeviceInventoryRequest]) (*connect.Response[pm.RefreshDeviceInventoryResponse], error) {
	msg := req.Msg

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, generated.GetDeviceByIDParams{
		ID: msg.DeviceId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("device not found"))
	}

	payload, _ := json.Marshal(map[string]string{
		"type": "request_inventory",
	})

	if err := h.store.Notify(ctx, "agent_"+msg.DeviceId, string(payload)); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to notify agent: %w", err))
	}

	return connect.NewResponse(&pm.RefreshDeviceInventoryResponse{}), nil
}
