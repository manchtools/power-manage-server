package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"

	"google.golang.org/protobuf/types/known/timestamppb"
)

const osqueryResultTimeout = 5 * time.Minute

// OSQueryHandler handles OSQuery dispatch, result polling, and device inventory RPCs.
type OSQueryHandler struct {
	taskQueueHolder
	store  *store.Store
	logger *slog.Logger
}

// NewOSQueryHandler creates a new OSQuery handler.
func NewOSQueryHandler(st *store.Store, logger *slog.Logger) *OSQueryHandler {
	return &OSQueryHandler{store: st, logger: logger}
}

// DispatchOSQuery dispatches an on-demand osquery to a connected device.
func (h *OSQueryHandler) DispatchOSQuery(ctx context.Context, req *connect.Request[pm.DispatchOSQueryRequest]) (*connect.Response[pm.DispatchOSQueryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	msg := req.Msg

	// Verify device exists
	_, err := h.store.Queries().GetDeviceByID(ctx, generated.GetDeviceByIDParams{
		ID: msg.DeviceId,
	})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
	}

	// Generate query ID
	queryID := ulid.Make().String()

	// Use "raw_sql" as table name for DB record when raw SQL is provided
	tableName := msg.Table
	if tableName == "" && msg.RawSql != "" {
		tableName = "raw_sql"
	}

	// Create pending result row
	if err := h.store.Queries().CreateOSQueryResult(ctx, generated.CreateOSQueryResultParams{
		QueryID:   queryID,
		DeviceID:  msg.DeviceId,
		TableName: tableName,
	}); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create query result")
	}

	// Dispatch osquery to device via Asynq task queue.
	// Limit retries and set a deadline so queries to offline devices fail quickly
	// rather than sitting in the queue indefinitely.
	if h.aqClient != nil {
		if err := h.aqClient.EnqueueToDevice(msg.DeviceId, taskqueue.TypeOSQueryDispatch, taskqueue.OSQueryDispatchPayload{
			QueryID: queryID,
			Table:   msg.Table,
			Columns: msg.Columns,
			Limit:   msg.Limit,
			RawSQL:  msg.RawSql,
		},
			asynq.MaxRetry(3),
			asynq.Deadline(time.Now().Add(2*time.Minute)),
		); err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to dispatch osquery")
		}
		h.logger.Info("osquery dispatched to device",
			"query_id", queryID,
			"device_id", msg.DeviceId,
			"table", tableName,
		)
	}

	return connect.NewResponse(&pm.DispatchOSQueryResponse{
		QueryId: queryID,
	}), nil
}

// GetOSQueryResult polls for the result of a dispatched osquery.
func (h *OSQueryHandler) GetOSQueryResult(ctx context.Context, req *connect.Request[pm.GetOSQueryResultRequest]) (*connect.Response[pm.GetOSQueryResultResponse], error) {
	result, err := h.store.Queries().GetOSQueryResult(ctx, req.Msg.QueryId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrQueryResultNotFound, connect.CodeNotFound, "query result not found")
	}

	// Auto-expire pending results that have been waiting too long
	if !result.Completed && time.Since(result.CreatedAt) > osqueryResultTimeout {
		timeoutErr := "query timed out: device did not respond within 5 minutes"
		if err := h.store.Queries().ExpirePendingOSQueryResult(ctx, generated.ExpirePendingOSQueryResultParams{
			QueryID: result.QueryID,
			Error:   timeoutErr,
		}); err != nil {
			h.logger.Warn("failed to expire pending osquery result", "query_id", result.QueryID, "error", err)
		}
		result.Completed = true
		result.Success = false
		result.Error = timeoutErr
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
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get inventory")
	}

	resp := &pm.GetDeviceInventoryResponse{}
	for _, row := range rows {
		table := &pm.InventoryTableResult{
			TableName:   row.TableName,
			CollectedAt: timestamppb.New(row.CollectedAt),
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
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
	}

	// Dispatch inventory request to device via Asynq task queue
	if h.aqClient != nil {
		if err := h.aqClient.EnqueueToDevice(msg.DeviceId, taskqueue.TypeInventoryRequest, taskqueue.InventoryRequestPayload{},
			asynq.MaxRetry(3),
			asynq.Deadline(time.Now().Add(2*time.Minute)),
		); err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to dispatch inventory request")
		}
		h.logger.Info("inventory refresh dispatched to device",
			"device_id", msg.DeviceId,
		)
	}

	return connect.NewResponse(&pm.RefreshDeviceInventoryResponse{}), nil
}
