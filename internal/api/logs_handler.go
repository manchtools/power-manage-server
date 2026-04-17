package api

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/taskqueue"

	"github.com/hibiken/asynq"
)

const logQueryResultTimeout = 5 * time.Minute

// LogsHandler handles device log query RPCs.
type LogsHandler struct {
	taskQueueHolder
	store  *store.Store
	logger *slog.Logger
}

// NewLogsHandler creates a new logs handler.
func NewLogsHandler(st *store.Store, logger *slog.Logger) *LogsHandler {
	return &LogsHandler{store: st, logger: logger}
}

// QueryDeviceLogs dispatches a journalctl log query to a connected device.
func (h *LogsHandler) QueryDeviceLogs(ctx context.Context, req *connect.Request[pm.QueryDeviceLogsRequest]) (*connect.Response[pm.QueryDeviceLogsResponse], error) {
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

	// Create pending result row
	if err := h.store.Queries().CreateLogQueryResult(ctx, generated.CreateLogQueryResultParams{
		QueryID:  queryID,
		DeviceID: msg.DeviceId,
	}); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create log query result")
	}

	// Dispatch log query to device via Asynq task queue
	if h.aqClient != nil {
		if err := h.aqClient.EnqueueToDevice(msg.DeviceId, taskqueue.TypeLogQueryDispatch, taskqueue.LogQueryDispatchPayload{
			QueryID:  queryID,
			Lines:    msg.Lines,
			Unit:     msg.Unit,
			Since:    msg.Since,
			Until:    msg.Until,
			Priority: msg.Priority,
			Grep:     msg.Grep,
			Kernel:   msg.Kernel,
		},
			asynq.MaxRetry(3),
			asynq.Deadline(time.Now().Add(2*time.Minute)),
		); err != nil {
			return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to dispatch log query")
		}
		h.logger.Info("log query dispatched to device",
			"query_id", queryID,
			"device_id", msg.DeviceId,
		)
	}

	return connect.NewResponse(&pm.QueryDeviceLogsResponse{
		QueryId: queryID,
	}), nil
}

// GetDeviceLogResult polls for the result of a dispatched log query.
func (h *LogsHandler) GetDeviceLogResult(ctx context.Context, req *connect.Request[pm.GetDeviceLogResultRequest]) (*connect.Response[pm.GetDeviceLogResultResponse], error) {
	result, err := h.store.Queries().GetLogQueryResult(ctx, req.Msg.QueryId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrQueryResultNotFound, connect.CodeNotFound, "log query result not found")
	}

	// Auto-expire pending results that have been waiting too long
	if !result.Completed && time.Since(result.CreatedAt) > logQueryResultTimeout {
		timeoutErr := "log query timed out: device did not respond within 5 minutes"
		if err := h.store.Queries().ExpirePendingLogQueryResult(ctx, generated.ExpirePendingLogQueryResultParams{
			QueryID: result.QueryID,
			Error:   timeoutErr,
		}); err != nil {
			h.logger.Warn("failed to expire pending log query result", "query_id", result.QueryID, "error", err)
		}
		result.Completed = true
		result.Success = false
		result.Error = timeoutErr
	}

	return connect.NewResponse(&pm.GetDeviceLogResultResponse{
		QueryId:   result.QueryID,
		Completed: result.Completed,
		Success:   result.Success,
		Error:     result.Error,
		Logs:      result.Logs,
	}), nil
}
