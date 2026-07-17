package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"

	"github.com/hibiken/asynq"
)

const logQueryResultTimeout = 5 * time.Minute

// LogsHandler handles device log query RPCs.
type LogsHandler struct {
	taskQueueHolder
	store  *store.Store
	logger *slog.Logger
	signer ca.ActionSigner  // signs log-query dispatches (WS4)
	now    func() time.Time // clock seam; defaults to time.Now, overridden in tests
}

// NewLogsHandler creates a new logs handler.
func NewLogsHandler(st *store.Store, logger *slog.Logger, signer ca.ActionSigner) *LogsHandler {
	return &LogsHandler{store: st, logger: logger, signer: signer, now: time.Now}
}

// QueryDeviceLogs dispatches a journalctl log query to a connected device.
func (h *LogsHandler) QueryDeviceLogs(ctx context.Context, req *connect.Request[pm.QueryDeviceLogsRequest]) (*connect.Response[pm.QueryDeviceLogsResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	msg := req.Msg

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "QueryDeviceLogs", msg.DeviceId); err != nil {
		return nil, err
	}

	// Verify device exists
	_, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: msg.DeviceId})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
	}

	// Fail fast when no task queue is configured. Same fail-closed
	// contract as DispatchAction / DispatchOSQuery: silently
	// returning a queryID the caller can poll until the 5-minute
	// timeout was actively misleading — no agent task was ever
	// enqueued.
	if h.aqClient == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeFailedPrecondition, "log query dispatch unavailable: task queue not configured")
	}

	// Generate query ID
	queryID := ulid.Make().String()

	// Create pending result row
	if err := h.store.Repos().Logs.CreateQueryResult(ctx, queryID, msg.DeviceId); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create log query result")
	}

	// Build + sign the dispatch (WS4): journalctl runs as root, so the agent
	// verifies the CA signature before building any journalctl invocation.
	// Fail closed on a signing error — expire the pending row rather than
	// shipping an unsigned task the agent drops.
	payload := taskqueue.LogQueryDispatchPayload{
		QueryID:        queryID,
		Lines:          msg.Lines,
		Unit:           msg.Unit,
		Since:          msg.Since,
		Until:          msg.Until,
		Priority:       msg.Priority,
		Grep:           msg.Grep,
		Kernel:         msg.Kernel,
		TargetDeviceID: msg.DeviceId,
	}
	if err := signLogQueryDispatch(h.signer, &payload); err != nil {
		h.logger.Error("log query dispatch signing failed; marking result expired",
			"query_id", queryID, "device_id", msg.DeviceId, "error", err)
		if expireErr := h.store.Repos().Logs.ExpirePendingQueryResult(ctx, queryID, "dispatch signing failed"); expireErr != nil {
			h.logger.Error("failed to mark sign-failed log query result as expired",
				"query_id", queryID, "error", expireErr)
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to sign log query dispatch")
	}

	// Dispatch log query to device via Asynq task queue.
	// Enqueue failure: the pending result row already exists. Mark
	// it expired so callers polling GetDeviceLogResult see a
	// terminal failure rather than waiting the full 5-minute
	// timeout on a task that never shipped.
	if err := h.aqClient.EnqueueToDevice(msg.DeviceId, taskqueue.TypeLogQueryDispatch, payload,
		asynq.MaxRetry(3),
		asynq.Deadline(h.now().Add(2*time.Minute)),
	); err != nil {
		h.logger.Error("log query enqueue failed; marking result expired",
			"query_id", queryID, "device_id", msg.DeviceId, "error", err)
		if expireErr := h.store.Repos().Logs.ExpirePendingQueryResult(ctx, queryID, fmt.Sprintf("dispatch enqueue failed: %v", err)); expireErr != nil {
			h.logger.Error("failed to mark enqueue-failed log query result as expired",
				"query_id", queryID, "error", expireErr)
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to dispatch log query")
	}
	h.logger.Info("log query dispatched to device",
		"query_id", queryID,
		"device_id", msg.DeviceId,
	)

	// Audit (#496): record who pulled logs off which device, with the query
	// scope (unit/priority) — never any log content. Best-effort.
	if userCtx, aerr := requireAuth(ctx); aerr == nil {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   msg.DeviceId,
			EventType:  string(eventtypes.DeviceLogsQueried),
			Data: payloads.DeviceLogsQueried{
				DeviceID: msg.DeviceId,
				QueryID:  queryID,
				Unit:     msg.Unit,
				Priority: msg.Priority,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}); err != nil {
			h.logger.Error("AUDIT GAP: failed to append DeviceLogsQueried; dispatch already succeeded",
				"query_id", queryID, "device_id", msg.DeviceId, "error", err)
		}
	} else {
		h.logger.Error("AUDIT GAP: could not resolve actor for DeviceLogsQueried; dispatch already succeeded",
			"query_id", queryID, "device_id", msg.DeviceId, "error", aerr)
	}

	return connect.NewResponse(&pm.QueryDeviceLogsResponse{
		QueryId: queryID,
	}), nil
}

// GetDeviceLogResult polls for the result of a dispatched log query.
func (h *LogsHandler) GetDeviceLogResult(ctx context.Context, req *connect.Request[pm.GetDeviceLogResultRequest]) (*connect.Response[pm.GetDeviceLogResultResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	result, err := h.store.Repos().Logs.GetQueryResult(ctx, req.Msg.QueryId)
	if err != nil {
		if store.IsNotFound(err) {
			// Uniform with the out-of-scope path below (spec 29 S10): a
			// scope-restricted caller must not tell a missing result apart from one
			// on a device outside their scope.
			return nil, deviceScopeMissError(ctx, "GetDeviceLogResult", ErrQueryResultNotFound, "log query result not found")
		}
		// A non-NotFound error is a transient/internal fault — surface it, don't
		// swallow it behind a NotFound like the prior blanket mapping did.
		h.logger.Error("failed to fetch log query result", "query_id", req.Msg.QueryId, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to get log query result")
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "GetDeviceLogResult", result.DeviceID); err != nil {
		return nil, err
	}

	// Auto-expire pending results that have been waiting too long
	if !result.Completed && time.Since(result.CreatedAt) > logQueryResultTimeout {
		timeoutErr := "log query timed out: device did not respond within 5 minutes"
		if err := h.store.Repos().Logs.ExpirePendingQueryResult(ctx, result.QueryID, timeoutErr); err != nil {
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
