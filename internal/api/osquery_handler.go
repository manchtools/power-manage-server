package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"

	"google.golang.org/protobuf/types/known/timestamppb"
)

const osqueryResultTimeout = 5 * time.Minute

// OSQueryHandler handles OSQuery dispatch, result polling, and device inventory RPCs.
type OSQueryHandler struct {
	taskQueueHolder
	store  *store.Store
	logger *slog.Logger
	signer ca.ActionSigner  // signs osquery/inventory dispatches (WS4)
	now    func() time.Time // clock seam; defaults to time.Now, overridden in tests
}

// NewOSQueryHandler creates a new OSQuery handler.
func NewOSQueryHandler(st *store.Store, logger *slog.Logger, signer ca.ActionSigner) *OSQueryHandler {
	return &OSQueryHandler{store: st, logger: logger, signer: signer, now: time.Now}
}

// DispatchOSQuery dispatches an on-demand osquery to a connected device.
func (h *OSQueryHandler) DispatchOSQuery(ctx context.Context, req *connect.Request[pm.DispatchOSQueryRequest]) (*connect.Response[pm.DispatchOSQueryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	msg := req.Msg
	hasTable := strings.TrimSpace(msg.Table) != ""
	hasRawSQL := strings.TrimSpace(msg.RawSql) != ""
	if hasTable == hasRawSQL {
		return nil, apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "exactly one of table or raw_sql is required")
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "DispatchOSQuery", msg.DeviceId); err != nil {
		return nil, err
	}

	// Verify device exists
	_, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: msg.DeviceId})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
	}

	// Fail fast when no task queue is configured. Without this
	// guard the handler used to write a pending osquery_result row
	// and return a queryID the caller could poll forever — the
	// agent never got the task. Same fail-closed contract as
	// DispatchAction.
	if h.aqClient == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeFailedPrecondition, "osquery dispatch unavailable: task queue not configured")
	}

	// Generate query ID
	queryID := ulid.Make().String()

	// Use "raw_sql" as table name for DB record when raw SQL is provided
	tableName := msg.Table
	if tableName == "" && msg.RawSql != "" {
		tableName = "raw_sql"
	}

	// Create pending result row
	if err := h.store.Repos().OSQuery.CreateResult(ctx, queryID, msg.DeviceId, tableName); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to create query result")
	}

	// Build the dispatch payload and sign it (WS4) so the agent verifies the
	// CA signature before running osquery as root — incl. raw SQL. Signing is
	// fail-closed: a signing failure (or nil signer) expires the pending row
	// and returns an error rather than shipping an unsigned task the agent
	// would drop.
	payload := taskqueue.OSQueryDispatchPayload{
		QueryID: queryID,
		Table:   msg.Table,
		Columns: msg.Columns,
		Limit:   msg.Limit,
		RawSQL:  msg.RawSql,
	}
	if err := signOSQueryDispatch(h.signer, &payload); err != nil {
		h.logger.Error("osquery dispatch signing failed; marking result expired",
			"query_id", queryID, "device_id", msg.DeviceId, "error", err)
		if expireErr := h.store.Repos().OSQuery.ExpirePendingResult(ctx, queryID, "dispatch signing failed"); expireErr != nil {
			h.logger.Error("failed to mark sign-failed osquery result as expired",
				"query_id", queryID, "error", expireErr)
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to sign osquery dispatch")
	}

	// Dispatch osquery to device via Asynq task queue.
	// Limit retries and set a deadline so queries to offline devices fail quickly
	// rather than sitting in the queue indefinitely.
	//
	// Enqueue failure: the pending result row already exists. Mark
	// it as expired with an explicit error so callers polling
	// GetOSQueryResult see a terminal failure rather than waiting
	// the full 5-minute timeout on a task that never shipped.
	if err := h.aqClient.EnqueueToDevice(msg.DeviceId, taskqueue.TypeOSQueryDispatch, payload,
		asynq.MaxRetry(3),
		asynq.Deadline(h.now().Add(2*time.Minute)),
	); err != nil {
		h.logger.Error("osquery enqueue failed; marking result expired",
			"query_id", queryID, "device_id", msg.DeviceId, "error", err)
		if expireErr := h.store.Repos().OSQuery.ExpirePendingResult(ctx, queryID, fmt.Sprintf("dispatch enqueue failed: %v", err)); expireErr != nil {
			h.logger.Error("failed to mark enqueue-failed osquery result as expired",
				"query_id", queryID, "error", expireErr)
		}
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to dispatch osquery")
	}
	h.logger.Info("osquery dispatched to device",
		"query_id", queryID,
		"device_id", msg.DeviceId,
		"table", tableName,
	)

	// Audit (#496): record who queried what on which device. Best-effort —
	// the dispatch already succeeded, so a failed append must not undo it;
	// log loudly (mirrors the UserLoggedIn audit-gap pattern).
	if userCtx, aerr := requireAuth(ctx); aerr == nil {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   msg.DeviceId,
			EventType:  string(eventtypes.OSQueryDispatched),
			Data: payloads.OSQueryDispatched{
				DeviceID:  msg.DeviceId,
				QueryID:   queryID,
				TableName: tableName,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}); err != nil {
			h.logger.Error("AUDIT GAP: failed to append OSQueryDispatched; dispatch already succeeded",
				"query_id", queryID, "device_id", msg.DeviceId, "error", err)
		}
	} else {
		h.logger.Error("AUDIT GAP: could not resolve actor for OSQueryDispatched; dispatch already succeeded",
			"query_id", queryID, "device_id", msg.DeviceId, "error", aerr)
	}

	return connect.NewResponse(&pm.DispatchOSQueryResponse{
		QueryId: queryID,
	}), nil
}

// GetOSQueryResult polls for the result of a dispatched osquery.
func (h *OSQueryHandler) GetOSQueryResult(ctx context.Context, req *connect.Request[pm.GetOSQueryResultRequest]) (*connect.Response[pm.GetOSQueryResultResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	result, err := h.store.Repos().OSQuery.GetResult(ctx, req.Msg.QueryId)
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrQueryResultNotFound, connect.CodeNotFound, "query result not found")
	}

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "GetOSQueryResult", result.DeviceID); err != nil {
		return nil, err
	}

	// Auto-expire pending results that have been waiting too long
	if !result.Completed && time.Since(result.CreatedAt) > osqueryResultTimeout {
		timeoutErr := "query timed out: device did not respond within 5 minutes"
		if err := h.store.Repos().OSQuery.ExpirePendingResult(ctx, result.QueryID, timeoutErr); err != nil {
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
		} else {
			// WS16 #11: a decode failure must not masquerade as a clean,
			// empty success — surface it so corrupt/malformed result rows are
			// observable instead of silently dropped.
			h.logger.Warn("osquery result rows decode failed",
				"query_id", result.QueryID, "error", err)
		}
	}

	return connect.NewResponse(resp), nil
}

// GetDeviceInventory returns cached inventory data for a device.
func (h *OSQueryHandler) GetDeviceInventory(ctx context.Context, req *connect.Request[pm.GetDeviceInventoryRequest]) (*connect.Response[pm.GetDeviceInventoryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	msg := req.Msg

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "GetDeviceInventory", msg.DeviceId); err != nil {
		return nil, err
	}

	var rows []store.InventoryTable
	var err error

	if len(msg.TableNames) > 0 {
		rows, err = h.store.Repos().Inventory.ListTables(ctx, msg.DeviceId, msg.TableNames)
	} else {
		rows, err = h.store.Repos().Inventory.ListAllTables(ctx, msg.DeviceId)
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
		} else {
			// WS16 #11: log a corrupt inventory table rather than emit it as
			// an empty (but present) table that looks like the device has no
			// data for it.
			h.logger.Warn("inventory table rows decode failed",
				"device_id", msg.DeviceId, "table", row.TableName, "error", err)
		}

		resp.Tables = append(resp.Tables, table)
	}

	return connect.NewResponse(resp), nil
}

// RefreshDeviceInventory requests the agent to re-collect and send inventory.
func (h *OSQueryHandler) RefreshDeviceInventory(ctx context.Context, req *connect.Request[pm.RefreshDeviceInventoryRequest]) (*connect.Response[pm.RefreshDeviceInventoryResponse], error) {
	if err := Validate(ctx, req.Msg); err != nil {
		return nil, err
	}

	msg := req.Msg

	if err := auth.EnforceDeviceScopeOnBaseTier(ctx, newScopeResolver(h.store), "RefreshDeviceInventory", msg.DeviceId); err != nil {
		return nil, err
	}

	// Verify device exists
	_, err := h.store.Repos().Device.Get(ctx, store.GetDeviceKey{ID: msg.DeviceId})
	if err != nil {
		return nil, apiErrorCtx(ctx, ErrDeviceNotFound, connect.CodeNotFound, "device not found")
	}

	// Fail fast when no task queue is configured. RefreshDeviceInventory
	// is fire-and-forget (no result row), so a silent-success when
	// aqClient is nil was less misleading than the DispatchOSQuery
	// case — but still returned 200 OK for a request that didn't
	// reach the device. Match the fail-closed contract.
	if h.aqClient == nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeFailedPrecondition, "inventory refresh unavailable: task queue not configured")
	}

	// Build + sign the inventory request (WS4): a query_id makes it bindable,
	// and the agent verifies the CA signature before running osquery as root.
	// Fail closed on a signing error.
	payload := taskqueue.InventoryRequestPayload{QueryID: ulid.Make().String()}
	if err := taskqueue.SignInventoryRequest(h.signer, &payload); err != nil {
		h.logger.Error("inventory request signing failed",
			"device_id", msg.DeviceId, "error", err)
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to sign inventory request")
	}

	// Dispatch inventory request to device via Asynq task queue
	if err := h.aqClient.EnqueueToDevice(msg.DeviceId, taskqueue.TypeInventoryRequest, payload,
		asynq.MaxRetry(3),
		asynq.Deadline(h.now().Add(2*time.Minute)),
	); err != nil {
		return nil, apiErrorCtx(ctx, ErrInternal, connect.CodeInternal, "failed to dispatch inventory request")
	}
	h.logger.Info("inventory refresh dispatched to device",
		"device_id", msg.DeviceId,
	)

	// Audit (#496): record who requested the inventory refresh. Best-effort.
	if userCtx, aerr := requireAuth(ctx); aerr == nil {
		if err := h.store.AppendEvent(ctx, store.Event{
			StreamType: "device",
			StreamID:   msg.DeviceId,
			EventType:  string(eventtypes.DeviceInventoryRefreshRequested),
			Data: payloads.DeviceInventoryRefreshRequested{
				DeviceID: msg.DeviceId,
			},
			ActorType: "user",
			ActorID:   userCtx.ID,
		}); err != nil {
			h.logger.Error("AUDIT GAP: failed to append DeviceInventoryRefreshRequested; dispatch already succeeded",
				"device_id", msg.DeviceId, "error", err)
		}
	} else {
		h.logger.Error("AUDIT GAP: could not resolve actor for DeviceInventoryRefreshRequested; dispatch already succeeded",
			"device_id", msg.DeviceId, "error", aerr)
	}

	return connect.NewResponse(&pm.RefreshDeviceInventoryResponse{}), nil
}
