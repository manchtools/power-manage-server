package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/store"
	db "github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	maxInstantQueryRows  = 10_000
	maxInventoryTables   = 128
	maxAgentLogResultLen = 16 << 20
)

// DispatchOSQuery creates the pollable SQLite result before sending one
// unsigned query frame over the authenticated agent stream.
func (h *Handlers) DispatchOSQuery(ctx context.Context, req *connect.Request[pmv1.DispatchOSQueryRequest]) (*connect.Response[pmv1.DispatchOSQueryResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	hasTable := strings.TrimSpace(req.Msg.Table) != ""
	hasRawSQL := strings.TrimSpace(req.Msg.RawSql) != ""
	if hasTable == hasRawSQL {
		return nil, rpcError(ctx, errValidationFailed, connect.CodeInvalidArgument, "exactly one of table or raw_sql is required")
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.mutationDevice(ctx, "DispatchOSQuery", req.Msg.DeviceId); err != nil {
		return nil, err
	}

	queryID := ulid.Make().String()
	tableName := req.Msg.Table
	if hasRawSQL {
		tableName = "raw_sql"
	}
	createdAt := h.now().UTC()
	record, err := h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceDispatchOSQueryProcedure, "DispatchOSQuery"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if err := tx.InsertPendingOSQueryResult(ctx, db.InsertPendingOSQueryResultParams{
				QueryID: queryID, DeviceID: req.Msg.DeviceId, TableName: tableName, CreatedAt: createdAt,
			}); err != nil {
				return fmt.Errorf("insert pending OS query: %w", err)
			}
			rec.Effect(queryResultEffect("osquery_result", queryID, "CREATE", store.EffectApplied,
				"completed", "created_at", "device_id", "table_name"))
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "commit OS query", err)
	}

	err = h.agentSender.Send(req.Msg.DeviceId, &pmv1.ServerMessage{
		Id: queryID,
		Payload: &pmv1.ServerMessage_Query{Query: &pmv1.OSQuery{
			QueryId: queryID, Table: req.Msg.Table, Columns: req.Msg.Columns,
			Limit: req.Msg.Limit, RawSql: req.Msg.RawSql,
		}},
	})
	if err != nil {
		if auditErr := h.failOSQueryDispatch(ctx, record.OperationID, req.Msg.DeviceId, queryID); auditErr != nil {
			return nil, h.internal(ctx, "record OS query dispatch failure", auditErr)
		}
		return nil, rpcError(ctx, errDeviceUnavailable, connect.CodeUnavailable, "device is unavailable")
	}
	return connect.NewResponse(&pmv1.DispatchOSQueryResponse{QueryId: queryID}), nil
}

// QueryDeviceLogs creates the pollable SQLite result before sending one
// journal query over the authenticated agent stream.
func (h *Handlers) QueryDeviceLogs(ctx context.Context, req *connect.Request[pmv1.QueryDeviceLogsRequest]) (*connect.Response[pmv1.QueryDeviceLogsResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.mutationDevice(ctx, "QueryDeviceLogs", req.Msg.DeviceId); err != nil {
		return nil, err
	}

	queryID := ulid.Make().String()
	createdAt := h.now().UTC()
	record, err := h.store.WithAudit(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceQueryDeviceLogsProcedure, "QueryDeviceLogs"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			if err := tx.InsertPendingLogQueryResult(ctx, db.InsertPendingLogQueryResultParams{
				QueryID: queryID, DeviceID: req.Msg.DeviceId, CreatedAt: createdAt,
			}); err != nil {
				return fmt.Errorf("insert pending log query: %w", err)
			}
			rec.Effect(queryResultEffect("log_query_result", queryID, "CREATE", store.EffectApplied,
				"completed", "created_at", "device_id"))
			return nil
		})
	if err != nil {
		return nil, h.internal(ctx, "commit log query", err)
	}

	err = h.agentSender.Send(req.Msg.DeviceId, &pmv1.ServerMessage{
		Id: queryID,
		Payload: &pmv1.ServerMessage_LogQuery{LogQuery: &pmv1.LogQuery{
			QueryId: queryID, Lines: req.Msg.Lines, Unit: req.Msg.Unit,
			Since: req.Msg.Since, Until: req.Msg.Until, Priority: req.Msg.Priority,
			Grep: req.Msg.Grep, Kernel: req.Msg.Kernel,
		}},
	})
	if err != nil {
		if auditErr := h.failLogQueryDispatch(ctx, record.OperationID, req.Msg.DeviceId, queryID); auditErr != nil {
			return nil, h.internal(ctx, "record log query dispatch failure", auditErr)
		}
		return nil, rpcError(ctx, errDeviceUnavailable, connect.CodeUnavailable, "device is unavailable")
	}
	return connect.NewResponse(&pmv1.QueryDeviceLogsResponse{QueryId: queryID}), nil
}

// RefreshDeviceInventory sends one immediate collection request. Periodic
// inventory remains an agent decision; this path is only the operator trigger.
func (h *Handlers) RefreshDeviceInventory(ctx context.Context, req *connect.Request[pmv1.RefreshDeviceInventoryRequest]) (*connect.Response[pmv1.RefreshDeviceInventoryResponse], error) {
	if err := validateRequest(h, ctx, req); err != nil {
		return nil, err
	}
	actor, err := h.actor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := h.mutationDevice(ctx, "RefreshDeviceInventory", req.Msg.DeviceId); err != nil {
		return nil, err
	}

	requestID := ulid.Make().String()
	record, err := h.store.RecordOperation(ctx, h.operation(req, actor,
		powermanagev1connect.ControlServiceRefreshDeviceInventoryProcedure, "RefreshDeviceInventory"),
		store.AuditEffect{
			ResourceType: "device_inventory", ResourceID: req.Msg.DeviceId,
			Action: "REFRESH", Outcome: store.EffectApplied,
		})
	if err != nil {
		return nil, h.internal(ctx, "record inventory refresh", err)
	}
	err = h.agentSender.Send(req.Msg.DeviceId, &pmv1.ServerMessage{
		Id: requestID,
		Payload: &pmv1.ServerMessage_RequestInventory{
			RequestInventory: &pmv1.RequestInventory{QueryId: requestID},
		},
	})
	if err == nil {
		return connect.NewResponse(&pmv1.RefreshDeviceInventoryResponse{}), nil
	}
	_, auditErr := h.store.WithAuditEffects(ctx, record.OperationID,
		func(_ context.Context, _ *store.Tx, rec *store.AuditRecorder) error {
			rec.Effect(store.AuditEffect{
				ResourceType: "device_inventory", ResourceID: req.Msg.DeviceId,
				Action: "REFRESH", Outcome: store.EffectFailed,
			})
			return nil
		})
	if auditErr != nil {
		return nil, h.internal(ctx, "record inventory refresh failure", auditErr)
	}
	return nil, rpcError(ctx, errDeviceUnavailable, connect.CodeUnavailable, "device is unavailable")
}

// CompleteOSQueryResult commits an authenticated agent's result directly.
func (h *Handlers) CompleteOSQueryResult(ctx context.Context, deviceID string, result *pmv1.OSQueryResult) error {
	if result == nil {
		return errors.New("OS query result is required")
	}
	if err := validateAgentDeviceMessage(h, ctx, deviceID, result); err != nil {
		return err
	}
	if len(result.Rows) > maxInstantQueryRows {
		return fmt.Errorf("OS query result exceeds %d rows", maxInstantQueryRows)
	}
	rows := make([]map[string]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		if row == nil {
			return errors.New("OS query result contains a nil row")
		}
		rows = append(rows, row.Data)
	}
	rowsJSON, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("marshal OS query rows: %w", err)
	}
	resultError := result.Error
	if result.Success {
		resultError = ""
	} else {
		rowsJSON = []byte("[]")
		if resultError == "" {
			resultError = "query failed"
		}
	}
	completedAt := h.now().UTC()
	return h.completeAgentResult(ctx, deviceID, "OSQueryResult", "osquery_result", result.QueryId, "rows",
		func(ctx context.Context, tx *store.Tx) (int64, error) {
			return tx.CompleteOSQueryResult(ctx, db.CompleteOSQueryResultParams{
				Success: result.Success, Error: resultError, Rows: rowsJSON, CompletedAt: &completedAt,
				QueryID: result.QueryId, DeviceID: deviceID,
			})
		})
}

// CompleteLogQueryResult commits an authenticated agent's bounded log result.
func (h *Handlers) CompleteLogQueryResult(ctx context.Context, deviceID string, result *pmv1.LogQueryResult) error {
	if result == nil {
		return errors.New("log query result is required")
	}
	if err := validateAgentDeviceMessage(h, ctx, deviceID, result); err != nil {
		return err
	}
	if len(result.Logs) > maxAgentLogResultLen {
		return fmt.Errorf("log query result exceeds %d bytes", maxAgentLogResultLen)
	}
	resultError, logs := result.Error, result.Logs
	if result.Success {
		resultError = ""
	} else {
		logs = ""
		if resultError == "" {
			resultError = "log query failed"
		}
	}
	completedAt := h.now().UTC()
	return h.completeAgentResult(ctx, deviceID, "LogQueryResult", "log_query_result", result.QueryId, "logs",
		func(ctx context.Context, tx *store.Tx) (int64, error) {
			return tx.CompleteLogQueryResult(ctx, db.CompleteLogQueryResultParams{
				Success: result.Success, Error: resultError, Logs: logs, CompletedAt: &completedAt,
				QueryID: result.QueryId, DeviceID: deviceID,
			})
		})
}

// StoreDeviceInventory replaces each reported table in one audited transaction.
func (h *Handlers) StoreDeviceInventory(ctx context.Context, deviceID string, inventory *pmv1.DeviceInventory) error {
	if inventory == nil {
		return errors.New("device inventory is required")
	}
	if err := validateAgentDeviceMessage(h, ctx, deviceID, inventory); err != nil {
		return err
	}
	if len(inventory.Tables) > maxInventoryTables {
		return fmt.Errorf("inventory exceeds %d tables", maxInventoryTables)
	}
	type inventoryRow struct {
		name string
		rows []byte
	}
	prepared := make([]inventoryRow, 0, len(inventory.Tables))
	seen := make(map[string]struct{}, len(inventory.Tables))
	for _, table := range inventory.Tables {
		if table == nil {
			return errors.New("inventory contains a nil table")
		}
		if _, duplicate := seen[table.TableName]; duplicate {
			return fmt.Errorf("inventory repeats table %q", table.TableName)
		}
		seen[table.TableName] = struct{}{}
		if len(table.Rows) > maxInstantQueryRows {
			return fmt.Errorf("inventory table %q exceeds %d rows", table.TableName, maxInstantQueryRows)
		}
		rows := make([]map[string]string, 0, len(table.Rows))
		for _, row := range table.Rows {
			if row == nil {
				return fmt.Errorf("inventory table %q contains a nil row", table.TableName)
			}
			rows = append(rows, row.Data)
		}
		encoded, err := json.Marshal(rows)
		if err != nil {
			return fmt.Errorf("marshal inventory table %q: %w", table.TableName, err)
		}
		prepared = append(prepared, inventoryRow{name: table.TableName, rows: encoded})
	}
	collectedAt := h.now().UTC()
	op := agentStreamOperation(deviceID, "DeviceInventory")
	_, err := h.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		for _, table := range prepared {
			if err := tx.UpsertDeviceInventoryTable(ctx, db.UpsertDeviceInventoryTableParams{
				DeviceID: deviceID, TableName: table.name, Rows: table.rows, CollectedAt: collectedAt,
			}); err != nil {
				return fmt.Errorf("upsert inventory table %q: %w", table.name, err)
			}
		}
		count := int64(len(prepared))
		rec.Effect(store.AuditEffect{
			ResourceType: "device_inventory", ResourceID: deviceID, Action: "UPDATE",
			Outcome: store.EffectApplied, ChangedFields: []string{"collected_at", "rows"},
			AfterCount: &count,
		})
		return nil
	})
	return err
}

func (h *Handlers) failOSQueryDispatch(ctx context.Context, operationID, deviceID, queryID string) error {
	failedAt := h.now().UTC()
	_, err := h.store.WithAuditEffects(ctx, operationID, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		rows, err := tx.FailPendingOSQueryResult(ctx, db.FailPendingOSQueryResultParams{
			Error: "device unavailable", CompletedAt: &failedAt, QueryID: queryID, DeviceID: deviceID,
		})
		if err != nil {
			return err
		}
		outcome := store.EffectFailed
		if rows == 0 {
			outcome = store.EffectRejected
		}
		effect := queryResultEffect("osquery_result", queryID, "DISPATCH", outcome,
			"completed", "completed_at", "error")
		effect.AfterCount = &rows
		rec.Effect(effect)
		return nil
	})
	return err
}

func (h *Handlers) failLogQueryDispatch(ctx context.Context, operationID, deviceID, queryID string) error {
	failedAt := h.now().UTC()
	_, err := h.store.WithAuditEffects(ctx, operationID, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
		rows, err := tx.FailPendingLogQueryResult(ctx, db.FailPendingLogQueryResultParams{
			Error: "device unavailable", CompletedAt: &failedAt, QueryID: queryID, DeviceID: deviceID,
		})
		if err != nil {
			return err
		}
		outcome := store.EffectFailed
		if rows == 0 {
			outcome = store.EffectRejected
		}
		effect := queryResultEffect("log_query_result", queryID, "DISPATCH", outcome,
			"completed", "completed_at", "error")
		effect.AfterCount = &rows
		rec.Effect(effect)
		return nil
	})
	return err
}

func (h *Handlers) completeAgentResult(
	ctx context.Context,
	deviceID, descriptor, resourceType, resourceID, payloadField string,
	complete func(context.Context, *store.Tx) (int64, error),
) error {
	_, err := h.store.WithAudit(ctx, agentStreamOperation(deviceID, descriptor),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			rows, err := complete(ctx, tx)
			if err != nil {
				return err
			}
			outcome := store.EffectApplied
			if rows == 0 {
				outcome = store.EffectRejected
			}
			rec.Effect(queryResultEffect(resourceType, resourceID, "COMPLETE", outcome,
				"completed", "completed_at", "error", payloadField, "success"))
			return nil
		})
	return err
}

func validateAgentDeviceMessage(h *Handlers, ctx context.Context, deviceID string, message any) error {
	if _, err := ulid.ParseStrict(deviceID); err != nil {
		return fmt.Errorf("invalid device id: %w", err)
	}
	if message == nil {
		return errors.New("agent message is required")
	}
	return h.validate(ctx, message)
}

func agentStreamOperation(deviceID, descriptor string) store.AuditOperation {
	return store.AuditOperation{
		Class: store.ClassMutation, ActorType: "agent", ActorID: deviceID, Origin: "agent_stream",
		RequestDescriptor:    "powermanage.v1.AgentService.Stream/" + descriptor,
		AuthorizationOutcome: store.AuthorizationAllowed, AuthorizationDetail: "device_mtls",
		Result: store.ResultSuccess, ResultCode: "OK",
	}
}

func queryResultEffect(resourceType, resourceID, action string, outcome store.EffectOutcome, fields ...string) store.AuditEffect {
	return store.AuditEffect{
		ResourceType: resourceType, ResourceID: resourceID, Action: action,
		Outcome: outcome, ChangedFields: fields,
	}
}
