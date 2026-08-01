package identity

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

const auditExportPageSize = int32(1000)

var auditCSVHeader = []string{
	"id", "occurred_at", "actor_type", "actor_id",
	"stream_type", "stream_id", "event_type", "data",
}

// auditEventData is the exhaustive allowlist exposed in AuditEvent.data.
// Neither audit table's sealed_detail, linkage hashes nor raw domain values
// are selectable through this shape.
type auditEventData struct {
	OperationID          string   `json:"operation_id"`
	OperationClass       string   `json:"operation_class"`
	ActorFingerprint     string   `json:"actor_fingerprint,omitempty"`
	Origin               string   `json:"origin"`
	OriginFingerprint    string   `json:"origin_fingerprint,omitempty"`
	RequestDescriptor    string   `json:"request_descriptor"`
	AuthorizationOutcome string   `json:"authorization_outcome"`
	AuthorizationDetail  string   `json:"authorization_detail,omitempty"`
	Result               string   `json:"result"`
	ResultCode           string   `json:"result_code,omitempty"`
	EffectOutcome        string   `json:"effect_outcome,omitempty"`
	ChangedFields        []string `json:"changed_fields,omitempty"`
	BeforeRef            *string  `json:"before_ref,omitempty"`
	AfterRef             *string  `json:"after_ref,omitempty"`
	BeforeFlag           *bool    `json:"before_flag,omitempty"`
	AfterFlag            *bool    `json:"after_flag,omitempty"`
	BeforeCount          *int64   `json:"before_count,omitempty"`
	AfterCount           *int64   `json:"after_count,omitempty"`
	EvidenceKind         string   `json:"evidence_kind,omitempty"`
	EvidenceFingerprint  string   `json:"evidence_fingerprint,omitempty"`
}

type auditExportRow struct {
	ID         string `json:"id"`
	OccurredAt string `json:"occurred_at"`
	ActorType  string `json:"actor_type"`
	ActorID    string `json:"actor_id"`
	StreamType string `json:"stream_type"`
	StreamID   string `json:"stream_id"`
	EventType  string `json:"event_type"`
	Data       string `json:"data"`
}

// ListAuditEvents reads the dedicated append-only operation/effect log. It
// never consults the abolished domain event store.
func (h *Handlers) ListAuditEvents(ctx context.Context, req *connect.Request[pmv1.ListAuditEventsRequest]) (*connect.Response[pmv1.ListAuditEventsResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if err := validateAuditFilters(ctx, req.Msg.ActorId, []string{req.Msg.StreamType}, req.Msg.EventType); err != nil {
		return nil, err
	}

	pageSize := req.Msg.PageSize
	if pageSize == 0 {
		pageSize = 50
	}
	beforeSeq, err := parseAuditCursor(ctx, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	if _, err := h.requireActor(ctx); err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermListAuditEvents, ""); err != nil {
		return nil, err
	}
	streamTypes := compactStrings(req.Msg.StreamType)
	filter := store.AuditEventFilter{
		ActorID: req.Msg.ActorId, StreamTypes: streamTypes,
		EventType: req.Msg.EventType, BeforeSeq: beforeSeq, Limit: pageSize + 1,
	}
	rows, err := h.store.ListAuditEventRows(ctx, filter)
	if err != nil {
		h.logger.Error("audit list failed", "error", err)
		return nil, internalError(ctx, "failed to list audit events")
	}
	count, err := h.store.CountAuditEventRows(ctx, filter)
	if err != nil {
		h.logger.Error("audit count failed", "error", err)
		return nil, internalError(ctx, "failed to count audit events")
	}

	next := ""
	if len(rows) > int(pageSize) {
		rows = rows[:pageSize]
		next = strconv.FormatInt(rows[len(rows)-1].ChainSeq, 10)
	}
	events, err := auditRowsToProto(rows)
	if err != nil {
		h.logger.Error("audit projection encoding failed", "error", err)
		return nil, internalError(ctx, "failed to encode audit events")
	}
	if count > math.MaxInt32 {
		count = math.MaxInt32
	}
	return connect.NewResponse(&pmv1.ListAuditEventsResponse{
		Events: events, NextPageToken: next, TotalCount: int32(count),
	}), nil
}

// ExportAuditEvents returns one bounded CSV or JSON fragment and records the
// protected read before any bytes are returned to the caller.
func (h *Handlers) ExportAuditEvents(ctx context.Context, req *connect.Request[pmv1.ExportAuditEventsRequest]) (*connect.Response[pmv1.ExportAuditEventsResponse], error) {
	if err := h.validate(ctx, req.Msg); err != nil {
		return nil, err
	}
	if err := validateAuditFilters(ctx, req.Msg.ActorId, req.Msg.StreamTypes, req.Msg.EventType); err != nil {
		return nil, err
	}
	if req.Msg.Format != "csv" && req.Msg.Format != "json" {
		return nil, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "unsupported export format")
	}
	beforeSeq, err := parseAuditCursor(ctx, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	from, to, err := auditDateBounds(ctx, req.Msg.OccurredFrom, req.Msg.OccurredTo)
	if err != nil {
		return nil, err
	}
	actor, err := h.requireActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.authorize(ctx, PermListAuditEvents, ""); err != nil {
		return nil, err
	}
	rows, err := h.store.ListAuditEventRows(ctx, store.AuditEventFilter{
		ActorID: req.Msg.ActorId, StreamTypes: req.Msg.StreamTypes,
		EventType: req.Msg.EventType, OccurredFrom: from, OccurredTo: to,
		BeforeSeq: beforeSeq, Limit: auditExportPageSize + 1,
	})
	if err != nil {
		h.logger.Error("audit export read failed", "error", err)
		return nil, internalError(ctx, "failed to export audit events")
	}

	hasMore := len(rows) > int(auditExportPageSize)
	if hasMore {
		rows = rows[:auditExportPageSize]
	}
	events, err := auditRowsToProto(rows)
	if err != nil {
		h.logger.Error("audit export projection failed", "error", err)
		return nil, internalError(ctx, "failed to encode audit export")
	}
	first := req.Msg.PageToken == ""
	last := !hasMore
	chunk, err := encodeAuditExport(events, req.Msg.Format, first, last)
	if err != nil {
		h.logger.Error("audit export encoding failed", "error", err)
		return nil, internalError(ctx, "failed to encode audit export")
	}

	op := h.operation(req, actor, store.ClassSensitiveRead, PermListAuditEvents,
		store.AuthorizationAllowed, store.ResultSuccess, "")
	op.OperationID = ulid.Make().String()
	exported := int64(len(rows))
	if _, err := h.store.RecordOperation(ctx, op, store.AuditEffect{
		ResourceType: "audit_log", ResourceID: op.OperationID,
		Action: "EXPORT", Outcome: store.EffectApplied, AfterCount: &exported,
	}); err != nil {
		h.logger.Error("audit export evidence failed", "error", err)
		return nil, internalError(ctx, "failed to record audit export")
	}

	next := ""
	if hasMore {
		next = strconv.FormatInt(rows[len(rows)-1].ChainSeq, 10)
	}
	return connect.NewResponse(&pmv1.ExportAuditEventsResponse{Chunk: chunk, NextPageToken: next}), nil
}

func validateAuditFilters(ctx context.Context, actorID string, streamTypes []string, eventType string) error {
	if actorID != "" {
		if _, err := ulid.ParseStrict(actorID); err != nil {
			return rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid actor id")
		}
	}
	for _, streamType := range streamTypes {
		if len(streamType) > 64 {
			return rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid stream type")
		}
	}
	if len(eventType) > 128 {
		return rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid event type")
	}
	return nil
}

func compactStrings(value string) []string {
	if value == "" {
		return []string{}
	}
	return []string{value}
}

func parseAuditCursor(ctx context.Context, token string) (int64, error) {
	if token == "" {
		return 0, nil
	}
	seq, err := strconv.ParseInt(token, 10, 64)
	if err != nil || seq <= 0 || strconv.FormatInt(seq, 10) != token {
		return 0, rpcError(ctx, ErrInvalidPageToken, connect.CodeInvalidArgument, "invalid page token")
	}
	return seq, nil
}

func auditDateBounds(ctx context.Context, from, to *timestamppb.Timestamp) (time.Time, time.Time, error) {
	lower := time.Unix(0, 0).UTC()
	upper := time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)
	if from != nil {
		if !from.IsValid() {
			return time.Time{}, time.Time{}, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid occurred-from timestamp")
		}
		lower = from.AsTime()
	}
	if to != nil {
		if !to.IsValid() {
			return time.Time{}, time.Time{}, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid occurred-to timestamp")
		}
		upper = to.AsTime()
	}
	if lower.After(upper) {
		return time.Time{}, time.Time{}, rpcError(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "invalid audit date range")
	}
	return lower, upper, nil
}

func auditRowsToProto(rows []store.AuditEventRow) ([]*pmv1.AuditEvent, error) {
	events := make([]*pmv1.AuditEvent, len(rows))
	for i, row := range rows {
		data, err := json.Marshal(auditEventData{
			OperationID: row.OperationID, OperationClass: row.OperationClass,
			ActorFingerprint: row.ActorFingerprint, Origin: row.Origin,
			OriginFingerprint: row.OriginFingerprint, RequestDescriptor: row.RequestDescriptor,
			AuthorizationOutcome: row.AuthorizationOutcome, AuthorizationDetail: row.AuthorizationDetail,
			Result: row.Result, ResultCode: row.ResultCode, EffectOutcome: row.EffectOutcome,
			ChangedFields: row.ChangedFields, BeforeRef: row.BeforeRef, AfterRef: row.AfterRef,
			BeforeFlag: row.BeforeFlag, AfterFlag: row.AfterFlag,
			BeforeCount: row.BeforeCount, AfterCount: row.AfterCount,
			EvidenceKind: row.EvidenceKind, EvidenceFingerprint: row.EvidenceFingerprint,
		})
		if err != nil {
			return nil, err
		}
		events[i] = &pmv1.AuditEvent{
			Id: row.ID, EventType: row.EventType, StreamType: row.StreamType,
			StreamId: row.StreamID, ActorType: row.ActorType, ActorId: row.ActorID,
			Data: string(data), OccurredAt: timestamppb.New(row.OccurredAt),
		}
	}
	return events, nil
}

func encodeAuditExport(events []*pmv1.AuditEvent, format string, first, last bool) ([]byte, error) {
	rows := make([]auditExportRow, len(events))
	for i, event := range events {
		rows[i] = auditExportRow{
			ID: event.Id, OccurredAt: event.OccurredAt.AsTime().Format(time.RFC3339Nano),
			ActorType: event.ActorType, ActorID: event.ActorId,
			StreamType: event.StreamType, StreamID: event.StreamId,
			EventType: event.EventType, Data: event.Data,
		}
	}
	if format == "csv" {
		return encodeAuditCSV(rows, first)
	}
	return encodeAuditJSON(rows, first, last)
}

func encodeAuditCSV(rows []auditExportRow, first bool) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if first {
		if err := w.Write(auditCSVHeader); err != nil {
			return nil, err
		}
	}
	for _, row := range rows {
		if err := w.Write([]string{
			row.ID, row.OccurredAt, row.ActorType, row.ActorID,
			row.StreamType, row.StreamID, row.EventType, row.Data,
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeAuditJSON(rows []auditExportRow, first, last bool) ([]byte, error) {
	var buf bytes.Buffer
	if first {
		buf.WriteByte('[')
	}
	for i, row := range rows {
		if i > 0 || !first {
			buf.WriteByte(',')
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			return nil, err
		}
		buf.Write(encoded)
	}
	if last {
		buf.WriteByte(']')
	}
	return buf.Bytes(), nil
}
